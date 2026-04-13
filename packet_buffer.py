"""
packet_buffer.py
----------------
Flow별 패킷을 메모리에 보관하고,
공격 탐지 시 해당 flow의 패킷을 반환하는 버퍼 컴포넌트.

입력 : scapy Packet 객체
신호 : Isolation Forest → flush(flow_id) 직접 호출
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional
import threading
import time
import logging

from scapy.packet import Packet

logger = logging.getLogger(__name__)


@dataclass
class BufferStats:
    """버퍼 운영 통계"""
    total_added:   int = 0
    total_flushed: int = 0
    total_evicted: int = 0
    active_flows:  int = 0


class PacketBuffer:
    """
    Flow별 패킷 슬라이딩 윈도우 버퍼.

    Parameters
    ----------
    max_packets_per_flow : int
        한 flow에 보관할 최대 패킷 수.
        초과 시 가장 오래된 패킷이 자동으로 밀려남 (deque maxlen).
    ttl_seconds : float
        마지막 패킷 수신 후 flow를 자동 만료시킬 시간 (초).
    evict_interval : float
        만료 GC 스레드 실행 주기 (초). 0이면 자동 GC 비활성화.
    """

    def __init__(
        self,
        max_packets_per_flow: int = 1000,
        ttl_seconds: float = 120.0,
        evict_interval: float = 30.0,
    ):
        self._max = max_packets_per_flow
        self._ttl = ttl_seconds

        # flow_id → deque[(recv_timestamp, Packet)]
        self._buffer: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self._max)
        )
        self._last_seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self.stats = BufferStats()

        # 자동 GC 스레드
        if evict_interval > 0:
            self._gc_thread = threading.Thread(
                target=self._gc_loop,
                args=(evict_interval,),
                daemon=True,
                name="PacketBuffer-GC",
            )
            self._gc_thread.start()
            logger.info(
                "PacketBuffer 초기화 | max=%d pkts/flow | ttl=%.0fs | gc=%.0fs",
                max_packets_per_flow, ttl_seconds, evict_interval,
            )

    # ------------------------------------------------------------------ #
    #  공개 API                                                            #
    # ------------------------------------------------------------------ #

    def add(self, flow_id: str, packet: Packet, timestamp: Optional[float] = None) -> None:
        """
        패킷을 버퍼에 추가한다.

        Parameters
        ----------
        flow_id  : Flow 변환기가 생성한 식별자
                   예) "192.168.1.1:80-10.0.0.2:54321-TCP"
        packet   : scapy Packet 객체
        timestamp: 수신 시각 (None이면 현재 시각 사용)
        """
        ts = timestamp if timestamp is not None else time.time()
        with self._lock:
            self._buffer[flow_id].append((ts, packet))
            self._last_seen[flow_id] = ts
            self.stats.total_added += 1
            self.stats.active_flows = len(self._buffer)

    def flush(self, flow_id: str) -> list[Packet]:
        """
        Isolation Forest가 공격을 탐지했을 때 호출하는 메서드
        해당 flow의 모든 패킷을 반환하고 버퍼에서 제거

        Returns: list[Packet]
        """
        with self._lock:
            entries = list(self._buffer.pop(flow_id, []))
            self._last_seen.pop(flow_id, None)
            self.stats.active_flows = len(self._buffer)

        packets = [pkt for _, pkt in entries]
        if packets:
            self.stats.total_flushed += len(packets)
            logger.info(
                "[FLUSH] flow_id=%s | %d 패킷 반환",
                flow_id, len(packets),
            )
        else:
            logger.warning("[FLUSH] flow_id=%s | 버퍼에 패킷 없음", flow_id)

        return packets

    def evict_expired(self) -> int:
        """
        TTL이 초과된 flow를 정리

        Returns: int (제거된 flow 수)
        """
        now = time.time()
        with self._lock:
            expired = [
                fid for fid, ts in self._last_seen.items()
                if now - ts > self._ttl
            ]
            for fid in expired:
                evicted_count = len(self._buffer.pop(fid, []))
                del self._last_seen[fid]
                self.stats.total_evicted += evicted_count

            self.stats.active_flows = len(self._buffer)

        if expired:
            logger.debug("[GC] %d개 만료 flow 제거", len(expired))

        return len(expired)

    def peek(self, flow_id: str) -> list[Packet]:
        """
        버퍼를 비우지 않고 현재 보관 중인 패킷 목록을 반환
        """
        with self._lock:
            return [pkt for _, pkt in self._buffer.get(flow_id, [])]

    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._buffer)

    # ------------------------------------------------------------------ #
    #  내부 메서드                                                          #
    # ------------------------------------------------------------------ #

    def _gc_loop(self, interval: float) -> None:
        while True:
            time.sleep(interval)
            try:
                self.evict_expired()
            except Exception:
                logger.exception("GC 중 예외 발생")
