"""
pcap 파일을 읽어 FlowRecord 형식으로 변환한다.

처리 흐름:
  pcap → 패킷 순회 → FlowKey로 그룹핑 → flow 완성 판정
       → 피처 추출 → FlowRecord yield
"""

import logging
from dataclassess import dataclass
from typing import Generator, Optional, Iterator, Union
import numpy as np
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from flow import FlowKey, FlowRecord, FEATURE_NAMES

logger = logging.getLogger(__name__)

@dataclass
class PacketEvent:
    flow_id: str
    packet: Packet

@dataclass
class FlowEvent:
    flow_id: str
    features: np.ndarray
    flow_key: FlowKey

StreamEvent = Union[PacketEvent, FlowEvent]


class _FlowAccumulator:
    """단일 flow의 패킷을 모으고 피처를 계산"""

    def __init__(self, key: FlowKey):
        self.key = key
        self._timestamps: list[float] = []
        self._pkt_lens: list[int] = []
        self._flags = {"SYN": 0, "FIN": 0, "RST": 0, "PSH": 0, "ACK": 0}

    def add(self, pkt: Packet) -> None:
        self._timestamps.append(float(pkt.time))
        self._pkt_lens.append(len(pkt))

        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02: self._flags["SYN"] += 1
            if flags & 0x01: self._flags["FIN"] += 1
            if flags & 0x04: self._flags["RST"] += 1
            if flags & 0x08: self._flags["PSH"] += 1
            if flags & 0x10: self._flags["ACK"] += 1

    def is_finished(self) -> bool:
        """TCP FIN 또는 RST 수신 시 flow 종료"""
        return self._flags["FIN"] > 0 or self._flags["RST"] > 0

    @property
    def last_seen(self) -> float:
        return self._timestamps[-1] if self._timestamps else 0.0
    
    def to_flow_event(self) -> FlowEvent:
        ts = self._timestamps
        lens = self._pkt_lens

        duration = (ts[-1] - ts[0]) if len(ts) > 1 else 0.0
        byte_count = sum(lens)

        if len(ts) > 1:
            iats = np.diff(ts)
            iat_mean, iat_std = float(iats.mean()), float(iats.std())
            iat_min, iat_max = float(iats.min()), float(iats.max())
        else:
            iat_mean = iat_std = iat_min = iat_max = 0.0

        arr = np.array(lens, dtype=float)

        features = np.array([
            duration,
            len(ts),
            byte_count,
            iat_mean, iat_std, iat_min, iat_max,
            float(arr.mean()), float(arr.std()), float(arr.min()), float(arr.max()),
            self._flags["SYN"],
            self._flags["FIN"],
            self._flags["RST"],
            self._flags["PSH"],
            self._flags["ACK"],
        ], dtype=float)

        return FlowEvent(
            flow_id=self.key.id(),
            features=features,
            flow_key=self.key
        )


class PcapFlowReader:

    def __init__(self, idle_timeout: float = 120.0):
        self.idle_timeout = idle_timeout

    def stream(self, pcap_path: str) -> Generator[StreamEvent, None, None]:
        logger.info("스트리밍 시작: %s", pcap_path)
        active: dict[FlowKey, _FlowAccumulator] = {}
        total_pkts = flow_count = 0

        with PcapReader(pcap_path) as pcap:
            for pkt in pcap:
                if IP not in pkt:
                    continue

                key = FlowKey.from_packet(pkt)
                if key is None:
                    continue

                total_pkts += 1

                yield PacketEvent(flow_id=key.to_id(), packet=pkt)

                if key not in active:
                    active[key] = _FlowAccumulator(key)

                acc = active[key]
                acc.add(pkt)

                # idle timeout 체크 (현재 패킷 기준으로 오래된 flow 정리)
                now = float(pkt.time)
                expired = [
                    k for k, a in active.items()
                    if k != key and now - a.last_seen > self.idle_timeout
                ]
                for k in expired:
                    flow_count += 1
                    yield active.pop(k).to_flow_event()

                # TCP FIN/RST → flow 즉시 종료
                if acc.is_finished():
                    flow_count += 1
                    yield active.pop(key).to_flow_event()

        # 파일 끝 → 남은 미완성 flow 모두 flush
        for acc in active.values():
            flow_count += 1
            yield acc.to_flow_event()

        logger.info(
            "스트리밍 완료: %s | 총 패킷=%d | 완성 flow=%d",
            pcap_path, total_pkts, flow_count
        )
