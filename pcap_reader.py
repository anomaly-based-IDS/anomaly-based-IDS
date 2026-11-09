"""
pcap_reader.py
--------------
pcap을 스트리밍으로 읽어 PacketEvent / FlowEvent를 순서대로 yield한다.

이벤트 종류:
  PacketEvent : 패킷 수신 즉시 발생 → PacketBuffer.add() / ContextBuffer.add()
  FlowEvent   : flow 완성 시 발생   → 모델 판정용 (피처 벡터 포함)

flow 완성 조건:
  1. TCP FIN / RST 수신
  2. idle_timeout 초 동안 패킷 없음 → 강제 종료
  3. pcap 끝 → 미완성 flow 일괄 flush

flow_id 와 uid:
  flow_id : 5-tuple 문자열. 사람이 읽는 식별자 (저장 경로, metadata)
  uid     : flow 인스턴스 고유 ID ("<flow_id>#<순번>").
            같은 5-tuple이 FIN 이후 다시 등장하면 새 uid를 받는다.
            PacketBuffer는 uid로 패킷을 관리하므로 서로 다른 flow 인스턴스의
            패킷이 섞이지 않는다.
"""

import logging
from dataclasses import dataclass
from typing import Generator, Union

import numpy as np
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from flow import FlowKey, FEATURE_NAMES

logger = logging.getLogger(__name__)


# ── 이벤트 타입 ────────────────────────────────────────────────────────

@dataclass
class PacketEvent:
    """패킷 수신 즉시 발생."""
    flow_id:   str
    packet:    Packet
    uid:       str = ""
    timestamp: float = 0.0   # 패킷 pcap 타임스탬프


@dataclass
class FlowEvent:
    """flow 완성 시 발생. 모델 판정에 사용한다."""
    flow_id:    str
    features:   np.ndarray   # shape (len(FEATURE_NAMES),)
    flow_key:   FlowKey
    flow_start: float = 0.0  # flow 첫 패킷 pcap 타임스탬프
    flow_end:   float = 0.0  # flow 마지막 패킷 pcap 타임스탬프
    uid:        str = ""


StreamEvent = Union[PacketEvent, FlowEvent]


# ── 피처 누적기 ────────────────────────────────────────────────────────

class _FlowAccumulator:
    """
    단일 flow의 피처를 패킷 단위로 누적.
    패킷 자체는 저장하지 않음 — PacketBuffer가 담당.
    """

    def __init__(self, key: FlowKey, uid: str = ""):
        self.key = key
        self.uid = uid or key.to_id()
        self._timestamps: list[float] = []
        self._pkt_lens:   list[int]   = []
        self._flags = {"SYN": 0, "FIN": 0, "RST": 0, "PSH": 0, "ACK": 0}

    def add(self, pkt: Packet) -> None:
        self._timestamps.append(float(pkt.time))
        self._pkt_lens.append(len(pkt))
        if TCP in pkt:
            f = pkt[TCP].flags
            if f & 0x02: self._flags["SYN"] += 1
            if f & 0x01: self._flags["FIN"] += 1
            if f & 0x04: self._flags["RST"] += 1
            if f & 0x08: self._flags["PSH"] += 1
            if f & 0x10: self._flags["ACK"] += 1

    def is_finished(self) -> bool:
        """TCP FIN 또는 RST 수신 시 flow 종료"""
        return self._flags["FIN"] > 0 or self._flags["RST"] > 0

    @property
    def last_seen(self) -> float:
        return self._timestamps[-1] if self._timestamps else 0.0

    def to_flow_event(self) -> FlowEvent:
        ts   = self._timestamps
        lens = self._pkt_lens

        duration   = (ts[-1] - ts[0]) if len(ts) > 1 else 0.0
        byte_count = sum(lens)

        if len(ts) > 1:
            iats = np.diff(ts)
            iat_mean, iat_std = float(iats.mean()), float(iats.std())
            iat_min,  iat_max = float(iats.min()),  float(iats.max())
        else:
            iat_mean = iat_std = iat_min = iat_max = 0.0

        arr = np.array(lens, dtype=float)
        features = np.array([
            duration, len(ts), byte_count,
            iat_mean, iat_std, iat_min, iat_max,
            float(arr.mean()), float(arr.std()),
            float(arr.min()),  float(arr.max()),
            self._flags["SYN"], self._flags["FIN"],
            self._flags["RST"], self._flags["PSH"],
            self._flags["ACK"],
        ], dtype=float)
        assert features.shape == (len(FEATURE_NAMES),)

        return FlowEvent(
            flow_id    = self.key.to_id(),
            features   = features,
            flow_key   = self.key,
            flow_start = ts[0]  if ts else 0.0,
            flow_end   = ts[-1] if ts else 0.0,
            uid        = self.uid,
        )


# ── 스트리밍 리더 ──────────────────────────────────────────────────────

class PcapFlowReader:
    """
    pcap 파일 → StreamEvent 제너레이터.

    Parameters
    ----------
    idle_timeout   : 마지막 패킷 이후 이 시간(초) 초과 시 flow 강제 종료
    sweep_interval : idle flow 검사 주기 (pcap 시간 기준, 초).
                     패킷마다 전체 flow를 훑지 않도록 주기적으로만 검사한다.
    """

    def __init__(self, idle_timeout: float = 120.0, sweep_interval: float = 1.0):
        self.idle_timeout = idle_timeout
        self.sweep_interval = sweep_interval

    def stream(self, pcap_path: str) -> Generator[StreamEvent, None, None]:
        """
        pcap을 패킷 단위로 읽으며 이벤트를 순서대로 yield한다.

        Usage
        -----
        for event in reader.stream("Monday.pcap"):
            if isinstance(event, PacketEvent):
                buffer.add(event.uid, event.packet)
            elif isinstance(event, FlowEvent):
                ...  # 모델 판정
        """
        logger.info("스트리밍 시작: %s", pcap_path)
        active: dict[FlowKey, _FlowAccumulator] = {}
        seq: dict[FlowKey, int] = {}
        total_pkts = flow_count = 0
        last_sweep = None

        with PcapReader(pcap_path) as pcap:
            for pkt in pcap:
                if IP not in pkt:
                    continue
                key = FlowKey.from_packet(pkt)
                if key is None:
                    continue

                total_pkts += 1
                now = float(pkt.time)

                # ① 피처 누적기 준비 (새 flow 인스턴스면 새 uid 발급)
                acc = active.get(key)
                if acc is not None and now - acc.last_seen > self.idle_timeout:
                    # 주기 검사 전에 같은 키 패킷이 다시 온 경우: 이전 flow를 먼저 종료
                    flow_count += 1
                    yield active.pop(key).to_flow_event()
                    acc = None
                if acc is None:
                    n = seq.get(key, 0) + 1
                    seq[key] = n
                    acc = active[key] = _FlowAccumulator(key, f"{key.to_id()}#{n}")

                # ② 패킷 이벤트 즉시 emit
                yield PacketEvent(flow_id=key.to_id(), packet=pkt,
                                  uid=acc.uid, timestamp=now)
                acc.add(pkt)

                # ③ idle timeout 검사 (sweep_interval 마다)
                if last_sweep is None:
                    last_sweep = now
                elif now - last_sweep >= self.sweep_interval:
                    last_sweep = now
                    expired = [
                        k for k, a in active.items()
                        if k != key and now - a.last_seen > self.idle_timeout
                    ]
                    for k in expired:
                        flow_count += 1
                        yield active.pop(k).to_flow_event()

                # ④ TCP FIN/RST → flow 즉시 종료
                if acc.is_finished():
                    flow_count += 1
                    yield active.pop(key).to_flow_event()

        # ⑤ 파일 끝 → 미완성 flow 모두 flush
        for acc in active.values():
            flow_count += 1
            yield acc.to_flow_event()

        logger.info(
            "스트리밍 완료: %s | 패킷=%d | flow=%d",
            pcap_path, total_pkts, flow_count,
        )
