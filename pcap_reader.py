"""
pcap 파일을 읽어 FlowRecord 형식으로 변환한다.

처리 흐름:
  pcap → 패킷 순회 → FlowKey로 그룹핑 → flow 완성 판정
       → 피처 추출 → FlowRecord yield
"""

import logging
from typing import Generator, Optional
import numpy as np
from scapy.utils import rdpcap, PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from flow import FlowKey, FlowRecord, FEATURE_NAMES

logger = logging.getLogger(__name__)


class _FlowAccumulator:
    """단일 flow의 패킷을 모으고 피처를 계산"""

    def __init__(self, key: FlowKey):
        self.key = key
        self.packets: list[Packet] = []
        self._timestamps: list[float] = []
        self._pkt_lens: list[int] = []
        self._flags = {"SYN": 0, "FIN": 0, "RST": 0, "PSH": 0, "ACK": 0}

    def add(self, pkt: Packet) -> None:
        self.packets.append(pkt)
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

    def to_record(self, label: Optional[str] = None) -> FlowRecord:
        ts = self._timestamps
        lens = self._pkt_lens

        duration    = (ts[-1] - ts[0]) if len(ts) > 1 else 0.0
        pkt_count   = len(ts)
        byte_count  = sum(lens)

        if len(ts) > 1:
            iats    = np.diff(ts)
            iat_mean, iat_std = float(iats.mean()), float(iats.std())
            iat_min,  iat_max = float(iats.min()),  float(iats.max())
        else:
            iat_mean = iat_std = iat_min = iat_max = 0.0

        arr         = np.array(lens, dtype=float)
        plen_mean   = float(arr.mean())
        plen_std    = float(arr.std())
        plen_min    = float(arr.min())
        plen_max    = float(arr.max())

        features = np.array([
            duration,
            pkt_count,
            byte_count,
            iat_mean, iat_std, iat_min, iat_max,
            plen_mean, plen_std, plen_min, plen_max,
            self._flags["SYN"],
            self._flags["FIN"],
            self._flags["RST"],
            self._flags["PSH"],
            self._flags["ACK"],
        ], dtype=float)

        return FlowRecord(
            flow_key=self.key,
            features=features,
            packets=self.packets,
            label=label,
        )


class PcapFlowReader:
    """
    pcap 파일 → FlowRecord 생성기.

    Parameters
    ----------
    idle_timeout : float
        마지막 패킷 이후 이 시간(초)이 지나면 flow를 강제 종료.
        배치 처리 종료 시 미완성 flow도 모두 flush.
    """

    def __init__(self, idle_timeout: float = 120.0):
        self.idle_timeout = idle_timeout

    def read(self, pcap_path: str) -> Generator[FlowRecord, None, None]:
        """
        pcap 파일을 순회하며 완성된 FlowRecord를 순서대로 yield

        사용법
        -----
        for record in reader.read("Monday.pcap"):
            pipeline.on_packet(record.flow_id, packet)   # 버퍼
            model.predict(record.features)                # IForest
        """
        logger.info("pcap 읽기 시작: %s", pcap_path)
        active: dict[FlowKey, _FlowAccumulator] = {}
        total_pkts = 0

        with PcapReader(pcap_path) as pcap:
            for pkt in pcap:
                if IP not in pkt:
                    continue

                key = FlowKey.from_packet(pkt)
                if key is None:
                    continue

                total_pkts += 1
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
                    yield active.pop(k).to_record()

                # TCP FIN/RST → flow 즉시 종료
                if acc.is_finished():
                    yield active.pop(key).to_record()

        # 파일 끝 → 남은 미완성 flow 모두 flush
        for acc in active.values():
            yield acc.to_record()

        logger.info(
            "pcap 읽기 완료: %s | 총 패킷=%d | 완성 flow=%d",
            pcap_path, total_pkts, total_pkts  # flow 수는 호출부에서 집계
        )
