"""
파이프라인 전체가 공유하는 Flow 데이터 구조

FlowRecord  : 완성된 flow 1개 (피처 벡터 + 패킷 목록)
FlowKey     : 5-tuple 식별자 (딕셔너리 key)
"""

from dataclasses import dataclass, field
from typing import Optional
import numpy as np
from scapy.packet import Packet


@dataclass(frozen=True)
class FlowKey:
    """
    5-tuple 기반 flow 식별자.
    """
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    protocol: str  # "TCP" | "UDP" | "OTHER"

    @classmethod
    def from_packet(cls, pkt: Packet) -> Optional["FlowKey"]:
        from scapy.layers.inet import IP, TCP, UDP
        if IP not in pkt:
            return None
        proto = "OTHER"
        sport = dport = 0
        if TCP in pkt:
            proto = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        return cls(pkt[IP].src, pkt[IP].dst, sport, dport, proto)

    def to_id(self) -> str:
        """고유의 Flow ID를 문자열로 생성"""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"


# Isolation Forest에 넘길 피처 순서
FEATURE_NAMES = [
    "duration",
    "pkt_count",
    "byte_count",
    "iat_mean",     
    "iat_std",
    "iat_min",
    "iat_max",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_min",
    "pkt_len_max",
    "tcp_flag_syn",
    "tcp_flag_fin",
    "tcp_flag_rst",
    "tcp_flag_psh",
    "tcp_flag_ack",
]


@dataclass
class FlowRecord:
    """
    완성된 flow

    - features  : Isolation Forest 입력 벡터 (FEATURE_NAMES 순서)
    - packets   : PacketBuffer.add()에 넘길 scapy Packet 목록
    - flow_id   : 두 컴포넌트 공통 식별자
    - label     : csv에서 읽은 정답 레이블 (평가용, 없으면 None)
    """
    flow_key:  FlowKey
    features:  np.ndarray          # shape (len(FEATURE_NAMES),)
    packets:   list[Packet]
    label:     Optional[str] = None

    @property
    def flow_id(self) -> str:
        return self.flow_key.to_id()
