"""
attack_writer.py
----------------

저장 구조:
  attack_pcaps/
  └── 20240601_153042_192.168.1.1-80_10.0.0.2-54321_TCP/
      ├── attack.pcap          ← 원본 패킷
      └── metadata.json        ← flow 요약 + 탐지 정보
"""

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

from scapy.packet import Packet
from scapy.utils import PcapWriter
from scapy.layers.inet import IP, TCP, UDP

logger = logging.getLogger(__name__)


@dataclass
class FlowMetadata:
    """공격 flow 메타데이터 구조체"""
    flow_id:          str
    detected_at:      str                    # ISO-8601 UTC 타임스탬프
    anomaly_score:    Optional[float]        # Isolation Forest score
    packet_count:     int
    total_bytes:      int
    duration_seconds: float
    src_ip:           Optional[str]
    dst_ip:           Optional[str]
    src_port:         Optional[int]
    dst_port:         Optional[int]
    protocol:         Optional[str]
    pcap_path:        str
    extra:            dict = field(default_factory=dict)  # 추가 정보


class AttackPacketWriter:
    """
    공격 탐지 시 호출되는 저장 컴포넌트.

    Parameters
    ----------
    output_dir : str
        저장 루트 디렉토리. 없으면 자동 생성.
    """

    def __init__(self, output_dir: str = "./attack_pcaps"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        logger.info("AttackPacketWriter 초기화 | output_dir=%s", output_dir)

    # ------------------------------------------------------------------ #
    #  공개 API                                                            #
    # ------------------------------------------------------------------ #

    def write(
        self,
        flow_id: str,
        packets: list[Packet],
        anomaly_score: Optional[float] = None,
        extra: Optional[dict] = None,
    ) -> Optional[str]:
        """
        패킷 리스트를 pcap + JSON으로 저장한다.

        Parameters
        ----------
        flow_id       : PacketBuffer.flush()가 반환한 flow 식별자
        packets       : scapy Packet 객체 목록
        anomaly_score : Isolation Forest가 계산한 이상 점수
        extra         : 추가로 전달할 메타데이터 딕셔너리 (공격유형이나 탐지근거 같은것)

        Returns
        -------
        str  : 저장된 디렉토리 경로. 패킷이 없으면 None.
        """
        if not packets:
            logger.warning("[WRITE] flow_id=%s | 패킷 없음, 저장 스킵", flow_id)
            return None

        # ── 저장 디렉토리 생성 ──────────────────────────────────────────
        save_dir = self._make_save_dir(flow_id)

        # ── pcap 저장 ───────────────────────────────────────────────────
        pcap_path = os.path.join(save_dir, "attack.pcap")
        self._write_pcap(pcap_path, packets)

        # ── JSON 메타데이터 저장 ────────────────────────────────────────
        meta = self._build_metadata(
            flow_id=flow_id,
            packets=packets,
            anomaly_score=anomaly_score,
            pcap_path=pcap_path,
            extra=extra or {},
        )
        json_path = os.path.join(save_dir, "metadata.json")
        self._write_json(json_path, meta)

        logger.info(
            "[SAVED] flow_id=%s | %d pkts | score=%.4f | dir=%s",
            flow_id,
            len(packets),
            anomaly_score if anomaly_score is not None else float("nan"),
            save_dir,
        )
        return save_dir

    # ------------------------------------------------------------------ #
    #  내부 메서드                                                          #
    # ------------------------------------------------------------------ #

    def _make_save_dir(self, flow_id: str) -> str:
        """
        flow_id + 타임스탬프 기반 저장 디렉토리를 생성한다.
        파일 시스템에서 금지된 문자를 모두 교체.
        """
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        safe_id = (
            flow_id
            .replace(":", "-")
            .replace("/", "_")
            .replace("\\", "_")
            .replace(" ", "_")
        )
        dir_name = f"{ts}_{safe_id}"
        save_dir = os.path.join(self.output_dir, dir_name)
        os.makedirs(save_dir, exist_ok=True)
        return save_dir

    def _write_pcap(self, path: str, packets: list[Packet]) -> None:
        with PcapWriter(path, sync=True) as writer:
            for pkt in packets:
                writer.write(pkt)

    def _build_metadata(
        self,
        flow_id: str,
        packets: list[Packet],
        anomaly_score: Optional[float],
        pcap_path: str,
        extra: dict,
    ) -> FlowMetadata:
        # 패킷에서 IP/포트/프로토콜 정보 추출 (첫 패킷 기준)
        first = packets[0]
        src_ip = dst_ip = src_port = dst_port = protocol = None

        if IP in first:
            src_ip = first[IP].src
            dst_ip = first[IP].dst

        if TCP in first:
            src_port = first[TCP].sport
            dst_port = first[TCP].dport
            protocol = "TCP"
        elif UDP in first:
            src_port = first[UDP].sport
            dst_port = first[UDP].dport
            protocol = "UDP"

        # 총 바이트, duration 계산 (scapy 패킷에 time 속성 있을 때)
        total_bytes = sum(len(p) for p in packets)
        try:
            t_start = float(packets[0].time)
            t_end   = float(packets[-1].time)
            duration = round(t_end - t_start, 6)
        except (AttributeError, TypeError):
            duration = 0.0

        return FlowMetadata(
            flow_id=flow_id,
            detected_at=datetime.now(tz=timezone.utc).isoformat(),
            anomaly_score=anomaly_score,
            packet_count=len(packets),
            total_bytes=total_bytes,
            duration_seconds=duration,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            pcap_path=os.path.abspath(pcap_path),
            extra=extra,
        )

    def _write_json(self, path: str, meta: FlowMetadata) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(meta), f, indent=2, ensure_ascii=False)
