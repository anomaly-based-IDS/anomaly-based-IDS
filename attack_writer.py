"""
attack_writer.py
----------------

저장 구조:
  attack_pcaps/
  └── 20240601_153042_192.168.1.1-80_10.0.0.2-54321_TCP/
      ├── capture.pcap          ← 공격 패킷 + 전후 컨텍스트 패킷 (시간순 정렬)
      └── metadata.json        ← 사후 분석을 위한 상세 메타 데이터

metadata.json 구조:
    - cpature_info: pcap 파일 정보
    - attack_flow: 탐지된 공격 flow 상세
    - detection: 모델 탐지 결과 (score, confidence, reason)
    - context: 컨텍스트 구간 정보 (전후 시간, 패킷 수) 
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
class CaptureInfo:
    """pcap 파일 정보"""
    pcap_path: str
    total_packets: int
    attack_packets: int
    context_packets: int
    capture_start: str
    capture_end: str
    duration_seconds: float

@dataclass
class AttackFlowInfo:
    """탐지된 공격 flow 상세정보"""
    flow_id: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    flow_start: str
    flow_end: str
    flow_duration_sec: float
    total_bytes: int
    packet_count: int

@dataclass
class DetectionInfo:
    """모델 탐지 결과 정보"""
    detected_at: str
    anomaly_score: Optional[float]
    confidence: Optional[float]
    anomaly_reason: Optional[str]

@dataclass
class ContextInfo:
    """컨텍스트 구간 정보"""
    before_sec: float
    after_sec: float
    context_start: str
    context_end: str
    context_packets: int

@dataclass
class AttackMetadata:
    """최상위 메타데이터"""
    capture: CaptureInfo
    attack: AttackFlowInfo
    detection: DetectionInfo
    context: ContextInfo

class AttackPacketWriter:
    """
    공격 탐지 시 호출되는 저장 컴포넌트.

    Parameters
    ----------
    output_dir : 저장 루트 디렉토리. 없으면 자동 생성.
    before_sec : 컨텍스트 - 탐지 시점 이전 구간 (초)
    after_sec  : 컨텍스트 - 탐지 시점 이후 구간 (초)
    """

    def __init__(self, output_dir: str = "./attack_pcaps", before_sec: float = 10.0, after_sec: float = 10.0):
        self.output_dir = output_dir
        self.before_sec = before_sec
        self.after_sec = after_sec
        os.makedirs(output_dir, exist_ok=True)
        logger.info("AttackPacketWriter 초기화 | dir=%s | context=±%.0fs", output_dir, before_sec)

    # ------------------------------------------------------------------ #
    #  공개 API                                                            #
    # ------------------------------------------------------------------ #

    def write(
        self,
        flow_id: str,
        attack_packets: list[Packet],
        context_packets: list[Packet] = None,
        anomaly_score: Optional[float] = None,
        extra: Optional[dict] = None,
    ) -> Optional[str]:
        """
        패킷 리스트를 pcap + JSON으로 저장한다.

        Parameters
        ----------
        flow_id       : PacketBuffer.flush()가 반환한 flow 식별자
        attack_packets: scapy Packet 객체 목록
        context_packets: 컨텍스트 패킷 목록
        anomaly_score : Isolation Forest가 계산한 이상 점수
        extra         : 추가로 전달할 메타데이터 딕셔너리 (공격유형이나 탐지근거 같은것)

        Returns
        -------
        str  : 저장된 디렉토리 경로. 패킷이 없으면 None.
        """

        if not attack_packets:
            logger.warning("[WRITE] flow_id=%s | 공격 패킷 없음, 저장 스킵", flow_id)
            return None

        context_packets = context_packets or []
        extra = extra or {}

        save_dir = self._make_save_dir(flow_id)
        pcap_path = os.path.join(save_dir, "capture.pcap")

        # 공격 + 컨텍스트 시간순 정렬 후 단일 pcap으로 저장
        all_packets = self._merge_sorted(attack_packets, context_packets)
        self._write_pcap(pcap_path, all_packets)

        # 메타데이터 생성 및 저장
        meta = self._build_metadata(
            flow_id, attack_packets, context_packets, anomaly_score, pcap_path, extra,
        )
        json_path = os.path.join(save_dir, "metadata.json")
        self._write_json(json_path, meta)

        logger.info(
            "[SAVED] %s | 공격=%d pkts | 컨텍스트=%d pkts | score=%s",
            flow_id,
            len(attack_packets),
            len(context_packets),
            f"{anomaly_score:.4f}" if anomaly_score is not None else "N/A",
        )
        return save_dir

    #  내부 메서드                                                          

    def _make_save_dir(self, flow_id: str) -> str:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        safe_id = (
            flow_id
            .replace(":", "-")
            .replace("/", "_")
            .replace("\\", "_")
            .replace(" ", "_")
        )
        path = os.path.join(self.output_dir, f"{ts}_{safe_id}")
        os.makedirs(path, exist_ok=True)
        return path
    
    def _merge_sorted(
        self,
        attack_packets: list[Packet],
        context_packets: list[Packet],
    ) -> list[Packet]:
        combined = attack_packets + context_packets
        try:
            combined.sort(key=lambda p: float(p.time))
        except (AttributeError, TypeError):
            pass
        return combined

    def _write_pcap(self, path: str, packets: list[Packet]) -> None:
        with PcapWriter(path, sync=True) as writer:
            for pkt in packets:
                writer.write(pkt)

    def _build_metadata(
        self,
        flow_id: str,
        attack_packets: list[Packet],
        context_packets: list[Packet],
        anomaly_score: Optional[float],
        pcap_path: str,
        extra: dict,
    ) -> AttackMetadata:
    
        # 공격 flow 기본 정보
        first    = attack_packets[0]
        src_ip   = dst_ip = None
        src_port = dst_port = protocol = None
 
        if IP in first:
            src_ip, dst_ip = first[IP].src, first[IP].dst
        if TCP in first:
            src_port, dst_port, protocol = first[TCP].sport, first[TCP].dport, "TCP"
        elif UDP in first:
            src_port, dst_port, protocol = first[UDP].sport, first[UDP].dport, "UDP"
 
        def pkt_time(p: Packet) -> float:
            try:    return float(p.time)
            except: return 0.0
 
        atk_times   = [pkt_time(p) for p in attack_packets]
        atk_start   = min(atk_times)
        atk_end     = max(atk_times)
        total_bytes = sum(len(p) for p in attack_packets)
 
        #  컨텍스트 구간 시각
        ctx_start_ts = atk_start - self.before_sec
        ctx_end_ts   = atk_end   + self.after_sec
 
        #  pcap 전체 범위 
        all_packets   = attack_packets + context_packets
        all_times     = [pkt_time(p) for p in all_packets]
        cap_start_ts  = min(all_times)
        cap_end_ts    = max(all_times)
 
        def to_iso(ts: float) -> str:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
 
        abs_pcap = os.path.abspath(pcap_path)

        return AttackMetadata(
            capture=CaptureInfo(
                pcap_path        = abs_pcap,
                total_packets    = len(all_packets),
                attack_packets   = len(attack_packets),
                context_packets  = len(context_packets),
                capture_start    = to_iso(cap_start_ts),
                capture_end      = to_iso(cap_end_ts),
                duration_seconds = round(cap_end_ts - cap_start_ts, 6),
            ),
            attack=AttackFlowInfo(
                flow_id          = flow_id,
                src_ip           = src_ip,
                dst_ip           = dst_ip,
                src_port         = src_port,
                dst_port         = dst_port,
                protocol         = protocol,
                flow_start       = to_iso(atk_start),
                flow_end         = to_iso(atk_end),
                flow_duration_sec= round(atk_end - atk_start, 6),
                total_bytes      = total_bytes,
                packet_count     = len(attack_packets),
            ),
            detection=DetectionInfo(
                detected_at    = datetime.now(tz=timezone.utc).isoformat(),
                anomaly_score  = anomaly_score,
                confidence     = extra.get("confidence"),
                anomaly_reason = extra.get("reason"),
            ),
            context=ContextInfo(
                before_sec      = self.before_sec,
                after_sec       = self.after_sec,
                context_start   = to_iso(ctx_start_ts),
                context_end     = to_iso(ctx_end_ts),
                context_packets = len(context_packets),
            ),
        )
 
    def _write_json(self, path: str, meta: AttackMetadata) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(meta), f, indent=2, ensure_ascii=False)
            