"""
attack_writer.py
----------------

저장 구조:
  attack_pcaps/
  └── 20240601_153042_192.168.1.1-80_10.0.0.2-54321_TCP/
      ├── capture.pcap          ← 공격 패킷 + 전후 컨텍스트 패킷 (시간순 정렬)
      └── metadata.json        ← 사후 분석을 위한 상세 메타 데이터

metadata.json 구조:
    - capture_info: pcap 파일 정보
    - attack_flow: 탐지된 공격 flow 상세
    - detection: 모델 탐지 결과 (score, confidence, reason)
    - context: 컨텍스트 구간 정보 (전후 시간, 패킷 수) 
    - zeek_analysis: Zeek 분석 결과 (conn, http, dns, ssl)
"""

import json
import logging
import os
import shutil
import subprocess
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
class ZeekConnRecord:
    ts: Optional[str]
    duration: Optional[float]
    src_ip: Optional[str]
    src_port:     Optional[int]
    dst_ip:       Optional[str]
    dst_port:     Optional[int]
    proto:        Optional[str]
    service:      Optional[str]
    orig_bytes:   Optional[int]
    resp_bytes:   Optional[int]
    conn_state:   Optional[str] 
    history:      Optional[str]  


@dataclass
class ZeekHttpRecord:
    ts:          Optional[str]
    src_ip:      Optional[str]
    dst_ip:      Optional[str]
    method:      Optional[str]
    host:        Optional[str]
    uri:         Optional[str]
    status_code: Optional[int]
    user_agent:  Optional[str]
    resp_mime:   Optional[str]

@dataclass
class ZeekDnsRecord:
    ts:       Optional[str]
    src_ip:   Optional[str]
    query:    Optional[str]
    qtype:    Optional[str]    
    rcode:    Optional[str]    
    answers:  list[str]

@dataclass
class ZeekSslRecord:
    """ssl.log 단일 레코드"""
    ts:              Optional[str]
    src_ip:          Optional[str]
    dst_ip:          Optional[str]
    dst_port:        Optional[int]
    version:         Optional[str]   
    cipher:          Optional[str]
    server_name:     Optional[str]   
    subject:         Optional[str]   
    issuer:          Optional[str]
    validation_status: Optional[str]
 
 
@dataclass
class ZeekAnalysis:
    """Zeek 분석 결과 전체"""
    zeek_version:   Optional[str]
    log_dir:        str
    executed_at:    str
    conn:           list[ZeekConnRecord]   = field(default_factory=list)
    http:           list[ZeekHttpRecord]   = field(default_factory=list)
    dns:            list[ZeekDnsRecord]    = field(default_factory=list)
    ssl:            list[ZeekSslRecord]    = field(default_factory=list)
    error:          Optional[str]          = None

@dataclass
class AttackMetadata:
    """최상위 메타데이터"""
    capture: CaptureInfo
    attack_flow: AttackFlowInfo
    detection: DetectionInfo
    context: ContextInfo
    zeek_analysis: ZeekAnalysis


# Zeek 로그 파싱

class ZeekRunner:
    """
    pcap 파일에 Zeek를 실행하고 로그를 파싱하는 유틸리티.
 
    Parameters
    ----------
    zeek_bin : Zeek 실행 파일 경로 (기본 'zeek', PATH에 있으면 그대로 사용)
    """
 
    def __init__(self, zeek_bin: str = "zeek"):
        self.zeek_bin = zeek_bin
        self._version: Optional[str] = None
 
    def run(self, pcap_path: str, log_dir: str) -> ZeekAnalysis:
        os.makedirs(log_dir, exist_ok=True)
        executed_at = datetime.now(tz=timezone.utc).isoformat()

        if not shutil.which(self.zeek_bin):
            msg = f"Zeek 실행 파일을 찾을 수 없음: '{self.zeek_bin}'"
            logger.warning(msg)
            return ZeekAnalysis(
                zeek_version=None, log_dir=log_dir,
                executed_at=executed_at, error=msg,
            )
 
        # Zeek 실행
        cmd = [
            self.zeek_bin, "-r", os.path.abspath(pcap_path),
            "LogAscii::use_json=T",  
        ]
        try:
            result = subprocess.run(
                cmd,
                cwd=log_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                msg = f"Zeek 종료 코드 {result.returncode}: {result.stderr[:500]}"
                logger.warning(msg)
                return ZeekAnalysis(
                    zeek_version=self._get_version(),
                    log_dir=log_dir,
                    executed_at=executed_at,
                    error=msg,
                )
        except subprocess.TimeoutExpired:
            msg = "Zeek 실행 타임아웃 (120초 초과)"
            logger.warning(msg)
            return ZeekAnalysis(
                zeek_version=None, log_dir=log_dir,
                executed_at=executed_at, error=msg,
            )
        except Exception as e:
            msg = f"Zeek 실행 예외: {e}"
            logger.warning(msg)
            return ZeekAnalysis(
                zeek_version=None, log_dir=log_dir,
                executed_at=executed_at, error=msg,
            )
 
        return ZeekAnalysis(
            zeek_version = self._get_version(),
            log_dir      = log_dir,
            executed_at  = executed_at,
            conn         = self._parse_conn(os.path.join(log_dir, "conn.log")),
            http         = self._parse_http(os.path.join(log_dir, "http.log")),
            dns          = self._parse_dns(os.path.join(log_dir, "dns.log")),
            ssl          = self._parse_ssl(os.path.join(log_dir, "ssl.log")),
        )
 
    # 로그 파싱
 
    def _read_json_log(self, path: str) -> list[dict]:
        if not os.path.exists(path):
            return []
        records = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records
 
    def _ts_to_iso(self, ts) -> Optional[str]:
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            return None
 
    def _parse_conn(self, path: str) -> list[ZeekConnRecord]:
        result = []
        for r in self._read_json_log(path):
            result.append(ZeekConnRecord(
                ts          = self._ts_to_iso(r.get("ts")),
                duration    = r.get("duration"),
                src_ip      = r.get("id.orig_h"),
                src_port    = r.get("id.orig_p"),
                dst_ip      = r.get("id.resp_h"),
                dst_port    = r.get("id.resp_p"),
                proto       = r.get("proto"),
                service     = r.get("service"),
                orig_bytes  = r.get("orig_bytes"),
                resp_bytes  = r.get("resp_bytes"),
                conn_state  = r.get("conn_state"),
                history     = r.get("history"),
            ))
        return result
 
    def _parse_http(self, path: str) -> list[ZeekHttpRecord]:
        result = []
        for r in self._read_json_log(path):
            result.append(ZeekHttpRecord(
                ts          = self._ts_to_iso(r.get("ts")),
                src_ip      = r.get("id.orig_h"),
                dst_ip      = r.get("id.resp_h"),
                method      = r.get("method"),
                host        = r.get("host"),
                uri         = r.get("uri"),
                status_code = r.get("status_code"),
                user_agent  = r.get("user_agent"),
                resp_mime   = r.get("resp_mime_types"),
            ))
        return result
 
    def _parse_dns(self, path: str) -> list[ZeekDnsRecord]:
        result = []
        for r in self._read_json_log(path):
            answers = r.get("answers", [])
            if isinstance(answers, str):
                answers = [answers]
            result.append(ZeekDnsRecord(
                ts      = self._ts_to_iso(r.get("ts")),
                src_ip  = r.get("id.orig_h"),
                query   = r.get("query"),
                qtype   = r.get("qtype_name"),
                rcode   = r.get("rcode_name"),
                answers = answers,
            ))
        return result
 
    def _parse_ssl(self, path: str) -> list[ZeekSslRecord]:
        result = []
        for r in self._read_json_log(path):
            result.append(ZeekSslRecord(
                ts                = self._ts_to_iso(r.get("ts")),
                src_ip            = r.get("id.orig_h"),
                dst_ip            = r.get("id.resp_h"),
                dst_port          = r.get("id.resp_p"),
                version           = r.get("version"),
                cipher            = r.get("cipher"),
                server_name       = r.get("server_name"),
                subject           = r.get("subject"),
                issuer            = r.get("issuer"),
                validation_status = r.get("validation_status"),
            ))
        return result
 
    def _get_version(self) -> Optional[str]:
        if self._version:
            return self._version
        try:
            r = subprocess.run(
                [self.zeek_bin, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            self._version = r.stdout.strip() or r.stderr.strip()
            return self._version
        except Exception:
            return None


class AttackPacketWriter:
    """
    공격 탐지 시 호출되는 저장 컴포넌트.

    Parameters
    ----------
    output_dir : 저장 루트 디렉토리. 없으면 자동 생성.
    before_sec : 컨텍스트 - 탐지 시점 이전 구간 (초)
    after_sec  : 컨텍스트 - 탐지 시점 이후 구간 (초)
    zeek_bin   : Zeek 실행 파일 경로
    """

    def __init__(self, output_dir: str = "./attack_pcaps", before_sec: float = 10.0, after_sec: float = 10.0, zeek_bin: str = "zeek"):
        self.output_dir = output_dir
        self.before_sec = before_sec
        self.after_sec = after_sec
        self.zeek = ZeekRunner(zeek_bin)
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
        log_dir = os.path.join(save_dir, "zeek_logs")

        # 공격 + 컨텍스트 시간순 정렬 후 단일 pcap으로 저장
        all_packets = self._merge_sorted(attack_packets, context_packets)
        self._write_pcap(pcap_path, all_packets)

        zeek_analysis = self.zeek.run(pcap_path, log_dir)

        # 메타데이터 생성 및 저장
        meta = self._build_metadata(
            flow_id, attack_packets, context_packets, anomaly_score, pcap_path, extra, zeek_analysis,
        )
        self._write_json(os.path.join(save_dir, "metadata.json"), meta)

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
        zeek_analysis: ZeekAnalysis,
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

        def to_iso(ts: float) -> str:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        
        atk_times   = [pkt_time(p) for p in attack_packets]
        atk_start   = min(atk_times)
        atk_end     = max(atk_times)
        all_packets = attack_packets + context_packets
        all_times = [pkt_time(p) for p in all_packets]
 

        return AttackMetadata(
            capture=CaptureInfo(
                pcap_path        = os.path.abspath(pcap_path),
                total_packets    = len(all_packets),
                attack_packets   = len(attack_packets),
                context_packets  = len(context_packets),
                capture_start    = to_iso(min(all_times)) if all_times else None,
                capture_end      = to_iso(max(all_times)) if all_times else None,
                duration_seconds = round(max(all_times) - min(all_times), 6) if all_times else 0,
            ),
            attack_flow=AttackFlowInfo(
                flow_id          = flow_id,
                src_ip           = src_ip,
                dst_ip           = dst_ip,
                src_port         = src_port,
                dst_port         = dst_port,
                protocol         = protocol,
                flow_start       = to_iso(atk_start),
                flow_end         = to_iso(atk_end),
                flow_duration_sec= round(atk_end - atk_start, 6),
                total_bytes      = sum(len(p) for p in attack_packets),
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
                context_start   = to_iso(atk_start - self.before_sec),
                context_end     = to_iso(atk_end + self.after_sec),
                context_packets = len(context_packets),
            ),
            zeek_analysis=zeek_analysis,
        )
 
    def _write_json(self, path: str, meta: AttackMetadata) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(meta), f, indent=2, ensure_ascii=False)
