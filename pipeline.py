"""
pipeline.py
-----------
pcap 파일 기반 사후 분석 파이프라인 (마이크로 배치 + 배치 단위 공격 병합).

흐름:
  pcap 파일
    │
    ├─ PacketEvent → PacketBuffer.add()      (flow 인스턴스(uid)별 버퍼)
    │              → ContextBuffer.add()     (전역 타임라인)
    │              → AttackWindowManager.tick()  (after 구간이 지난 윈도우 저장)
    │
    └─ FlowEvent   → 배치 큐 누적
                       └── BATCH_SIZE 도달 시
                             AnomalyDetector.predict_batch()
                               ├─ 정상 → PacketBuffer.flush() (메모리 해제)
                               └─ 공격 → PacketBuffer.flush()
                                         AttackWindowManager.push()
                             배치 끝 → AttackWindowManager.close()
                                         (배치 내 공격을 윈도우 1개로 병합)
                             after 구간 경과 후 → ContextBuffer.get_context()
                                                  AttackPacketWriter.write()

실행:
  python pipeline.py
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from AnomalyDetector import AnomalyDetector
from pcap_reader import PcapFlowReader, PacketEvent, FlowEvent
from packet_buffer import PacketBuffer, ContextBuffer
from attack_writer import AttackPacketWriter
from scapy.layers.inet import IP

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════
# AttackWindowManager — 배치 단위 공격 병합
# ══════════════════════════════════════════════════════════════════════

@dataclass
class _AttackEntry:
    """단일 공격 flow의 탐지 정보"""
    flow_id:    str
    src_ip:     str
    dst_ip:     str
    atk_start:  float
    atk_end:    float
    packets:    list
    score:      float
    confidence: float
    reason:     str


@dataclass
class _AttackWindow:
    """배치 하나에서 탐지된 공격 flow들을 묶은 윈도우"""
    entries: list[_AttackEntry] = field(default_factory=list)

    @property
    def window_start(self) -> float:
        return min(e.atk_start for e in self.entries)

    @property
    def window_end(self) -> float:
        return max(e.atk_end for e in self.entries)

    @property
    def ips(self) -> set[str]:
        result = set()
        for e in self.entries:
            result.add(e.src_ip)
            result.add(e.dst_ip)
        return result

    @property
    def all_attack_packets(self) -> list:
        pkts = []
        for e in self.entries:
            pkts.extend(e.packets)
        pkts.sort(key=lambda p: float(p.time))
        return pkts

    @property
    def worst_score(self) -> float:
        return min(e.score for e in self.entries)

    @property
    def max_confidence(self) -> float:
        return max(e.confidence for e in self.entries)

    @property
    def primary_entry(self) -> _AttackEntry:
        """가장 이상한(score가 가장 낮은) 공격 flow"""
        return min(self.entries, key=lambda e: e.score)


@dataclass
class SavedWindow:
    """저장 완료된 윈도우 요약 (결과 통계용)"""
    save_dir:        Optional[str]
    merged_count:    int
    attack_packets:  int
    context_packets: int


class AttackWindowManager:
    """
    배치 단위로 공격 flow를 병합해 컨텍스트 중복 저장을 줄인다.

    동작:
      - push()  : 현재 배치에서 탐지된 공격을 모은다.
      - close() : 배치 끝에 호출. 모은 공격을 윈도우 1개로 묶어 대기열에 넣는다.
                  대기 중인 직전 윈도우와 컨텍스트 구간이 겹치면 그 윈도우에 합친다
                  (배치 경계에서 한 공격이 둘로 나뉘는 것 방지).
                  단, 합친 윈도우 길이가 max_window_sec 를 넘으면 합치지 않는다.
      - tick()  : 패킷 시각(now)이 window_end + after_sec 를 지나면 저장한다.
                  after 구간 패킷이 ContextBuffer에 다 들어온 뒤에 저장하기 위함.
      - flush() : 파이프라인 종료 시 남은 윈도우를 모두 저장한다.

    컨텍스트:
      - 윈도우에 포함된 모든 공격 flow의 IP를 대상으로 조회한다.
      - 공격 패킷 자체는 컨텍스트에서 제외한다.
      - IP별로 이미 저장한 컨텍스트 구간을 기억해, 같은 패킷을 다른 이벤트에
        다시 저장하지 않는다. (전체 저장 패킷 수 ≤ 전체 처리 패킷 수)
    """

    def __init__(
        self,
        context_buffer: ContextBuffer,
        writer:         AttackPacketWriter,
        after_sec:      float,
        before_sec:     float = 0.0,
        max_window_sec: float = 60.0,
    ):
        self.context_buffer = context_buffer
        self.writer         = writer
        self.after_sec      = after_sec
        self.before_sec     = before_sec
        self.max_window_sec = max_window_sec
        self._saved_ranges: dict[str, tuple[float, float]] = {}   # ip → (from, to)
        self._current: list[_AttackEntry] = []
        self._pending: list[_AttackWindow] = []
        self.saved:    list[SavedWindow] = []

    # ── 공개 API ──────────────────────────────────────────────────────

    def push(self, entry: _AttackEntry) -> None:
        self._current.append(entry)

    def close(self) -> None:
        if not self._current:
            return
        window = _AttackWindow(entries=self._current)
        self._current = []

        if self._pending and self._can_merge(self._pending[-1], window):
            self._pending[-1].entries.extend(window.entries)
            logger.debug("[WINDOW] 직전 대기 윈도우와 병합 → flows=%d",
                         len(self._pending[-1].entries))
            return
        self._pending.append(window)
        logger.debug(
            "[WINDOW] close: flows=%d | [%.3f, %.3f]",
            len(window.entries), window.window_start, window.window_end,
        )

    def tick(self, now: Optional[float]) -> None:
        if not self._pending or now is None:
            return
        self._save_while(lambda w: now > w.window_end + self.after_sec)

    def flush(self) -> None:
        self.close()
        self._save_while(lambda w: True)

    def _save_while(self, is_ready) -> None:
        """
        준비된 윈도우를 하나씩 저장한다. 저장 중인 윈도우만 대기열에서 빼고
        나머지는 대기열에 남겨 두어, 그 공격 패킷이 컨텍스트로 중복 저장되지 않게 한다.
        """
        i = 0
        while i < len(self._pending):
            if is_ready(self._pending[i]):
                self._save_window(self._pending.pop(i))
            else:
                i += 1

    @property
    def pending_count(self) -> int:
        return len(self._pending) + (1 if self._current else 0)

    # ── 내부 ──────────────────────────────────────────────────────────

    def _can_merge(self, prev: _AttackWindow, new: _AttackWindow) -> bool:
        """두 윈도우의 컨텍스트 구간이 겹치고, 합친 길이가 제한 이내인지"""
        overlap = (new.window_start - self.before_sec) <= (prev.window_end + self.after_sec) \
            and (prev.window_start - self.before_sec) <= (new.window_end + self.after_sec)
        span = max(prev.window_end, new.window_end) - min(prev.window_start, new.window_start)
        return overlap and span <= self.max_window_sec

    def _pending_attack_ids(self) -> set[int]:
        ids = set()
        for w in self._pending:
            for e in w.entries:
                ids.update(id(p) for p in e.packets)
        for e in self._current:
            ids.update(id(p) for p in e.packets)
        return ids

    def _already_saved(self, pkt) -> bool:
        """이 패킷이 이전 이벤트의 컨텍스트로 이미 저장됐는지"""
        ts = float(pkt.time)
        ip = pkt[IP]
        for addr in (ip.src, ip.dst):
            rng = self._saved_ranges.get(addr)
            if rng and rng[0] <= ts <= rng[1]:
                return True
        return False

    def _save_window(self, window: _AttackWindow) -> None:
        atk_pkts = window.all_attack_packets
        if not atk_pkts:
            logger.warning("[WINDOW] 공격 패킷이 없는 윈도우 — 저장 스킵")
            return

        ctx_pkts = self.context_buffer.get_context(
            ips          = window.ips,
            attack_start = window.window_start,
            attack_end   = window.window_end,
            # 이 윈도우와 아직 저장 전인 다른 윈도우의 공격 패킷은 컨텍스트에서 제외
            exclude      = {id(p) for p in atk_pkts} | self._pending_attack_ids(),
        )
        ctx_pkts = [p for p in ctx_pkts if not self._already_saved(p)]
        t_from = window.window_start - self.before_sec
        t_to   = window.window_end + self.after_sec
        for addr in window.ips:
            prev = self._saved_ranges.get(addr)
            if prev and prev[1] >= t_from:                # 이어지는 구간이면 확장
                self._saved_ranges[addr] = (min(prev[0], t_from), max(prev[1], t_to))
            else:
                self._saved_ranges[addr] = (t_from, t_to)

        n = len(window.entries)
        primary = window.primary_entry
        representative_id = (
            primary.flow_id if n == 1 else f"{primary.flow_id}__merged_{n}"
        )

        save_dir = self.writer.write(
            flow_id         = representative_id,
            attack_packets  = atk_pkts,
            context_packets = ctx_pkts,
            anomaly_score   = window.worst_score,
            extra={
                "confidence":   window.max_confidence,
                "reason":       primary.reason,
                "merged_flows": [e.flow_id for e in window.entries],
                "merged_count": n,
            },
        )
        self.saved.append(SavedWindow(
            save_dir        = save_dir,
            merged_count    = n,
            attack_packets  = len(atk_pkts),
            context_packets = len(ctx_pkts),
        ))
        logger.info(
            "[WINDOW SAVED] flows=%d | atk_pkts=%d | ctx_pkts=%d | window=[%.1f, %.1f]",
            n, len(atk_pkts), len(ctx_pkts), window.window_start, window.window_end,
        )


# ══════════════════════════════════════════════════════════════════════
# AttackCapturePipeline
# ══════════════════════════════════════════════════════════════════════

class AttackCapturePipeline:
    """
    pcap 기반 사후 분석 파이프라인.

    Parameters
    ----------
    detector             : 학습 완료된 AnomalyDetector
    max_packets          : PacketBuffer — flow당 최대 보관 패킷 수
    ttl_seconds          : PacketBuffer TTL (pcap 모드에서는 GC 스레드를 쓰지 않음, 아래 참고)
    output_dir           : 공격 pcap/json 저장 경로
    batch_size           : 마이크로 배치 크기 (= 병합 단위)
    confidence_threshold : AnomalyDetector.get_confidence() 값이 이 이상인 공격만 저장 (0~1)
    idle_timeout         : flow 강제 종료 idle 시간 (초)
    context_before_sec   : 공격 시작 전 컨텍스트 구간 (초)
    context_after_sec    : 공격 종료 후 컨텍스트 구간 (초)
    context_max_duration : ContextBuffer 전역 타임라인 보관 시간 (초)
    max_window_sec       : 병합된 공격 윈도우의 최대 길이 (초). context_max_duration 보다 작아야 함
    zeek_bin             : Zeek 실행 파일 경로

    PacketBuffer GC:
      pcap 모드에서는 모든 flow가 FIN/RST, idle timeout, EOF 중 하나로 반드시
      FlowEvent를 내고 flush되므로 GC 스레드가 필요 없다. 벽시계 기준 GC는
      Zeek 실행 등으로 처리가 늦어질 때 판정 대기 중인 flow를 지워버릴 수 있어 끈다.
    """

    def __init__(
        self,
        detector:              AnomalyDetector,
        max_packets:           int   = 5000,
        ttl_seconds:           float = 120.0,
        output_dir:            str   = "./attack_pcaps",
        batch_size:            int   = 100,
        confidence_threshold:  float = 0.0,
        idle_timeout:          float = 120.0,
        context_before_sec:    float = 10.0,
        context_after_sec:     float = 10.0,
        context_max_duration:  float = 300.0,
        max_window_sec:        float = 60.0,
        zeek_bin:              str   = "zeek",
    ):
        if not detector.is_trained:
            raise ValueError(
                "학습되지 않은 모델입니다. "
                "detector.train() 또는 detector.load_model()을 먼저 호출하세요."
            )

        self.detector = detector
        self.buffer = PacketBuffer(max_packets, ttl_seconds, evict_interval=0)
        self.context_buffer = ContextBuffer(
            before_sec   = context_before_sec,
            after_sec    = context_after_sec,
            max_duration = context_max_duration,
        )
        self.writer = AttackPacketWriter(
            output_dir = output_dir,
            before_sec = context_before_sec,
            after_sec  = context_after_sec,
            zeek_bin   = zeek_bin,
        )
        self.window_manager = AttackWindowManager(
            context_buffer = self.context_buffer,
            writer         = self.writer,
            after_sec      = context_after_sec,
            before_sec     = context_before_sec,
            max_window_sec = max_window_sec,
        )
        if max_window_sec + context_before_sec + context_after_sec > context_max_duration:
            logger.warning(
                "max_window_sec(%.0f)+before+after 가 context_max_duration(%.0f)보다 큼 "
                "— 긴 윈도우의 앞쪽 컨텍스트가 유실될 수 있음",
                max_window_sec, context_max_duration,
            )
        self._reader = PcapFlowReader(idle_timeout=idle_timeout)
        self.batch_size = batch_size
        self.confidence_threshold = confidence_threshold

    # ── pcap 실행 ─────────────────────────────────────────────────────

    def run_pcap(self, pcap_path: str, max_flows: int = 0) -> dict:
        """
        pcap 파일을 스트리밍으로 읽어 파이프라인을 실행한다.

        max_flows : 0이면 전체 처리, 양수면 해당 수 이상 처리 후 조기 종료

        Returns
        -------
        dict : total_packets, total_flows, attack_count(공격 flow 수),
               saved_events(저장된 윈도우 수), saved_attack_packets,
               saved_context_packets, saved_dirs
        """
        logger.info("=== pcap 시작: %s ===", pcap_path)

        batch_queue: list[FlowEvent] = []
        total_flows = pkt_count = attack_count = 0
        next_progress = 1000

        for event in self._reader.stream(pcap_path):
            if isinstance(event, PacketEvent):
                ts = event.timestamp
                self.buffer.add(event.uid, event.packet, timestamp=ts)
                self.context_buffer.add(event.packet, timestamp=ts)
                self.window_manager.tick(ts)
                pkt_count += 1

            elif isinstance(event, FlowEvent):
                batch_queue.append(event)
                if len(batch_queue) >= self.batch_size:
                    attack_count += self._process_batch(batch_queue)
                    total_flows += len(batch_queue)
                    batch_queue.clear()

                    if total_flows >= next_progress:
                        next_progress += 1000
                        logger.info(
                            "진행 중... flow=%d | 공격=%d | 버퍼=%d flows",
                            total_flows, attack_count, self.buffer.active_flow_count(),
                        )

                    if max_flows > 0 and total_flows >= max_flows:
                        logger.info("조기 종료: %d flows 처리 완료", total_flows)
                        break

        # 자투리 배치 처리
        if batch_queue:
            attack_count += self._process_batch(batch_queue)
            total_flows += len(batch_queue)
            batch_queue.clear()

        # 남은 윈도우 저장
        self.window_manager.flush()

        saved = self.window_manager.saved
        result = {
            "total_packets":         pkt_count,
            "total_flows":           total_flows,
            "attack_count":          attack_count,
            "saved_events":          len(saved),
            "saved_attack_packets":  sum(s.attack_packets for s in saved),
            "saved_context_packets": sum(s.context_packets for s in saved),
            "saved_dirs":            [s.save_dir for s in saved if s.save_dir],
        }
        logger.info(
            "=== pcap 완료 | 패킷=%d | flow=%d | 공격 flow=%d (%.2f%%) | 저장 이벤트=%d ===",
            pkt_count, total_flows, attack_count,
            (attack_count / total_flows * 100) if total_flows > 0 else 0.0,
            len(saved),
        )
        return result

    def stats(self) -> dict:
        s = self.buffer.stats
        return {
            "active_flows":  s.active_flows,
            "total_added":   s.total_added,
            "total_flushed": s.total_flushed,
            "total_evicted": s.total_evicted,
        }

    # ── 내부 메서드 ───────────────────────────────────────────────────

    def _process_batch(self, batch: list[FlowEvent]) -> int:
        feature_matrix = np.array([e.features for e in batch], dtype=float)
        feature_matrix = np.nan_to_num(feature_matrix, nan=0.0, posinf=0.0, neginf=0.0)
        predictions, scores, x_scaled = self.detector.predict_batch(feature_matrix)
        confidences = self.detector.get_confidence(scores)

        attack_count = 0
        for i, pred in enumerate(predictions):
            ev = batch[i]
            # 판정이 끝났으므로 정상/공격 모두 버퍼에서 꺼낸다 (메모리 해제)
            pkts = self.buffer.flush(ev.uid or ev.flow_id)

            if pred != -1 or confidences[i] < self.confidence_threshold:
                continue
            if not pkts:
                logger.warning("[SKIP] flow_id=%s | 버퍼에 패킷 없음", ev.flow_id)
                continue

            attack_count += 1
            reason = self.detector.get_anomaly_reason(x_scaled[i])
            self.window_manager.push(_AttackEntry(
                flow_id    = ev.flow_id,
                src_ip     = ev.flow_key.src_ip,
                dst_ip     = ev.flow_key.dst_ip,
                atk_start  = ev.flow_start,
                atk_end    = ev.flow_end,
                packets    = pkts,
                score      = float(scores[i]),
                confidence = float(confidences[i]),
                reason     = reason,
            ))
            logger.info(
                "[ATTACK] %s | score=%.4f | conf=%.3f | reason=%s | pkts=%d",
                ev.flow_id, scores[i], confidences[i], reason, len(pkts),
            )

        # 배치 끝: 이번 배치의 공격을 윈도우 1개로 병합
        self.window_manager.close()
        return attack_count


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    PCAP_FILE  = "forTest.pcap"
    MODEL_PATH = "anomaly_ids_model.pkl"
    OUTPUT_DIR = "./attack_pcaps"

    detector = AnomalyDetector(model_path=MODEL_PATH)
    detector.load_model()

    pipeline = AttackCapturePipeline(detector=detector, output_dir=OUTPUT_DIR)
    result = pipeline.run_pcap(PCAP_FILE, max_flows=5000)

    total = result["total_flows"]
    print("\n" + "=" * 50)
    print("[파이프라인 종료]")
    print(f"▶ 총 처리 플로우 : {total:,}건")
    if total > 0:
        print(f"▶ 공격 flow      : {result['attack_count']:,}건 "
              f"({result['attack_count'] / total * 100:.2f}%)")
    print(f"▶ 저장 이벤트    : {result['saved_events']:,}건")
    print(f"▶ 총 패킷        : {result['total_packets']:,}개")
    print(f"▶ 저장 경로      : {OUTPUT_DIR}")
    print("=" * 50)
