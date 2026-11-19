"""
evaluate.py
-----------
파이프라인을 한 번 돌리고 탐지 성능(오탐/미탐)과 저장 효율, 저장 무결성(중복 저장)을
한 번에 리포트한다.

  1) 입력 pcap이 크면(기본 300MB 초과) slice_pcap.py 로 최소 구간만 잘라 test_data/ 에 캐시
  2) AttackCapturePipeline 실행 (flow별 판정을 콜백으로 수집)
  3) 저장된 capture.pcap / metadata.json 을 다시 읽어 검증

지표:
  [탐지 - flow 단위]  TP/FP/FN/TN, 정밀도, 재현율(탐지율), 미탐률(FNR), 오탐률(FPR), F1
                      공격 종류별 탐지율과 첫 탐지 지연
  [탐지 - 이벤트 단위] 저장 이벤트 중 정답 공격 flow를 포함한 비율
  [저장 효율]         저장 패킷/바이트 비율, 공격·컨텍스트 비중, 정답 공격 패킷 보존율,
                      디스크 사용량(Zeek 로그 포함)
  [무결성]            이벤트 간 중복 저장 패킷 수, 저장 ≤ 처리, metadata 와 pcap 패킷 수 일치

결과: <output>/evaluation.json, eval_runs/history.csv (실행 이력 누적)
무결성 검사가 실패하면 종료 코드 1.

사용:
  python evaluate.py Tuesday-WorkingHours.pcap            # 자동으로 잘라서 평가
  python evaluate.py test_data/Tuesday-WorkingHours_slice.pcap --no-zeek
  python evaluate.py forTest.pcap --gt my_rules.json --max-flows 5000
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from flow import FEATURE_NAMES
from ground_truth import BENIGN, GroundTruth, get_profile
from pcap_raw import iter_pcap, parse_five_tuple

logger = logging.getLogger(__name__)

_PKT = FEATURE_NAMES.index("pkt_count")
_BYTES = FEATURE_NAMES.index("byte_count")
NO_ZEEK_BIN = "__zeek_disabled__"


# ══════════════════════════════════════════════════════════════════════
# flow 판정 수집
# ══════════════════════════════════════════════════════════════════════

@dataclass
class _AttackTally:
    flows: int = 0
    detected: int = 0
    packets: int = 0
    first_flow_start: Optional[float] = None
    first_detect_end: Optional[float] = None


@dataclass
class FlowTally:
    """pipeline.flow_callback 으로 flow별 판정을 받아 혼동행렬을 만든다."""
    gt: GroundTruth
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    flows: int = 0
    packets: int = 0
    bytes: int = 0
    attack_packets: int = 0
    model_flagged_dropped: int = 0     # 모델은 이상 판정했지만 threshold/빈 버퍼로 저장 안 됨
    per_attack: dict = field(default_factory=lambda: defaultdict(_AttackTally))
    fp_reasons: Counter = field(default_factory=Counter)

    def __call__(self, ev, pred, score, confidence, flagged):
        k = ev.flow_key
        label = self.gt.label(k.src_ip, k.dst_ip, k.src_port, k.dst_port, ev.flow_start)
        n_pkts = int(ev.features[_PKT])
        self.flows += 1
        self.packets += n_pkts
        self.bytes += int(ev.features[_BYTES])
        if pred == -1 and not flagged:
            self.model_flagged_dropped += 1

        if label == BENIGN:
            if flagged:
                self.fp += 1
                self.fp_reasons[f"{k.protocol}/{min(k.src_port, k.dst_port) or 0}"] += 1
            else:
                self.tn += 1
            return

        self.attack_packets += n_pkts
        t = self.per_attack[label]
        t.flows += 1
        t.packets += n_pkts
        if t.first_flow_start is None or ev.flow_start < t.first_flow_start:
            t.first_flow_start = ev.flow_start
        if flagged:
            self.tp += 1
            t.detected += 1
            if t.first_detect_end is None or ev.flow_end < t.first_detect_end:
                t.first_detect_end = ev.flow_end
        else:
            self.fn += 1


def _ratio(n, d) -> Optional[float]:
    return n / d if d else None


def detection_metrics(t: FlowTally) -> dict:
    precision = _ratio(t.tp, t.tp + t.fp)
    recall = _ratio(t.tp, t.tp + t.fn)
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
    per_attack = {}
    for name in t.gt.attack_names:
        a = t.per_attack.get(name, _AttackTally())
        delay = (a.first_detect_end - a.first_flow_start) \
            if a.first_detect_end is not None and a.first_flow_start is not None else None
        per_attack[name] = {
            "flows": a.flows, "detected": a.detected, "missed": a.flows - a.detected,
            "recall": _ratio(a.detected, a.flows), "packets": a.packets,
            "first_detection_delay_sec": delay,
        }
    return {
        "flows": t.flows,
        "attack_flows": t.tp + t.fn,
        "benign_flows": t.fp + t.tn,
        "tp": t.tp, "fp": t.fp, "fn": t.fn, "tn": t.tn,
        "precision": precision,
        "recall": recall,                                  # 탐지율
        "miss_rate": _ratio(t.fn, t.tp + t.fn),           # 미탐률 (FNR)
        "false_positive_rate": _ratio(t.fp, t.fp + t.tn),  # 오탐률 (FPR)
        "f1": f1,
        "accuracy": _ratio(t.tp + t.tn, t.flows),
        "model_flagged_but_not_saved": t.model_flagged_dropped,
        "per_attack": per_attack,
        "top_false_positive_services": t.fp_reasons.most_common(5),
    }


# ══════════════════════════════════════════════════════════════════════
# 저장 결과 검증
# ══════════════════════════════════════════════════════════════════════

def _parse_flow_id(flow_id: str):
    """'1.2.3.4:80-5.6.7.8:1234-TCP' → (src, dst, sport, dport). 실패 시 None"""
    try:
        a, b, _proto = flow_id.split("-")
        src, sport = a.rsplit(":", 1)
        dst, dport = b.rsplit(":", 1)
        return src, dst, int(sport), int(dport)
    except ValueError:
        return None


def _dir_size(path: str) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def storage_metrics(saved_dirs: list[str], gt: GroundTruth, processed_packets: int,
                    processed_bytes: int, gt_attack_packets: int) -> dict:
    seen: Counter = Counter()           # 패킷 지문 → 저장 횟수
    saved_pkts = saved_bytes = 0
    gt_atk_saved = set()
    meta_atk = meta_ctx = 0
    meta_mismatch = []
    events_true = events_false = 0
    disk_pcap = disk_total = 0

    for d in saved_dirs:
        pcap = os.path.join(d, "capture.pcap")
        n_in_pcap = 0
        if os.path.exists(pcap):
            disk_pcap += os.path.getsize(pcap)
            for reader, rec in iter_pcap(pcap):
                n_in_pcap += 1
                saved_bytes += len(rec.data)
                # 같은 원본 패킷 = 같은 (타임스탬프, 바이트)
                fp = hashlib.blake2b(repr(rec.ts_raw).encode() + rec.data, digest_size=16).digest()
                seen[fp] += 1
                ft = parse_five_tuple(rec.data, reader.linktype)
                if ft and gt.label(ft.src_ip, ft.dst_ip, ft.src_port, ft.dst_port, rec.ts) != BENIGN:
                    gt_atk_saved.add(fp)
        saved_pkts += n_in_pcap
        disk_total += _dir_size(d)

        meta_path = os.path.join(d, "metadata.json")
        is_true = False
        if os.path.exists(meta_path):
            with open(meta_path, encoding="utf-8") as f:
                m = json.load(f)
            cap = m.get("capture", {})
            meta_atk += cap.get("attack_packets", 0)
            meta_ctx += cap.get("context_packets", 0)
            if cap.get("total_packets") != n_in_pcap:
                meta_mismatch.append(os.path.basename(d))
            for fid in m.get("attack_flow", {}).get("merged_flows", []):
                parsed = _parse_flow_id(fid)
                if parsed and gt.label(*parsed) != BENIGN:
                    is_true = True
                    break
        if is_true:
            events_true += 1
        else:
            events_false += 1

    unique = len(seen)
    dup_packets = saved_pkts - unique
    dup_distinct = sum(1 for c in seen.values() if c > 1)
    n_events = len(saved_dirs)
    return {
        "events": n_events,
        "events_with_true_attack": events_true,
        "events_false_alarm": events_false,
        "event_precision": _ratio(events_true, n_events),
        "processed_packets": processed_packets,
        "processed_bytes": processed_bytes,
        "saved_packets": saved_pkts,
        "saved_unique_packets": unique,
        "saved_bytes": saved_bytes,
        "packet_storage_ratio": _ratio(saved_pkts, processed_packets),
        "byte_storage_ratio": _ratio(saved_bytes, processed_bytes),
        "reduction_ratio": (1 - saved_bytes / processed_bytes) if processed_bytes else None,
        "saved_attack_packets_meta": meta_atk,
        "saved_context_packets_meta": meta_ctx,
        "context_share": _ratio(meta_ctx, meta_atk + meta_ctx),
        "avg_packets_per_event": _ratio(saved_pkts, n_events),
        "gt_attack_packets_total": gt_attack_packets,
        "gt_attack_packets_saved": len(gt_atk_saved),
        "gt_attack_packet_coverage": _ratio(len(gt_atk_saved), gt_attack_packets),
        "benign_packets_saved": unique - len(gt_atk_saved),
        "disk_bytes_pcap": disk_pcap,
        "disk_bytes_total": disk_total,
        "duplicate_packets": dup_packets,
        "duplicate_distinct_packets": dup_distinct,
        "metadata_mismatch_events": meta_mismatch,
    }


def integrity_checks(st: dict, pipeline_result: dict) -> list[dict]:
    checks = [
        ("no_duplicate_packets", st["duplicate_packets"] == 0,
         f"이벤트 간 중복 저장 {st['duplicate_packets']:,}개 "
         f"(서로 다른 패킷 {st['duplicate_distinct_packets']:,}개)"),
        ("saved_le_processed", st["saved_packets"] <= st["processed_packets"],
         f"저장 {st['saved_packets']:,} ≤ 처리 {st['processed_packets']:,}"),
        ("metadata_matches_pcap", not st["metadata_mismatch_events"],
         f"metadata/pcap 패킷 수 불일치 이벤트 {len(st['metadata_mismatch_events'])}개"),
        ("pipeline_counts_match",
         pipeline_result["saved_attack_packets"] + pipeline_result["saved_context_packets"]
         == st["saved_packets"],
         f"파이프라인 집계 {pipeline_result['saved_attack_packets'] + pipeline_result['saved_context_packets']:,}"
         f" vs pcap {st['saved_packets']:,}"),
    ]
    return [{"name": n, "passed": bool(ok), "detail": d} for n, ok, d in checks]


# ══════════════════════════════════════════════════════════════════════
# 실행
# ══════════════════════════════════════════════════════════════════════

def run_evaluation(detector, pcap: str, gt: GroundTruth, output_dir: str,
                   pipeline_kwargs: Optional[dict] = None, max_flows: int = 0) -> dict:
    """파이프라인을 실행하고 평가 리포트 dict 를 반환한다 (테스트에서 직접 호출 가능)."""
    from pipeline import AttackCapturePipeline

    tally = FlowTally(gt)
    pipe = AttackCapturePipeline(detector=detector, output_dir=output_dir,
                                 flow_callback=tally, **(pipeline_kwargs or {}))
    started = time.time()
    result = pipe.run_pcap(pcap, max_flows=max_flows)
    elapsed = time.time() - started

    det = detection_metrics(tally)
    st = storage_metrics(result["saved_dirs"], gt, result["total_packets"],
                         tally.bytes, tally.attack_packets)
    checks = integrity_checks(st, result)
    return {
        "input": {"pcap": os.path.abspath(pcap), "bytes": os.path.getsize(pcap),
                  "ground_truth": gt.to_dict()},
        "runtime": {"elapsed_sec": round(elapsed, 2),
                    "packets_per_sec": round(result["total_packets"] / elapsed, 1) if elapsed else None,
                    "flows_judged": tally.flows,
                    "packets_in_judged_flows": tally.packets,
                    "early_stop": bool(max_flows)},
        "pipeline": {k: v for k, v in result.items() if k != "saved_dirs"},
        "detection": det,
        "storage": st,
        "checks": checks,
        "passed": all(c["passed"] for c in checks),
        "output_dir": os.path.abspath(output_dir),
    }


# ── 출력 ───────────────────────────────────────────────────────────────

def _pct(x) -> str:
    return "  N/A" if x is None else f"{x * 100:6.2f}%"


def _mb(n) -> str:
    return f"{n / 2**20:,.2f} MB"


def print_report(r: dict) -> None:
    d, s, rt = r["detection"], r["storage"], r["runtime"]
    line = "=" * 64
    print(f"\n{line}\n  평가 리포트 — {os.path.basename(r['input']['pcap'])}"
          f"  ({r['input']['ground_truth']['name']})\n{line}")
    print(f"  처리: {r['pipeline']['total_packets']:,} pkts / {d['flows']:,} flows"
          f" | {rt['elapsed_sec']}s ({rt['packets_per_sec']} pkts/s)")

    print("\n  [탐지 성능 - flow 단위]")
    print(f"    정답 공격 flow {d['attack_flows']:,} / 정상 flow {d['benign_flows']:,}")
    print(f"    TP {d['tp']:,} | FP {d['fp']:,} | FN {d['fn']:,} | TN {d['tn']:,}")
    print(f"    탐지율(Recall)  {_pct(d['recall'])}    미탐률(FNR) {_pct(d['miss_rate'])}")
    print(f"    정밀도          {_pct(d['precision'])}    오탐률(FPR) {_pct(d['false_positive_rate'])}")
    print(f"    F1              {_pct(d['f1'])}    정확도      {_pct(d['accuracy'])}")
    for name, a in d["per_attack"].items():
        delay = a["first_detection_delay_sec"]
        print(f"    - {name:<12}: {a['detected']:,}/{a['flows']:,} 탐지 ({_pct(a['recall']).strip()})"
              f" | 첫 탐지 지연 {'N/A' if delay is None else f'{delay:.1f}s'}")
    if d["top_false_positive_services"]:
        top = ", ".join(f"{k}×{v}" for k, v in d["top_false_positive_services"])
        print(f"    오탐 상위 서비스(프로토콜/작은 포트): {top}")
    if d["model_flagged_but_not_saved"]:
        print(f"    (모델 이상 판정이지만 threshold/빈 버퍼로 제외: {d['model_flagged_but_not_saved']:,})")

    print("\n  [탐지 성능 - 저장 이벤트 단위]")
    print(f"    저장 이벤트 {s['events']:,} | 정답 공격 포함 {s['events_with_true_attack']:,}"
          f" | 오탐 이벤트 {s['events_false_alarm']:,} | 이벤트 정밀도 {_pct(s['event_precision']).strip()}")

    print("\n  [저장 효율]")
    print(f"    저장 패킷 {s['saved_packets']:,} / 처리 {s['processed_packets']:,}"
          f"  → {_pct(s['packet_storage_ratio']).strip()}")
    print(f"    저장 바이트 {_mb(s['saved_bytes'])} / 처리 {_mb(s['processed_bytes'])}"
          f"  → {_pct(s['byte_storage_ratio']).strip()} (절감 {_pct(s['reduction_ratio']).strip()})")
    print(f"    공격 {s['saved_attack_packets_meta']:,} + 컨텍스트 {s['saved_context_packets_meta']:,}"
          f" (컨텍스트 비중 {_pct(s['context_share']).strip()}) | 이벤트당 평균 "
          f"{(s['avg_packets_per_event'] or 0):,.1f} pkts")
    print(f"    정답 공격 패킷 보존율 {s['gt_attack_packets_saved']:,}/{s['gt_attack_packets_total']:,}"
          f" → {_pct(s['gt_attack_packet_coverage']).strip()} | 저장된 정상 패킷 {s['benign_packets_saved']:,}")
    print(f"    디스크: pcap {_mb(s['disk_bytes_pcap'])} / 전체(metadata·Zeek 포함) {_mb(s['disk_bytes_total'])}")

    print("\n  [무결성 검사]")
    for c in r["checks"]:
        print(f"    {'PASS' if c['passed'] else 'FAIL'}  {c['name']:<24} {c['detail']}")
    print(f"\n  결과: {'PASS' if r['passed'] else 'FAIL'} | 저장 경로 {r['output_dir']}\n{line}")


def _git_rev() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                              cwd=os.path.dirname(os.path.abspath(__file__)),
                              text=True, timeout=5).stdout.strip() or "-"
    except Exception:
        return "-"


def append_history(r: dict, path: str) -> None:
    d, s = r["detection"], r["storage"]
    row = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "git": _git_rev(),
        "pcap": os.path.basename(r["input"]["pcap"]),
        "flows": d["flows"], "tp": d["tp"], "fp": d["fp"], "fn": d["fn"], "tn": d["tn"],
        "recall": d["recall"], "miss_rate": d["miss_rate"], "precision": d["precision"],
        "fpr": d["false_positive_rate"], "f1": d["f1"],
        "events": s["events"], "event_precision": s["event_precision"],
        "packet_storage_ratio": s["packet_storage_ratio"],
        "byte_storage_ratio": s["byte_storage_ratio"],
        "gt_attack_coverage": s["gt_attack_packet_coverage"],
        "duplicates": s["duplicate_packets"],
        "passed": r["passed"],
        "output_dir": r["output_dir"],
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    new = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if new:
            w.writeheader()
        w.writerow({k: (f"{v:.6f}" if isinstance(v, float) else v) for k, v in row.items()})


def _json_default(o):
    if isinstance(o, (set, tuple)):
        return list(o)
    return str(o)


# ── 슬라이스 캐시 ──────────────────────────────────────────────────────

def ensure_slice(pcap: str, gt: GroundTruth, args) -> str:
    """큰 pcap이면 test_data/ 에 잘라 둔 슬라이스를 재사용하거나 새로 만든다."""
    from slice_pcap import slice_pcap

    out = os.path.join(args.slice_dir,
                       os.path.splitext(os.path.basename(pcap))[0] + "_slice.pcap")
    params = {"benign_sec": args.benign_sec, "attack_sec": args.attack_sec, "preroll": args.preroll}
    manifest_path = out + ".json"
    if os.path.exists(out) and os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as f:
            m = json.load(f)
        same_src = m.get("source_bytes") == os.path.getsize(pcap)
        same_params = all(m.get("params", {}).get(k) == v for k, v in params.items())
        if same_src and same_params and m.get("ground_truth") == gt.to_dict():
            print(f"[slice] 캐시 재사용: {out} ({_mb(os.path.getsize(out))})")
            return out
    print(f"[slice] {pcap} ({_mb(os.path.getsize(pcap))}) → {out} 생성 중...")
    m = slice_pcap(pcap, out, gt, **params)
    print(f"[slice] 완료: {m['packets_written']:,} pkts, {_mb(m['output_bytes'])} ({m['elapsed_sec']}s)")
    for name in m["missing_attacks"]:
        print(f"[slice] 경고: '{name}' 공격 패킷을 찾지 못함")
    return out


def _load_gt(args, pcap: str) -> GroundTruth:
    if args.gt:
        return GroundTruth.load(args.gt)
    if args.profile:
        return get_profile(args.profile)
    manifest = pcap + ".json"
    if os.path.exists(manifest):
        return GroundTruth.load(manifest)
    return get_profile("tuesday")


def main():
    p = argparse.ArgumentParser(description="IDS 파이프라인 평가 (탐지 성능 + 저장 효율 + 무결성)")
    p.add_argument("pcap", nargs="?", default="Tuesday-WorkingHours.pcap")
    p.add_argument("--model", default="anomaly_ids_model.pkl")
    p.add_argument("--output", default=None, help="저장 경로 (기본: eval_runs/<시각>)")
    p.add_argument("--profile", default=None, help="정답 프로파일 (기본: 매니페스트 → tuesday)")
    p.add_argument("--gt", default=None, help="정답 규칙 JSON 파일")
    p.add_argument("--max-flows", type=int, default=0, help="flow 처리 상한 (0이면 전체)")
    # 파이프라인 파라미터
    p.add_argument("--batch", type=int, default=100)
    p.add_argument("--threshold", type=float, default=0.0)
    p.add_argument("--before", type=float, default=10.0)
    p.add_argument("--after", type=float, default=10.0)
    p.add_argument("--zeek", default="zeek")
    p.add_argument("--no-zeek", action="store_true", help="Zeek 실행 생략 (빠른 평가)")
    # 크기 제한
    p.add_argument("--no-slice", action="store_true", help="큰 파일도 자르지 않고 그대로 사용")
    p.add_argument("--slice-threshold-mb", type=float, default=300.0, help="이보다 크면 자동으로 자름")
    p.add_argument("--slice-dir", default="test_data")
    p.add_argument("--benign-sec", type=float, default=120.0)
    p.add_argument("--attack-sec", type=float, default=120.0)
    p.add_argument("--preroll", type=float, default=30.0)
    p.add_argument("--history", default="eval_runs/history.csv")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    if args.no_zeek:
        logging.getLogger("attack_writer").setLevel(logging.ERROR)

    for label, path in (("pcap", args.pcap), ("모델", args.model)):
        if not os.path.exists(path):
            print(f"에러: {label} 파일이 없습니다: {path}")
            sys.exit(2)

    gt = _load_gt(args, args.pcap)
    pcap = args.pcap
    if not args.no_slice and os.path.getsize(pcap) > args.slice_threshold_mb * 2**20:
        pcap = ensure_slice(pcap, gt, args)

    from AnomalyDetector import AnomalyDetector
    detector = AnomalyDetector(model_path=args.model)
    detector.load_model()

    out = args.output or os.path.join("eval_runs", datetime.now().strftime("%Y%m%d_%H%M%S"))
    report = run_evaluation(
        detector, pcap, gt, out, max_flows=args.max_flows,
        pipeline_kwargs={
            "batch_size": args.batch,
            "confidence_threshold": args.threshold,
            "context_before_sec": args.before,
            "context_after_sec": args.after,
            "zeek_bin": NO_ZEEK_BIN if args.no_zeek else args.zeek,
        },
    )
    report["params"] = vars(args)
    print_report(report)

    with open(os.path.join(out, "evaluation.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=_json_default)
    append_history(report, args.history)
    print(f"  리포트: {os.path.join(out, 'evaluation.json')} | 이력: {args.history}")
    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
