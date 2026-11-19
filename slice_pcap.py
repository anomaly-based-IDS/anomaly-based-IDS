"""
slice_pcap.py
-------------
수 GB 원본 pcap(예: Tuesday-WorkingHours.pcap)에서 평가에 필요한 최소 구간만 잘라낸다.

자동 모드 (기본):
  - 정상 구간  : 파일 시작 + --benign-offset 부터 --benign-sec 초
  - 공격 구간  : 정답 규칙(공격 종류)마다 첫 공격 패킷 시각 t 기준
                [t - --preroll, t + --attack-sec]  (공격 주변의 정상 트래픽도 함께 포함)
  - 모든 구간이 끝나면 파일 나머지는 읽지 않고 종료한다.
  공격 시각을 시간대(timezone) 가정 없이 패킷에서 직접 찾으므로 안전하다.

수동 모드:
  --range START END  (epoch 초, 여러 번 지정 가능)

출력:
  <out>.pcap       잘라낸 pcap (원본과 같은 형식, 시간순)
  <out>.pcap.json  매니페스트 (구간, 정답 규칙, 구간별 패킷 수) — evaluate.py 가 자동으로 읽음

사용:
  python slice_pcap.py Tuesday-WorkingHours.pcap -o test_data/tuesday_slice.pcap
  python slice_pcap.py Tuesday-WorkingHours.pcap --attack-sec 60 --benign-sec 60
  python slice_pcap.py big.pcap --range 1499170000 1499170300 -o part.pcap
"""

import argparse
import json
import os
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from ground_truth import BENIGN, GroundTruth, get_profile
from pcap_raw import RawPcapReader, parse_five_tuple


@dataclass
class Segment:
    name: str
    start: float
    end: float
    packets: int = 0
    attack_packets: int = 0


def _iso(ts: Optional[float]) -> Optional[str]:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts is not None else None


def slice_pcap(
    src: str,
    out: str,
    gt: GroundTruth,
    benign_sec: float = 120.0,
    benign_offset: float = 0.0,
    attack_sec: float = 120.0,
    preroll: float = 30.0,
    ranges: Optional[list[tuple[float, float]]] = None,
    max_packets: int = 0,
    progress: bool = True,
) -> dict:
    """원본 pcap을 한 번만 순차로 읽어 필요한 구간만 out 에 쓴다. 매니페스트 dict 반환."""
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    manual = bool(ranges)
    segments: list[Segment] = [Segment(f"range{i}", s, e) for i, (s, e) in enumerate(ranges or [])]
    pending_rules = [] if manual else list(gt.attack_names)
    first_seen: dict[str, float] = {}

    preroll_q: deque = deque()   # (ts, record_bytes, label) — 아직 쓰지 않은 최근 패킷
    last_written = float("-inf")
    t0 = None
    read_n = written = 0
    started = time.time()
    next_report = started + 5

    def active(ts):
        return [s for s in segments if s.start <= ts <= s.end]

    def account(ts, label):
        for s in active(ts):
            s.packets += 1
            if label != BENIGN:
                s.attack_packets += 1

    with open(src, "rb") as fin, open(out, "wb") as fout:
        reader = RawPcapReader(fin)
        fout.write(reader.global_header)

        for rec in reader:
            ts = rec.ts
            read_n += 1
            if t0 is None:
                t0 = ts
                if not manual and benign_sec > 0:
                    segments.append(Segment("BENIGN", t0 + benign_offset, t0 + benign_offset + benign_sec))

            ft = parse_five_tuple(rec.data, reader.linktype)
            label = gt.label(ft.src_ip, ft.dst_ip, ft.src_port, ft.dst_port, ts) if ft else BENIGN

            # 새 공격 종류의 첫 패킷 → 공격 구간 생성 + preroll 패킷 소급 기록
            if label in pending_rules:
                pending_rules.remove(label)
                first_seen[label] = ts
                seg = Segment(label, ts - preroll, ts + attack_sec)
                segments.append(seg)
                for qts, qbytes, qlabel in preroll_q:
                    if qts >= seg.start and qts > last_written:
                        fout.write(qbytes)
                        written += 1
                        account(qts, qlabel)
                        last_written = qts

            if active(ts):
                fout.write(reader.record_bytes(rec))
                written += 1
                account(ts, label)
                last_written = max(last_written, ts)
                preroll_q.clear()
            elif pending_rules and preroll > 0:
                preroll_q.append((ts, reader.record_bytes(rec), label))
                while preroll_q and preroll_q[0][0] < ts - preroll:
                    preroll_q.popleft()

            if max_packets and written >= max_packets:
                print(f"[slice] --max-packets {max_packets} 도달, 중단", file=sys.stderr)
                break
            # 남은 공격 종류가 없고 모든 구간이 지났으면 나머지 파일은 읽지 않는다
            if not pending_rules and segments and ts > max(s.end for s in segments):
                break

            if progress and read_n % 20000 == 0 and time.time() >= next_report:
                next_report = time.time() + 5
                print(f"[slice] 읽음 {read_n:,} | 기록 {written:,} | pcap 시각 {_iso(ts)} "
                      f"| 남은 공격 {pending_rules or '-'}", file=sys.stderr)

    for name in pending_rules:
        print(f"[slice] 경고: '{name}' 공격 패킷을 찾지 못함 (원본/정답 규칙 확인)", file=sys.stderr)

    manifest = {
        "source": os.path.abspath(src),
        "source_bytes": os.path.getsize(src),
        "output": os.path.abspath(out),
        "output_bytes": os.path.getsize(out),
        "packets_read": read_n,
        "packets_written": written,
        "elapsed_sec": round(time.time() - started, 2),
        "params": {
            "mode": "manual" if manual else "auto",
            "benign_sec": benign_sec, "benign_offset": benign_offset,
            "attack_sec": attack_sec, "preroll": preroll,
        },
        "attack_first_seen": {k: {"ts": v, "iso": _iso(v)} for k, v in first_seen.items()},
        "missing_attacks": pending_rules,
        "segments": [
            {"name": s.name, "start": s.start, "end": s.end,
             "start_iso": _iso(s.start), "end_iso": _iso(s.end),
             "packets": s.packets, "attack_packets": s.attack_packets}
            for s in sorted(segments, key=lambda s: s.start)
        ],
        "ground_truth": gt.to_dict(),
    }
    with open(out + ".json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    return manifest


def main():
    p = argparse.ArgumentParser(description="평가용 최소 pcap 슬라이스 생성")
    p.add_argument("pcap", help="원본 pcap (libpcap 형식)")
    p.add_argument("-o", "--out", default=None, help="출력 pcap (기본: test_data/<원본>_slice.pcap)")
    p.add_argument("--profile", default="tuesday", help="정답 프로파일 (ground_truth.PROFILES)")
    p.add_argument("--gt", default=None, help="정답 규칙 JSON (지정 시 --profile 무시)")
    p.add_argument("--benign-sec", type=float, default=120.0, help="정상 구간 길이 (0이면 생략)")
    p.add_argument("--benign-offset", type=float, default=0.0, help="정상 구간 시작 = 파일 시작 + offset 초")
    p.add_argument("--attack-sec", type=float, default=120.0, help="공격 종류별 구간 길이 (첫 공격 패킷 이후)")
    p.add_argument("--preroll", type=float, default=30.0, help="첫 공격 패킷 이전에 포함할 초")
    p.add_argument("--range", nargs=2, type=float, action="append", metavar=("START", "END"),
                   help="수동 구간 (epoch 초). 지정하면 자동 구간 대신 사용")
    p.add_argument("--max-packets", type=int, default=0, help="기록 패킷 상한 (0이면 무제한)")
    args = p.parse_args()

    gt = GroundTruth.load(args.gt) if args.gt else get_profile(args.profile)
    out = args.out or os.path.join(
        "test_data", os.path.splitext(os.path.basename(args.pcap))[0] + "_slice.pcap")

    m = slice_pcap(args.pcap, out, gt,
                   benign_sec=args.benign_sec, benign_offset=args.benign_offset,
                   attack_sec=args.attack_sec, preroll=args.preroll,
                   ranges=[tuple(r) for r in args.range] if args.range else None,
                   max_packets=args.max_packets)

    print(f"\n원본  : {m['source']} ({m['source_bytes'] / 2**20:,.1f} MB, {m['packets_read']:,} pkts 읽음)")
    print(f"슬라이스: {m['output']} ({m['output_bytes'] / 2**20:,.1f} MB, {m['packets_written']:,} pkts)")
    for s in m["segments"]:
        print(f"  - {s['name']:<12} {s['start_iso']} ~ {s['end_iso']} | "
              f"pkts={s['packets']:,} (정답 공격 {s['attack_packets']:,})")
    if m["missing_attacks"]:
        print(f"  ! 찾지 못한 공격: {', '.join(m['missing_attacks'])}")
    print(f"매니페스트: {out}.json  ({m['elapsed_sec']}s)")


if __name__ == "__main__":
    main()
