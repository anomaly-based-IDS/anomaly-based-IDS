"""
demo.py

python demo.py
python demo.py --pcap custom.pcap --model custom.pkl --output ./demo_output
python demo.py --before 5 --after 5 --flows 1000
python demo.py --no-pause            # Enter 대기 없이 끝까지 실행

"""

import argparse
import json
import os
import sys
import time
import unicodedata

import numpy as np

SEPARATOR  = "=" * 60
SEPARATOR2 = "-" * 60

def section(title: str):
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)

def step(msg: str):
    print(f"\n  ▶ {msg}")

def ok(msg: str):
    print(f"    ✅ {msg}")

def info(msg: str):
    print(f"    info  {msg}")

def pause(msg: str = "계속하려면 Enter..."):
    if args.no_pause:
        return
    input(f"\n  [ {msg} ] ")


# ══════════════════════════════════════════════════════════════════════
# 인자 파싱
# ══════════════════════════════════════════════════════════════════════

parser = argparse.ArgumentParser(description="IDS 파이프라인 발표 시연")
parser.add_argument("--pcap",   default="forTest.pcap",   help="분석할 pcap 파일")
parser.add_argument("--model",  default="anomaly_ids_model.pkl", help="학습된 모델 파일")
parser.add_argument("--output", default="./demo_output",         help="결과 저장 경로")
parser.add_argument("--flows",  type=int, default=1000,           help="처리할 최대 flow 수")
parser.add_argument("--before", type=float, default=10.0,        help="컨텍스트 전방 구간(초)")
parser.add_argument("--after",  type=float, default=10.0,        help="컨텍스트 후방 구간(초)")
parser.add_argument("--threshold", type=float, default=0.0,      help="저장할 최소 confidence (0~1)")
parser.add_argument("--batch",  type=int, default=100,            help="마이크로 배치 크기 (= 병합 단위)")
parser.add_argument("--zeek",   default="zeek",                   help="Zeek 실행 파일 경로")
parser.add_argument("--no-pause", action="store_true",            help="단계별 Enter 대기 생략")
args = parser.parse_args()


# ══════════════════════════════════════════════════════════════════════
# 파일 확인
# ══════════════════════════════════════════════════════════════════════

section("STEP 1 | 파일 확인")

for label, path in [("pcap 파일", args.pcap), ("모델 파일", args.model)]:
    if not os.path.exists(path):
        print(f"\n  ❌ {label}을 찾을 수 없습니다: {path}")
        sys.exit(1)
    size_mb = os.path.getsize(path) / (1024 ** 2)
    ok(f"{label}: {path}  ({size_mb:.2f} MB)")

info(f"결과 저장 경로 : {args.output}")
info(f"처리 flow 제한 : {args.flows:,}개")
info(f"컨텍스트 구간  : 전방 {args.before}초 / 후방 {args.after}초")
pause("ENTER로 이동")


# ══════════════════════════════════════════════════════════════════════
# 모델 로드
# ══════════════════════════════════════════════════════════════════════

section("STEP 2 | AnomalyDetector 모델 로드")

step("AnomalyDetector 초기화 및 모델 로드 중...")

from AnomalyDetector import AnomalyDetector
from flow import FEATURE_NAMES

detector = AnomalyDetector(model_path=args.model)
detector.load_model()

ok(f"모델 로드 완료 (is_trained={detector.is_trained})")
info(f"피처 수        : {len(detector.feature_names)}개")
info(f"피처 목록      : {', '.join(detector.feature_names)}")

# 더미 피처로 predict_batch 동작 확인
dummy = np.zeros((1, len(FEATURE_NAMES)))
preds, scores, scaled = detector.predict_batch(dummy)
conf = detector.get_confidence(scores)
ok(f"predict_batch 동작 확인 — pred={preds[0]}, score={scores[0]:.4f}, confidence={conf[0]:.3f}")
info(f"판정 경계(offset) : {detector.model.offset_:.4f}  (score < offset 이면 이상)")
info("confidence = (offset - score) / (1 + offset), 0~1  — 더 이상할수록 커짐")

pause("ENTER로 이동")


# ══════════════════════════════════════════════════════════════════════
# PacketBuffer / ContextBuffer 시연
# ══════════════════════════════════════════════════════════════════════

section("STEP 3 | PacketBuffer & ContextBuffer 동작 시연")

from packet_buffer import PacketBuffer, ContextBuffer
from scapy.layers.inet import IP, TCP

step("PacketBuffer — flow별 패킷 적재 시연")

buf = PacketBuffer(max_packets_per_flow=5000, evict_interval=0)
DEMO_FLOW = "192.168.1.100:54321-10.0.0.1:80-TCP"
for i in range(5):
    pkt = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=54321, dport=80)
    pkt.time = time.time() + i * 0.1
    buf.add(DEMO_FLOW, pkt)

info(f"적재된 flow 수  : {buf.active_flow_count()}")
info(f"총 적재 패킷    : {buf.stats.total_added}")
flushed = buf.flush(DEMO_FLOW)
ok(f"flush 완료      : {len(flushed)}개 패킷 반환, 버퍼 잔여={buf.active_flow_count()}")

step("ContextBuffer — 전역 타임라인 시연")

ctx_buf = ContextBuffer(before_sec=args.before, after_sec=args.after, max_duration=300.0)

# t=0~30 구간: 배경 트래픽 (다른 IP)
BASE_TIME = time.time()
for i in range(30):
    bg = IP(src="1.1.1.1", dst="2.2.2.2") / TCP()
    bg.time = BASE_TIME + i
    ctx_buf.add(bg, timestamp=BASE_TIME + i)

# t=10~20 구간: 공격 IP 트래픽
ATK_START = BASE_TIME + 10
ATK_END   = BASE_TIME + 20
atk_timeline = []
for i in range(10):
    atk = IP(src="192.168.1.100", dst="10.0.0.1") / TCP()
    atk.time = ATK_START + i
    ctx_buf.add(atk, timestamp=ATK_START + i)
    atk_timeline.append(atk)

info(f"타임라인 총 패킷 : {len(ctx_buf._timeline)}개")

ctx_pkts = ctx_buf.get_context(
    src_ip="192.168.1.100", dst_ip="10.0.0.1",
    attack_start=ATK_START, attack_end=ATK_END,
)
ok(f"get_context 결과 : {len(ctx_pkts)}개 패킷 "
   f"(공격 구간 ±{args.before}초, 같은 src/dst IP만)")

pause("ENTER로 이동")


# ══════════════════════════════════════════════════════════════════════
# 저장 정책 시연 (이전 vs 현재)
# ══════════════════════════════════════════════════════════════════════

section("STEP 4 | 저장 정책 비교")

from attack_writer import AttackPacketWriter

step("이전 저장 정책 — 공격 패킷만 / 플랫 metadata")
print("""
    attack_pcaps/
    └── 20240601_153042_.../
        ├── attack.pcap        ← 공격 패킷만
        └── metadata.json      ← 단순 플랫 구조
              { "flow_id": ..., "packet_count": ...,
                "anomaly_score": }
""")

step("현재 저장 정책 — 공격 + 컨텍스트 / Zeek 분석 결과 포함")
print("""
    attack_pcaps/
    └── 20240601_153042_.../
        ├── capture.pcap       ← 공격 + 전후 컨텍스트 패킷 (시간순 정렬)
        ├── zeek_logs/         ← Zeek 자동 실행 결과
        │   ├── conn.log
        │   ├── http.log
        │   ├── dns.log
        │   └── ssl.log
        └── metadata.json      ← 5섹션 구조
              capture     : pcap 기본 정보 (공격/컨텍스트 패킷 수, 시각)
              attack_flow : flow 상세 (IP, 포트, bytes, duration, 병합된 flow 목록)
              detection   : score, confidence, anomaly_reason
              context     : before/after_sec, 컨텍스트 구간 시각
              zeek_analysis: conn/http/dns/ssl 파싱 결과
""")

step("실제 저장 시연 (더미 패킷으로 구조 확인)")

writer = AttackPacketWriter(
    output_dir = os.path.join(args.output, "storage_demo"),
    before_sec = args.before,
    after_sec  = args.after,
    zeek_bin   = args.zeek,
)

# 더미 공격 패킷: 타임라인에 들어간 공격 IP 패킷 중 앞 5개를 공격 flow로 사용
# (나머지는 컨텍스트로 저장되고, 공격 패킷은 컨텍스트에서 자동 제외되어 중복 저장되지 않음)
atk_pkts = atk_timeline[:5]

saved = writer.write(
    flow_id         = "192.168.1.100:54321-10.0.0.1:80-TCP",
    attack_packets  = atk_pkts,
    context_packets = ctx_pkts,
    anomaly_score   = -0.42,
    extra           = {"confidence": 0.78, "reason": "pkt_count"},
)

if saved:
    ok(f"저장 완료: {saved}")
    # metadata.json 주요 필드 출력
    with open(os.path.join(saved, "metadata.json"), encoding="utf-8") as f:
        meta = json.load(f)

    print(f"\n    ── metadata.json 미리보기 ──")
    print(f"    capture.total_packets    : {meta['capture']['total_packets']}")
    print(f"    capture.attack_packets   : {meta['capture']['attack_packets']}")
    print(f"    capture.context_packets  : {meta['capture']['context_packets']}")
    print(f"    (pcap 패킷 수 = 공격 + 컨텍스트, 중복 없음)")
    print(f"    attack_flow.src_ip       : {meta['attack_flow']['src_ip']}")
    print(f"    attack_flow.total_bytes  : {meta['attack_flow']['total_bytes']}")
    print(f"    detection.anomaly_score  : {meta['detection']['anomaly_score']}")
    print(f"    detection.confidence     : {meta['detection']['confidence']}")
    print(f"    detection.anomaly_reason : {meta['detection']['anomaly_reason']}")
    print(f"    context.before_sec       : {meta['context']['before_sec']}")
    print(f"    context.after_sec        : {meta['context']['after_sec']}")

    zeek = meta.get("zeek_analysis", {})
    if zeek.get("error"):
        info(f"Zeek 미설치 환경 — error: {zeek['error']}")
    else:
        ok(f"Zeek 분석 완료 — conn={len(zeek.get('conn',[]))} "
           f"http={len(zeek.get('http',[]))} "
           f"dns={len(zeek.get('dns',[]))} "
           f"ssl={len(zeek.get('ssl',[]))}")

pause("ENTER로 이동")


# ══════════════════════════════════════════════════════════════════════
# 전체 파이프라인 실행
# ══════════════════════════════════════════════════════════════════════

section("STEP 5 | 전체 파이프라인 실행")

import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from datetime import datetime
from pipeline import AttackCapturePipeline

step("AttackCapturePipeline 초기화")

# 실행마다 새 폴더에 저장 (이전 실행 결과가 통계에 섞이지 않도록)
run_dir = os.path.join(args.output, "pipeline_result", datetime.now().strftime("%Y%m%d_%H%M%S"))

pipeline = AttackCapturePipeline(
    detector             = detector,
    max_packets          = 5000,
    ttl_seconds          = 120.0,
    output_dir           = run_dir,
    batch_size           = args.batch,
    confidence_threshold = args.threshold,
    idle_timeout         = 120.0,
    context_before_sec   = args.before,
    context_after_sec    = args.after,
    context_max_duration = 300.0,
    zeek_bin             = args.zeek,
)

info(f"PacketBuffer  : max={pipeline.buffer._max} pkts/flow")
info(f"ContextBuffer : before={args.before}s / after={args.after}s / max_duration=300s")
info(f"배치 크기      : {pipeline.batch_size}  (배치 단위로 공격을 병합해 저장)")
info(f"confidence 임계값: {pipeline.confidence_threshold}")
info(f"저장 경로      : {run_dir}")

step(f"pcap 스트리밍 시작: {args.pcap}  (최대 {args.flows:,} flows)")
print()

start_time = time.time()
result = pipeline.run_pcap(args.pcap, max_flows=args.flows)
elapsed = time.time() - start_time


# ══════════════════════════════════════════════════════════════════════
# 결과 요약
# ══════════════════════════════════════════════════════════════════════

section("STEP 6 | 결과 요약")

total  = result["total_flows"]
attack = result["attack_count"]
pkts   = result["total_packets"]
events = result["saved_events"]
atk_saved = result["saved_attack_packets"]
ctx_saved = result["saved_context_packets"]
all_saved = atk_saved + ctx_saved

def pct(n: int) -> float:
    return (n / pkts * 100) if pkts > 0 else 0.0

rate = (attack / total * 100) if total > 0 else 0.0

W = 46
def row(text: str = "") -> str:
    # 한글은 터미널에서 2칸을 차지하므로 표시 폭 기준으로 오른쪽을 채운다
    width = sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)
    return "  │" + text + " " * max(W - width, 0) + "│"

lines = [
    "  ┌" + "─" * W + "┐",
    row(f"  총 처리 패킷      : {pkts:>10,} 개"),
    row(f"  총 처리 플로우    : {total:>10,} 건"),
    row(f"  공격 판정 flow    : {attack:>10,} 건 ({rate:.2f}%)"),
    row(f"  저장 이벤트(병합) : {events:>10,} 건"),
    row(f"  소요 시간         : {elapsed:>10.2f} 초"),
    "  ├" + "─" * W + "┤",
    row(f"  저장된 패킷 합계  : {all_saved:>10,} 개 ({pct(all_saved):.2f}%)"),
    row(f"    ├ 공격 패킷     : {atk_saved:>10,} 개 ({pct(atk_saved):.2f}%)"),
    row(f"    └ 컨텍스트 패킷 : {ctx_saved:>10,} 개 ({pct(ctx_saved):.2f}%)"),
    "  └" + "─" * W + "┘",
]
print()
print("\n".join(lines))
info("저장율 = 저장된 패킷 / 전체 처리 패킷")

step("저장 결과 확인")
saved_dirs = result["saved_dirs"]
SHOW = 3
if saved_dirs:
    info(f"저장된 공격 이벤트 : {len(saved_dirs)}건")
    for full in saved_dirs[:SHOW]:
        files = sorted(os.listdir(full))
        print(f"\n    📁 {os.path.basename(full)}")
        print(f"       파일: {', '.join(files)}")

        meta_path = os.path.join(full, "metadata.json")
        if os.path.exists(meta_path):
            with open(meta_path, encoding="utf-8") as f:
                m = json.load(f)
            zeek = m.get("zeek_analysis", {})
            if zeek.get("error"):
                print(f"       Zeek 분석: 실패/미설치 ({zeek['error'][:60]})")
            else:
                print(f"       Zeek 분석: 완료 (conn={len(zeek.get('conn', []))}, "
                      f"http={len(zeek.get('http', []))})")
            print(f"       병합 flow: {m['attack_flow'].get('merged_count', 1)}개 "
                  f"| 공격 패킷: {m['capture']['attack_packets']}개 "
                  f"| 컨텍스트: {m['capture']['context_packets']}개")
            print(f"       score: {m['detection']['anomaly_score']:.4f} "
                  f"| conf: {m['detection']['confidence']:.3f} "
                  f"| reason: {m['detection']['anomaly_reason']}")
    if len(saved_dirs) > SHOW:
        info(f"... 외 {len(saved_dirs) - SHOW}건")
else:
    info("탐지된 공격 없음 (정상 pcap이거나 threshold 조정 필요)")

print(f"\n{SEPARATOR}")
print("  시연 완료")
print(SEPARATOR)
