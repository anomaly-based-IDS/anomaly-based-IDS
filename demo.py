"""
demo.py

python demo.py
python demo.py --pcap custom.pcap --model custom.pkl --output ./demo_output
python demo.py --before 5 --after 5 --flows 1000

"""

import argparse
import json
import os
import sys
import time

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
ok(f"predict_batch 동작 확인 — pred={preds[0]}, score={scores[0]:.4f}")

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
for i in range(10):
    atk = IP(src="192.168.1.100", dst="10.0.0.1") / TCP()
    atk.time = ATK_START + i
    ctx_buf.add(atk, timestamp=ATK_START + i)

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
              attack_flow : flow 상세 (IP, 포트, bytes, duration)
              detection   : score, confidence, anomaly_reason
              context     : before/after_sec, 컨텍스트 구간 시각
              zeek_analysis: conn/http/dns/ssl 파싱 결과
""")

step("실제 저장 시연 (더미 패킷으로 구조 확인)")

writer = AttackPacketWriter(
    output_dir = os.path.join(args.output, "storage_demo"),
    before_sec = args.before,
    after_sec  = args.after,
)

# 더미 공격 패킷
atk_pkts = []
for i in range(5):
    p = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=54321, dport=80)
    p.time = BASE_TIME + 10 + i
    atk_pkts.append(p)

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

from pipeline import AttackCapturePipeline

step("AttackCapturePipeline 초기화")

pipeline = AttackCapturePipeline(
    detector             = detector,
    max_packets          = 5000,
    ttl_seconds          = 120.0,
    output_dir           = os.path.join(args.output, "pipeline_result"),
    batch_size           = 100,
    confidence_threshold = 0.3,
    idle_timeout         = 120.0,
    context_before_sec   = args.before,
    context_after_sec    = args.after,
    context_max_duration = 300.0,
)

info(f"PacketBuffer  : max={pipeline.buffer._max} pkts/flow | ttl={pipeline.buffer._ttl}s")
info(f"ContextBuffer : before={args.before}s / after={args.after}s / max_duration=300s")
info(f"배치 크기      : {pipeline.batch_size}")
info(f"confidence 임계값: {pipeline.confidence_threshold}")

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
rate   = (attack / total * 100) if total > 0 else 0.0

print(f"""
  ┌─────────────────────────────────────┐
  │  총 처리 패킷   : {pkts:>10,} 개         │
  │  총 처리 플로우  : {total:>10,} 건         │
  │  탐지된 공격    : {attack:>10,} 건         │
  │  탐지율         : {rate:>9.2f} %         │
  │  소요 시간      : {elapsed:>9.2f} 초        │
  └─────────────────────────────────────┘
""")

step("저장 결과 확인")
output_dir = os.path.join(args.output, "pipeline_result")
if os.path.exists(output_dir):
    saved_dirs = [
        d for d in os.listdir(output_dir)
        if os.path.isdir(os.path.join(output_dir, d))
    ]
    info(f"저장된 공격 케이스 : {len(saved_dirs)}건")
    for d in saved_dirs[:3]:
        full = os.path.join(output_dir, d)
        files = os.listdir(full)
        has_zeek = "zeek_logs" in files
        print(f"\n    📁 {d}")
        print(f"       파일: {', '.join(files)}")
        print(f"       Zeek 분석: {'완료' if has_zeek else '미실행(Zeek 미설치)'}")

        meta_path = os.path.join(full, "metadata.json")
        if os.path.exists(meta_path):
            with open(meta_path, encoding="utf-8") as f:
                m = json.load(f)
            print(f"       공격 패킷: {m['capture']['attack_packets']}개 "
                  f"| 컨텍스트: {m['capture']['context_packets']}개 "
                  f"| score: {m['detection']['anomaly_score']:.4f} "
                  f"| conf: {m['detection']['confidence']:.2f}")
    if len(saved_dirs) > 3:
        info(f"... 외 {len(saved_dirs)-3}건")
else:
    info("탐지된 공격 없음 (정상 pcap이거나 threshold 조정 필요)")

print(f"\n{SEPARATOR}")
print("  시연 완료")
print(SEPARATOR)