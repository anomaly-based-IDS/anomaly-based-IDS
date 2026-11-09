"""
analyze_results.py
------------------
저장된 metadata.json을 모아 정밀도와 저장 효율을 계산한다.

python analyze_results.py                         # ./attack_pcaps
python analyze_results.py demo_output/pipeline_result/<run>
"""

import os
import sys
import json
from collections import Counter

TARGET_DIR = sys.argv[1] if len(sys.argv) > 1 else "./attack_pcaps"
ATTACKER_IP = "192.168.10.50"

def analyze_saved_results():
    total_saved = 0
    true_attacks = 0
    false_alarms = 0
    
    # 새로운 통계 지표를 위한 변수
    reasons = Counter()
    total_attack_pkts = 0
    total_context_pkts = 0

    print(f"📂 저장된 결과 분석 중... 대상 디렉터리: {TARGET_DIR}")

    for root, _, files in os.walk(TARGET_DIR):
        if "metadata.json" not in files:
            continue

        meta_path = os.path.join(root, "metadata.json")

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"⚠️ 메타데이터 로드 실패 ({meta_path}): {e}")
            continue

        # 계층 구조 안전하게 추출
        capture_info = data.get("capture", {})
        attack_info = data.get("attack_flow", {})
        detection_info = data.get("detection", {})

        src_ip = attack_info.get("src_ip")
        dst_ip = attack_info.get("dst_ip")

        # 실제 공격 조건 판별 (양방향 검증)
        is_real_attack = (src_ip == ATTACKER_IP or dst_ip == ATTACKER_IP)
        total_saved += 1

        if is_real_attack:
            true_attacks += 1
        else:
            false_alarms += 1

        # 탐지 근거 수집
        reason = detection_info.get("anomaly_reason", "Unknown")
        reasons[reason] += 1

        # 패킷 효율성 통계 누적
        total_attack_pkts += capture_info.get("attack_packets", 0)
        total_context_pkts += capture_info.get("context_packets", 0)

        # PCAP 실재 여부 체크
        pcap_path = capture_info.get("pcap_path")
        if pcap_path and not os.path.exists(pcap_path):
            # 윈도우/리눅스 경로 호환성 차이 방어용
            local_pcap = os.path.join(root, "capture.pcap")
            if not os.path.exists(local_pcap):
                print(f"⚠️ 실물 PCAP 파일이 누락되었습니다: {pcap_path}")

    print("\n" + "=" * 60)
    print("        📊 스마트 패킷 저장 결과 종합 검증 리포트")
    print("=" * 60)
    print(f"▶ 저장된 총 탐지 이벤트 수  : {total_saved:,}개")
    print(f"▶ 실제 공격 탐지 (TP)       : {true_attacks:,}개")
    print(f"▶ 일반 정상 트래픽 오탐 (FP) : {false_alarms:,}개")

    if total_saved > 0:
        precision = (true_attacks / total_saved) * 100
        print(f"🎯 정밀도 (Precision)       : {precision:.2f}%")
        
        print("\n📦 스마트 패킷 녹화 저장 효율성")
        avg_atk = total_attack_pkts / total_saved
        avg_ctx = total_context_pkts / total_saved
        print(f" - 이벤트당 평균 순수 공격 패킷 수 : {avg_atk:.1f} pkts")
        print(f" - 이벤트당 평균 전후 컨텍스트 수  : {avg_ctx:.1f} pkts")
        print(f" - 전체 패킷 대비 컨텍스트 비중    : {(total_context_pkts / (total_attack_pkts + total_context_pkts + 1e-5) * 100):.1f}%")
    else:
        print("🎯 정밀도 (Precision)       : N/A (저장된 데이터 없음)")

    print("\n🔍 탐지 핵심 유발 요인 (Top 5 Anomaly Reasons)")
    print("-" * 60)
    for reason, count in reasons.most_common(5):
        print(f" 📑 {reason:<20} : {count:,} 번 원인 제공")

    print("=" * 60)

if __name__ == "__main__":
    analyze_saved_results()