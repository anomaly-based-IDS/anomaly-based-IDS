"""
test_model.py
-------------
정상 트래픽 pcap에 파이프라인을 돌려 오탐(False Positive) 수준을 확인한다.

python test_model.py
python test_model.py --pcap forTest.pcap --flows 0
"""

import argparse
import logging
import os
import time

from AnomalyDetector import AnomalyDetector
from pipeline import AttackCapturePipeline


def main():
    parser = argparse.ArgumentParser(description="모델 오탐률 점검")
    parser.add_argument("--pcap", default="forTest_normal.pcap")
    parser.add_argument("--model", default="anomaly_ids_model.pkl")
    parser.add_argument("--output", default="./attack_pcaps")
    parser.add_argument("--flows", type=int, default=5000, help="0이면 전체")
    parser.add_argument("--threshold", type=float, default=0.0)
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)

    if not os.path.exists(args.model):
        print(f"에러: {args.model} 가 없습니다. 모델을 먼저 학습하세요.")
        return

    detector = AnomalyDetector(model_path=args.model)
    detector.load_model()

    pipeline = AttackCapturePipeline(
        detector=detector,
        output_dir=args.output,
        confidence_threshold=args.threshold,
    )

    print(f"파이프라인 시작: {args.pcap}")
    start = time.time()
    result = pipeline.run_pcap(args.pcap, max_flows=args.flows)
    elapsed = time.time() - start

    total = result["total_flows"]
    attack = result["attack_count"]
    print("\n" + "=" * 50)
    print("[모델 점검 종료]")
    print(f"▶ 총 처리 플로우 : {total:,}건")
    if total:
        print(f"▶ 이상 판정 flow : {attack:,}건 ({attack / total * 100:.2f}%)")
    print(f"▶ 저장 이벤트    : {result['saved_events']:,}건")
    print(f"▶ 소요 시간      : {elapsed:.2f}초")
    print(f"▶ 저장 경로      : {args.output}")
    print("=" * 50)


if __name__ == "__main__":
    main()
