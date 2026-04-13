import pandas as pd
import numpy as np
import os
from AnomalyDetector import AnomalyDetector

# 1. 경로 설정
BASE_DIR = "MachineLearningCVE"
TEST_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
TEST_PATH = os.path.join(BASE_DIR, TEST_FILE)
MODEL_PATH = "anomaly_ids_model.pkl"

def run_test():
    # 모델 초기화 및 로드
    detector = AnomalyDetector()
    if not os.path.exists(MODEL_PATH):
        print("❌ 에러: 모델 파일이 없습니다. train_model.py를 먼저 실행하세요.")
        return
    detector.load_model(MODEL_PATH)

    # 2. 데이터 로드 및 전처리
    print(f"📅 데이터 로딩 시작: {TEST_FILE}...")
    df = pd.read_csv(TEST_PATH, low_memory=False)
    df.columns = df.columns.str.strip()

    df_selected = df[detector.feature_names].copy()
    df_selected = df_selected.apply(pd.to_numeric, errors='coerce')
    df_selected = df_selected.replace([np.inf, -np.inf], 0).fillna(0)
    X_test = df_selected.values.astype('float32')

    # 3. 탐지 수행
    print("🔍 탐지 수행 중... (잠시만 기다려 주세요)")
    X_test_scaled = detector.scaler.transform(X_test)
    
    # Isolation Forest에서 이상치 점수(score_samples)를 직접 가져옴
    scores = detector.model.score_samples(X_test_scaled)
    predictions = detector.model.predict(X_test_scaled)

    # 4. 결과 요약 (중복 없이 한 번만 출력하도록 구성)
    total = len(predictions)
    anomalies = np.count_nonzero(predictions == -1)
    normal = np.count_nonzero(predictions == 1)

    print("\n" + "="*50)
    print(f"🚀 [최종 탐지 결과 보고서]")
    print("-" * 50)
    print(f"1. 전체 데이터 수   : {total:,}건")
    print(f"2. 정상 판정        : {normal:,}건")
    print(f"3. 이상 탐지(공격)  : {anomalies:,}건")
    print(f"4. 최종 탐지율      : {(anomalies/total)*100:.2f}%")
    print("="*50)

    # 5. [업그레이드] 이상 탐지 사유 분석 (신뢰도 높은 순 상위 5개)
    anomaly_indices = np.where(predictions == -1)[0]
    
    if len(anomaly_indices) > 0:
        # 이상치들의 신뢰도 점수만 따로 모아서 정렬
        # score_samples는 낮을수록 더 이상한 놈이므로, 가장 낮은 순서대로 인덱스 정렬
        anomaly_scores = scores[anomaly_indices]
        top_anomaly_indices = anomaly_indices[np.argsort(anomaly_scores)[:5]]

        print("\n🕵️ [이상 탐지 상세 분석 - 모델 확신도 기준 Top 5]")
        print("-" * 75)
        for i in top_anomaly_indices:
            flow_sample = dict(zip(detector.feature_names, X_test[i]))
            # AnomalyDetector의 predict_anomaly 활용
            _, conf, reason = detector.predict_anomaly(flow_sample)
            actual = df.iloc[i]['Label'] if 'Label' in df.columns else "N/A"
            
            print(f"-> 원인: {reason:20} | 신뢰도: {conf:.2f} | 실제: {actual}")
        print("-" * 75)

    # 6. 실제 라벨 분포 확인
    if 'Label' in df.columns:
        print("\n📝 [데이터셋 실제 라벨 분포]")
        print(df['Label'].value_counts())

if __name__ == "__main__":
    run_test()