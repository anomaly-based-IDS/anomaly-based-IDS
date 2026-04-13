import pandas as pd
import numpy as np
import os
from AnomalyDetector import AnomalyDetector

# 1. 경로 및 피처 설정
BASE_DIR = "MachineLearningCVE"
FILE_NAME = "Monday-WorkingHours.pcap_ISCX.csv"
FILE_PATH = os.path.join(BASE_DIR, FILE_NAME)
MODEL_SAVE_PATH = "anomaly_ids_model.pkl"

# CICIDS2017의 실제 컬럼명과 일치시켜야 함 (공백 제거 후 기준)
SELECTED_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Flow IAT Mean", "Flow IAT Std", "Packet Length Mean", "Packet Length Std",
    "Flow Packets/s", "Flow Bytes/s"
    
]

def run_training():
    # 2. 데이터 로드
    if not os.path.exists(FILE_PATH):
        print(f"에러: {FILE_PATH} 파일을 찾을 수 없습니다.")
        return

    print(f"데이터 로딩 중... ({FILE_NAME})")
    df = pd.read_csv(FILE_PATH, low_memory=False)
    
    # [중요] 컬럼명 공백 제거
    df.columns = df.columns.str.strip()

    # 3. 데이터 정제
    print("데이터 정제 및 특징 추출 중...")
    try:
        df_selected = df[SELECTED_FEATURES].copy()
    except KeyError as e:
        print(f"에러: 선택한 피처가 데이터셋에 없습니다. {e}")
        return

    # 숫자로 변환 및 무한대/결측치 처리
    df_selected = df_selected.apply(pd.to_numeric, errors='coerce')
    df_selected = df_selected.replace([np.inf, -np.inf], 0).fillna(0)
    
    X_train = df_selected.values.astype('float32')

    # 4. 모델 생성 및 학습 시동
    # 월요일 데이터는 정상이므로 contamination을 낮게 설정 (0.1% 내외)
    # train_model.py의 4번 항목 수정
    detector = AnomalyDetector(contamination=0.05, model_path=MODEL_SAVE_PATH) # 0.001 -> 0.05로 변경
    detector.feature_names = SELECTED_FEATURES
    
    print(f"학습 시작 (데이터 크기: {X_train.shape})...")
    detector.train(X_train)
    
    print(f"🎉 모델 학습 완료! 저장 경로: {MODEL_SAVE_PATH}")

if __name__ == "__main__":
    run_training()