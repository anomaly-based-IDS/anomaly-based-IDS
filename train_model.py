import os
import time
import numpy as np
from AnomalyDetector import AnomalyDetector
from pcap_reader import PcapFlowReader

# 월요일 정상 트래픽 PCAP 파일 경로를 맞춰주세요.
TRAIN_PCAP_FILE = "Monday-WorkingHours.pcap" 
MODEL_SAVE_PATH = "anomaly_ids_model.pkl"

def run_training():
    if not os.path.exists(TRAIN_PCAP_FILE):
        print(f"❌ 에러: {TRAIN_PCAP_FILE} 파일이 없습니다.")
        return

    print(f"📅 데이터 로딩 및 16개 특징 추출 시작: {TRAIN_PCAP_FILE}...")
    start_time = time.time()
    
    # 1. PcapFlowReader를 이용해 PCAP에서 직접 플로우 추출
    reader = PcapFlowReader(idle_timeout=120.0)
    training_data = []
    
    total_flows = 0
    MAX_FLOWS = 10000 # ★ 1만 개 플로우만 수집하고 강제 종료!
    
    for record in reader.read(TRAIN_PCAP_FILE):
        training_data.append(record.features)
        total_flows += 1
        
        if total_flows % 10000 == 0:
            print(f"🔄 플로우 추출 중... ({total_flows:,}개 완료)")
            
        # ★ 50만 개가 모이면 무식한 10GB 읽기를 멈추고 루프 탈출
        if total_flows >= MAX_FLOWS:
            print(f"\n🚨 파일이 너무 커서 {MAX_FLOWS:,}개 플로우만 추출하고 조기 종료합니다!")
            break

    if not training_data:
        print("❌ 에러: 추출된 데이터가 없습니다.")
        return

    # 2. 추출된 데이터를 2D 행렬 (N, 16) 로 변환
    X_train = np.array(training_data, dtype='float32')
    print(f"✅ 데이터 추출 완료! 학습 데이터 차원: {X_train.shape}")
    print(f"소요 시간: {time.time() - start_time:.2f}초\n")

    # 3. 모델 생성 및 학습
    # 월요일 데이터는 거의 정상이므로 contamination은 낮게(0.01) 설정
    detector = AnomalyDetector(contamination=0.01, model_path=MODEL_SAVE_PATH)
    
    detector.train(X_train)

if __name__ == "__main__":
    run_training()