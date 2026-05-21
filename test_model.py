import os
import time
import numpy as np

from AnomalyDetector import AnomalyDetector
from pcap_reader import PcapFlowReader
from packet_buffer import PacketBuffer
from attack_writer import AttackPacketWriter

# 경로 설정 (실제 테스트할 pcap 파일 경로로 변경하세요)
PCAP_FILE = "forTest_normal.pcap"
MODEL_PATH = "anomaly_ids_model.pkl"
OUTPUT_DIR = "./attack_pcaps"

def process_batch(detector, buffer, writer, batch_records):
    """마이크로 배치를 모델에 넣고 결과를 처리하는 핵심 함수"""
    # 1. 1D 배열들을 묶어 모델 입력용 2D 행렬(Matrix)로 변환
    feature_matrix = np.array([r.features for r in batch_records])
    
    # 2. 모델 일괄 추론 (Micro-Batching)
    predictions, scores, x_scaled = detector.predict_batch(feature_matrix)
    
    batch_anomaly_count = 0
    
    # 3. 판정 결과에 따른 버퍼 제어(Action)
    for i, pred in enumerate(predictions):
        flow_id = batch_records[i].flow_id
        
        # [핵심] 정상이든 공격이든 판정이 끝났으므로 버퍼에서 패킷을 빼냅니다 (메모리 확보)
        pkts = buffer.flush(flow_id)
        
        if pred == -1: # 1차적으로 모델이 이상하다고 판정했을 때
            # 먼저 확신도(Confidence)를 계산
            confidence = float(1 / (1 + np.exp(-scores[i])))
            
            # ★ 60% 이상 확신할 때만 '진짜 탐지'로 인정하고 카운트 & 저장!
            if confidence >= 0.3: 
                batch_anomaly_count += 1  # 여기서만 카운트 증가!
                reason = detector.get_anomaly_reason(x_scaled[i])
                
                extra_info = {
                    "reason": reason,
                    "confidence": confidence
                }
                
                # AttackPacketWriter를 통해 pcap 파일과 json 메타데이터 저장
                writer.write(
                    flow_id=flow_id, 
                    packets=pkts, 
                    anomaly_score=float(scores[i]), 
                    extra=extra_info
                )
            
    return batch_anomaly_count

def run_pipeline():
    if not os.path.exists(MODEL_PATH):
        print(f"에러: {MODEL_PATH} 가 없습니다. 모델을 먼저 학습하세요.")
        return
        
    print(f"실시간 패킷 분석 파이프라인 시작: {PCAP_FILE}")
    start_time = time.time()

    # 1. 파이프라인 컴포넌트 초기화
    detector = AnomalyDetector(model_path=MODEL_PATH)
    detector.load_model()
    
    reader = PcapFlowReader(idle_timeout=120.0)
    buffer = PacketBuffer(max_packets_per_flow=5000, evict_interval=0) 
    writer = AttackPacketWriter(output_dir=OUTPUT_DIR)
    
    # 마이크로 배치 설정
    BATCH_SIZE = 100 
    batch_records = []
    
    total_flows = 0
    anomaly_count = 0
    skip_count = 0
    # ★ 테스트 시간 단축을 위한 제한 설정
    MAX_TEST_FLOWS = 5000
    
    # 2. PCAP 스트리밍 및 마이크로 배치 루프
    for record in reader.read(PCAP_FILE):
        # A. 패킷을 버퍼에 저장 (팀원의 역할 시뮬레이션)
        for pkt in record.packets:
            buffer.add(record.flow_id, pkt)
            
        # B. 추출된 플로우 피처를 대기열에 추가
        batch_records.append(record)
        
        # C. 윈도우 크기(BATCH_SIZE)에 도달하면 일괄 판정
        if len(batch_records) >= BATCH_SIZE:
            anomaly_count += process_batch(detector, buffer, writer, batch_records)
            total_flows += len(batch_records)
            batch_records.clear() # 배치 비우기
            
            if total_flows % 1000 == 0:
                print(f"처리 진행 중... (현재 {total_flows}개 플로우 검사, 탐지: {anomaly_count}개)")

            # ★ 5만 개 검사 완료 시 무한 루프 탈출!
            if total_flows >= MAX_TEST_FLOWS:
                print(f"\n테스트 시간 단축을 위해 {MAX_TEST_FLOWS:,}개 검사 후 조기 종료합니다!")
                break 

    # 3. 루프 종료 후 남은 자투리 데이터 처리
    if batch_records:
        anomaly_count += process_batch(detector, buffer, writer, batch_records)
        total_flows += len(batch_records)
        batch_records.clear()
        
    elapsed = time.time() - start_time
    print("\n" + "="*50)
    print("[실시간 탐지 파이프라인(마이크로 배치) 종료]")
    print(f"▶ 총 처리 플로우 : {total_flows:,}건")
    print(f"▶ 탐지된 공격    : {anomaly_count:,}건 (탐지율: {(anomaly_count/total_flows)*100:.2f}%)")
    print(f"▶ 소요 시간      : {elapsed:.2f}초")
    print(f"▶ 패킷 저장 경로 : {OUTPUT_DIR}")
    print("="*50)

if __name__ == "__main__":
    run_pipeline()