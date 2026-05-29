import numpy as np
import joblib
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

# [수정 포인트 1] flow.py에서 정의된 고정 피처 리스트를 가져와 사용합니다.
from flow import FEATURE_NAMES

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnomalyDetector:    
    def __init__(self, contamination=0.01, model_path=None):        
        self.model = IsolationForest(
            max_samples=1024,
            contamination=contamination, 
            random_state=42, 
            n_jobs=-1
        )        
        self.scaler = RobustScaler()        
        self.is_trained = False        
        self.model_path = model_path        
        
        # 외부 주입 대신, flow.py의 공통 FEATURE_NAMES를 바로 연결합니다.
        self.feature_names = FEATURE_NAMES 

    # [수정 포인트 2] extract_features() 메서드 삭제
    # -> PcapFlowReader가 생성하는 FlowRecord는 이미 features 배열(np.ndarray)을 
    #    갖고 있으므로, 딕셔너리 파싱 로직은 더 이상 필요 없습니다.
                        
    def train(self, training_matrix): 
        """전처리된 2D 행렬(np.ndarray)을 받아 학습 수행"""
        logger.info(f"🚀 모델 학습 시작: 데이터 차원 {training_matrix.shape}")
        
        # 1. 데이터 정규화 학습 및 변환
        scaled_features = self.scaler.fit_transform(training_matrix)
        
        # 2. Isolation Forest 학습
        self.model.fit(scaled_features)            
        self.is_trained = True
        
        # 3. 모델 저장
        if self.model_path:                
            self.save_model(self.model_path)
        
        logger.info("✅ 모델 학습 및 파일 저장 완료.")
                    
    # [수정 포인트 3] 마이크로 배치 전용 탐지 메서드 신설
    def predict_batch(self, feature_matrix): 
        """
        다수의 FlowRecord.features(1D Array)가 모여 만들어진 
        2D 행렬(feature_matrix)을 한 번에 판정
        """
        if not self.is_trained:                
            raise Exception("모델이 학습되지 않았습니다.")                        
        
        # 배치 데이터 전체를 한 번에 스케일링
        X_scaled = self.scaler.transform(feature_matrix)
        
        # 배치 데이터 전체를 한 번에 판정 및 점수 계산
        predictions = self.model.predict(X_scaled) 
        scores = self.model.score_samples(X_scaled)
        
        return predictions, scores, X_scaled

    def get_anomaly_reason(self, scaled_feature_row):
        """특정 패킷이 공격으로 판정됐을 때, 가장 튀는 피처 이름 반환"""
        reason_idx = np.argmax(np.abs(scaled_feature_row))
        return self.feature_names[reason_idx]

    def save_model(self, path=None):    
        path = path or self.model_path            
        if path:                
            joblib.dump({
                'model': self.model, 
                'scaler': self.scaler, 
                'feature_names': self.feature_names,
                'is_trained': self.is_trained
            }, path)                
            logger.info(f"💾 모델 저장 성공: {path}")                
                    
    def load_model(self, path=None):   
        path = path or self.model_path            
        if path:                
            data = joblib.load(path)                
            self.model = data['model']                
            self.scaler = data['scaler']                
            self.feature_names = data.get('feature_names', FEATURE_NAMES)
            self.is_trained = data.get('is_trained', True)
            logger.info(f"📂 모델 로드 성공: {path}")