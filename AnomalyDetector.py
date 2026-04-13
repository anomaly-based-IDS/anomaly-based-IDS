import numpy as np
import joblib
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

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
        self.feature_names = [] # 학습 시점에 외부에서 주입받음

    def extract_features(self, flow_dict):            
        """실시간 탐지 시 딕셔너리 데이터를 어레이로 변환"""
        features = []        
        for fname in self.feature_names:                
            # 데이터셋의 컬럼명과 입력 딕셔너리의 키를 매칭
            val = flow_dict.get(fname, 0.0)
            features.append(val)
        
        return np.array(features).reshape(1, -1)                
						
    def train(self, training_matrix): 
        """전처리된 행렬 데이터를 받아 학습 수행"""
        logger.info("모델 학습 및 스케일링 시작...")
        
        # 1. 데이터 정규화 학습 및 변환
        scaled_features = self.scaler.fit_transform(training_matrix)
        
        # 2. Isolation Forest 학습
        self.model.fit(scaled_features)            
        self.is_trained = True
        
        # 3. 모델 저장
        if self.model_path:                
            self.save_model(self.model_path)
        
        logger.info("모델 학습 및 파일 저장 완료.")
		            
    def predict_anomaly(self, flow_dict): 
        """플로우 데이터에 대해 이상 여부 판정"""
        if not self.is_trained:                
            raise Exception("모델이 학습되지 않았습니다.")                        
        
        X = self.extract_features(flow_dict)            
        X_scaled = self.scaler.transform(X)
        
        prediction = self.model.predict(X_scaled)[0] 
        raw_score = self.model.score_samples(X_scaled)[0]
        confidence = 1 / (1 + np.exp(-raw_score)) 
        
        # 이상 탐지 시 가장 큰 영향을 준 특징 추출
        reason = self.feature_names[np.argmax(np.abs(X_scaled))] if prediction == -1 else "Normal"
        
        return prediction, confidence, reason

    def save_model(self, path=None):    
        path = path or self.model_path            
        if path:                
            # 모델, 스케일러, 특징 이름을 함께 저장해야 나중에 똑같이 불러올 수 있음
            joblib.dump({
                'model': self.model, 
                'scaler': self.scaler, 
                'feature_names': self.feature_names,
                'is_trained': self.is_trained
            }, path)                
            logger.info(f"모델 저장 성공: {path}")                
				    
    def load_model(self, path=None):   
        path = path or self.model_path            
        if path:                
            data = joblib.load(path)                
            self.model = data['model']                
            self.scaler = data['scaler']                
            self.feature_names = data['feature_names']
            self.is_trained = data.get('is_trained', True)
            logger.info(f"모델 로드 성공: {path}")