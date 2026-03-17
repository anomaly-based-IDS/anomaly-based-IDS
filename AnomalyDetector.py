# use Isolation Forest for anomaly detection
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

class AnomalyDetector:
    def __init__(self, contamination=0.05, model_path=None):
        self.model = IsolationForest(contamination = contamination, random_state=42, n_jobs=-1)
        self.scaler = StandardScaler()
        self.if_trained = False
        self.model_path = model_path
        self.feature_names = [
            'total_packets', 'total_bytes', 'duration_sec', 'packets_per_sec', 'bytes_per_packet', 'src_port', 'dst_port'
        ]

        def extract_features(self, flow_dict):
            features = []
            for fname in self.feature_names:
                if fname in flow_dict:
                    features.append((flow_dict[fname] / 65535))
                else:
                    features.append(flow_dict[fname])
            return np.array(features).reshape(1, -1)
        
        def train(self, training_flows): # 정의한 플로우들로 모델 학습 / Args: training_flows: list of flow feature dicts
            feature_matrix = []
            for flow in training_flows:
                feature_vector = self.extract_features(flow)
                feature_matrix.append(feature_vector.flatten())
            
            feature_matrix = np.array(feature_matrix)
            self.scaler.fit(feature_matrix)
            scaled_features = self.scaler.transform(feature_matrix)
            self.model.fit(scaled_features)
            self.if_trained = True

            if self.model_path:
                joblib.dump((self.model, self.scaler), self.model_path)

        def predict_anomaly(self, flow_dict): # 플로우가 이상인지 판정 Returns: anomaly_score & confidence
            if not self.is_trained:
                raise Exception("Model not trained yet.")
            
            X = self.extract_features(flow_dict)
            X_scaled = self.scaler.transform(X)

            anomaly_score = self.model.score_samples(X_scaled)[0]
            prediction = self.model.predict(X_scaled)[0] # -1: anomaly, 1: normal
            
            confidence = 1 / (1 + np.exp(-anomaly_score)) # Sigmoid

            return prediction, confidence
        
        def save_model(self, path=None):    # 학습 모델 저장
            path = path if path else self.model_path
            if path:
                joblib.dump({'model': self.model, 'scaler': self.scaler}, path)
                print(f"Model saved to {path}")
        
        def load_model(self, path=None):   # 모델 로드
            path = path or self.model_path
            if path:
                data = joblib.load(path)
                self.model = data['model']
                self.scaler = data['scaler']
                self.is_trained = True
                print(f"Model loaded from {path}")