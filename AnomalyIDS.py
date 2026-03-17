import threading
import time
from pathlib import Path
import AnomalyDetector
import FlowExtractor
import PacketCaptureEngine
from scapy.all import wrpcap, PcapWriter

class AnomalyIDS: # 메인 시스템 - 패킷 캡처, 플로우 추출, 이상 탐지 통합
    def __init__(self, interface=None, modal_path=None, anomaly_threshold=0.3, output_dir='alerts'):
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # 컴포넌트 초기화
        self.packet_engine = PacketCaptureEngine(interface=interface)
        self.flow_extractor = FlowExtractor(flow_timeout_seconds=30)
        self.anomaly_detector = AnomalyDetector(model_path=modal_path)

        # 이상 탐지 임계값 (낮을수록 민감)
        self.anomaly_threshold = anomaly_threshold

        # 위험 패킷 임시 저장
        self.pcap_buffer = []
        self.pcap_buffer_size = 50 # 최근 50개 패킷 저장(현재 임시값, 추후 조정 필요)

        # 로깅
        self.alerts = []
        self.lock = threading.Lock()
        
        # 스레드 제어
        self.processing_thread = None
        self.stop_event = threading.Event()

        # 모델 로드
        if modal_path:
            self.anomaly_detector.load_model(modal_path)

    def start(self):
        print("Starting Anomaly IDS")
        self.packet_engine.start_capture()

        self.processing_thread = threading.Thread(target=self._process_flows, daemon=False)
        self.processing_thread.start()
        print("IDS started successfully")

    def _process_flows(self):
        while not self.stop_event.is_set():
            try:
                # 패킷 큐에서 데이터 읽고
                while not self.packet_engine.packet_queue.empty():
                    try:
                        packet_info = self.packet_engine.packet_queue.get_nowait()
                        self.flow_extractor.update_flow(packet_info)

                        # 버퍼에 추가
                        with self.lock:
                            self.pcap_buffer.append(packet_info)
                            if len(self.pcap_buffer) > self.pcap_buffer_size:
                                self.pcap_buffer.pop(0)

                    except queue.Empty:
                        break

                # 타임아웃 플로우 분석
                expired_flows = self.flow_extractor.get_expired_flows() 
                for flow_key, feature_dict in expired_flows:
                    self._analyze_flow(flow_key, feature_dict)

                time.sleep(1)

            except Exception as e:
                print(f"Error in flow processing: {e}")

    def _analyze_flow(self, flow_key, feature_dict): # 개별 플로우 분석하고 이상 탐지
        if not self.anomaly_detector.if_trained:
            return
        
        prediction, confidence = self.anomaly_detector.predict_anomaly(feature_dict)

        if prediction == -1:
            alert = {
                # 플로우 정보
            }

            with self.lock:
                self.alerts.append(alert)
