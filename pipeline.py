"""
pcap/csv 로 읽어옴
-> reader에서 flowRecord 형식으로 변환
-> flowRecord에서 feature를 isolation forest 모델로 전달
-> .predict(feature)로 공격탐지해서 flush로 탐지된 id 전달
-> attack writer가 기록

"""

import logging
from typing import Optional

import numpy as np

from pcap_reader import PcapFlowReader, PacketEvent, FlowEvent
from packet_buffer import PacketBuffer
from attack_writer import AttackPacketWriter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

class AnomalyModel(Protocol):
    # Isolation Forest 모델 인터페이스
    
    def predict(self, features: np.ndarray) -> bool:
        ...
    
    def score(self, features: np.ndarray) -> float:
        ...

class AttackCapturePipeline:
    """
    Parameters:
    - model: AnomalyModel 인터페이스 구현 객체
    - max_packets: 버퍼 flow당 최대 패킷 수
    - ttl_seconds: 버퍼 flow ttl
    - output_dir: 공격 저장 경로
    """

    def __init__(
        self,
        model: AnomalyModel,
        max_packets: int = 1000,
        ttl_seconds: float = 120.0,
        output_dir: str = "./attack_pcaps",
    ):
        self.model = model
        self.buffer = PacketBuffer(max_packets, ttl_seconds)
        self.writer = AttackPacketWriter(output_dir)
        self._reader = PcapFlowReader()

    # pcap streaming
    def run_pcap(self, pcap_path: str) -> None:
        logger.info("=== pcap 스트리밍 시작: %s ===", pcap_path)
        pkt_count = flow_count = attack_count = 0

        for event in self._reader.stream(pcap_path):
            # 패킷을 버퍼에 추가
            if isinstance(event, PacketEvent):
                self.buffer.add(event.flow_id, event.packet)
                pkt_count += 1
            # flow 완성 -> 모델 예측 -> 공격 판단 -> 공격 저장
            elif isinstance(event, FlowEvent):
                flow_count += 1
                if self._judge(event):
                    attack_count += 1
        
        logger.info(
            "=== pcap 스트리밍 완료: %s | 총 패킷=%d | 완성 flow=%d | 탐지된 공격=%d ===",
            pkt_count, flow_count, attack_count
        )
                

    def stats(self):
        s = self.buffer.stats()
        return {
            "active_flows": s.active_flows,
            "total_added": s.total_added,
            "total_flushed": s.total_flushed,
            "total evicted": s.total_evicted,
        }
    

    def _judge(self, event: FlowEvent) -> bool:
        is_attack = self.model.predict(event.features)
        if is_attack:
            score = self.model.score(event.features)
            packets = self.buffer.flush(event.flow_id)
            self.writer.write(
                flow_id=event.flow_id,
                packets=packets,
                anomaly_score=score,
            )
            logger.info(
                "공격 탐지: %s | score=%.4f | flushed_pkts=%d",
                event.flow_id, score, len(packets)
            )
        return is_attack
    

# 동작
if __name__ == "__main__":
    import time
    from sklearn.ensemble import IsolationForest
    from scapy.layers.inet import IP, TCP   
    from flow import FEATURE_NAMES, FlowKey
    from pcap_reader import FlowEvent

    # 더미 모델
    class IForestModel:
        def __init__(self, threshold: float = 0.0):
            self.threshold = threshold
            self._iforest = IsolationForest(contamination=0.1, random_state=42)
            self._iforest.fit(np.random.rand(100, len(FEATURE_NAMES)))  # 랜덤 데이터로 학습

        def predict(self, features: np.ndarray) -> bool:
            return self.score(features) < self.threshold
        
        def score(self, features: np.ndarray) -> float:
            return float(self._iforest.score_samples(features.reshape(1, -1))[0])
        
    # 파이프라인 생성
    pipeline = AttackCapturePipeline(
        model=IForestModel(threshold=0.0),
        output_dir="./attack_pcaps_test",
    )

