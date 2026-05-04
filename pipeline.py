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
from csv_reader import CsvFlowReader
from packet_buffer import PacketBuffer
from attack_writer import AttackPacketWriter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    # handler 추가
)
logger = logging.getLogger(__name__)

class AttackDetectionPipeline:
    """
    Parameters:
    - model: sklearn IsolationForest
    - max_packets: 버퍼 flow당 최대 패킷 수
    - ttl_seconds: 버퍼 flow ttl
    - output_dir: 공격 저장 경로
    - anomaly_threshold: 이상치 판단 임계값
    """

    def __init__(
        self,
        model,
        max_packets: int = 1000,
        ttl_seconds: float = 120.0,
        output_dir: str = "./attack_pcaps",
        anomaly_threshold: float = 0.0
    ):
        self.model = model
        self.threshold = anomaly_threshold
        self.buffer = PacketBuffer(max_packets, ttl_seconds)
        self.writer = AttackPacketWriter(output_dir)
        self._reader = PcapFlowReader()
        self._csv_reader = CsvFlowReader()

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
                # 미완
        
        logger.info(
            "=== pcap 스트리밍 완료: %s | 총 패킷=%d | 완성 flow=%d | 탐지된 공격=%d ===",
            pkt_count, flow_count, attack_count
        )
                
    # csv
    def run_csv(self, csv_path: str) -> None:
        logger.info("=== csv 스트리밍 시작: %s ===", csv_path)
        total = tp = fp = 0

        for record in self._csv_reader.stream(csv_path):
            total += 1
            score = self._score(record.features)
            predicted = score < self.threshold
            is_attack = record.label not in (None, "Benign")

            if predicted:
                (tp if is_attack else fp).__class__ # 카운터증가
                if is_attack: tp += 1
                else: fp += 1
                logger.info(
                    "공격 탐지: flow_id=%s | score=%.4f | label=%s",
                    record.flow_id, score, record.label 
                )

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        logger.info(
            "=== csv 스트리밍 완료: 총 flow=%d | TP=%d | FP=%d | Precision=%.2f%% ===",
            total, tp, fp, precision * 100
        )