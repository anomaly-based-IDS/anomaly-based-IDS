"""

python pipeline.py
로 실행

"""

import logging
import numpy as np

from AnomalyDetector import AnomalyDetector
from pcap_reader import PcapFlowReader, PacketEvent, FlowEvent
from packet_buffer import PacketBuffer, ContextBuffer
from attack_writer import AttackPacketWriter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

class AttackCapturePipeline:

    def __init__(
        self,
        detector: AnomalyDetector,
        max_packets: int = 5000,
        ttl_seconds: float = 120.0,
        output_dir: str = "./attack_pcaps",
        batch_size: int = 100,
        confidence_threshold: float = 0.3,
        idle_timeout: float = 120.0,
        context_before_sec:    float = 10.0,
        context_after_sec:     float = 10.0,
        context_max_duration:  float = 300.0,

    ):
        
        self.detector = detector
        self.buffer = PacketBuffer(max_packets, ttl_seconds)
        self.context_buffer = ContextBuffer(
            before_sec = context_before_sec,
            after_sec= context_after_sec,
            max_duration = context_max_duration,
        )
        self.writer = AttackPacketWriter(output_dir, before_sec=context_before_sec, after_sec=context_after_sec)
        self._reader = PcapFlowReader(idle_timeout=idle_timeout)
        self.batch_size = batch_size
        self.confidence_threshold = confidence_threshold

    # pcap streaming
    def run_pcap(self, pcap_path: str, max_flows: int = 0) -> dict:
        logger.info("=== pcap 스트리밍 시작: %s ===", pcap_path)
        
        batch_queue: list[FlowEvent] = []
        total_flows = pkt_count = attack_count = 0

        for event in self._reader.stream(pcap_path):
            # 패킷을 버퍼에 추가
            if isinstance(event, PacketEvent):
                self.buffer.add(event.flow_id, event.packet)
                ts = None
                try:
                    ts = float(event.packet.time)
                except(AttributeError, TypeError):
                    pass
                self.context_buffer.add(event.packet, timestamp=ts)
                pkt_count += 1

            # flow 완성 -> 모델 예측 -> 공격 판단 -> 공격 저장
            elif isinstance(event, FlowEvent):
                batch_queue.append(event)

                if len(batch_queue) >= self.batch_size:
                    attack_count += self._process_batch(batch_queue)
                    total_flows += len(batch_queue)
                    batch_queue.clear()

                    if total_flows % 1000 == 0:
                        logger.info(
                            "진행 중... flow=%d | 공격=%d | 버퍼=%d flows",
                            total_flows, attack_count, self.buffer.active_flow_count()
                        )

                    if max_flows > 0 and total_flows >= max_flows:
                        logger.info("조기종료: %d flows 처리 완료", max_flows)
                        break

        # 나머지 배치 처리
        if batch_queue:
            attack_count += self._process_batch(batch_queue)
            total_flows += len(batch_queue)
            batch_queue.clear()

        result = {
            "total_flows": total_flows,
            "attack_count": attack_count,
            "total_packets": pkt_count,
        }
        logger.info(
            "=== pcap 스트리밍 완료 | 패킷=%d | flow=%d | 공격=%d (%.2f%%)===",
            pkt_count, total_flows, attack_count, (attack_count / total_flows * 100) if total_flows > 0 else 0.0,
        )
        return result
                

    def stats(self):
        s = self.buffer.stats()
        return {
            "active_flows": s.active_flows,
            "total_added": s.total_added,
            "total_flushed": s.total_flushed,
            "total_evicted": s.total_evicted,
        }
    
    # 내부 메서드

    def _process_batch(self, batch: list[FlowEvent]) -> int:
        feature_matrix = np.array([e.features for e in batch])
        predictions, scores, x_scaled = self.detector.predict_batch(feature_matrix)
        attack_count = 0

        for i, pred in enumerate(predictions):
            flow_id = batch[i].flow_id
            pkts = self.buffer.flush(flow_id)

            if pred == -1:
                confidence = float(1 / (1.0 / (1.0 + np.exp(-scores[i]))))
                
                if confidence >= self.confidence_threshold:
                    attack_count += 1
                    reason = self.detector.get_anomaly_reason(x_scaled[i])

                    # 공격 flow 시간 범위 계산
                    atk_time = []
                    for p in pkts:
                        try: atk_time.append(float(p.time))
                        except (AttributeError, TypeError):
                            pass
                    atk_start = min(atk_time) if atk_time else None
                    atk_end   = max(atk_time) if atk_time else None

                    # 전후 컨텍스트 패킷 조회
                    flow_key = batch[i].flow_key
                    ctx_pkts = self.context_buffer.get_context(
                        src_ip = flow_key.src_ip,
                        dst_ip = flow_key.dst_ip,
                        attack_start = atk_start,
                        attack_end = atk_end,
                    )

                    self.writer.write(
                        flow_id=flow_id,
                        attack_packets=pkts,
                        context_packets=ctx_pkts,
                        anomaly_score=float(scores[i]),
                        extra={"reason": reason, "confidence": confidence},
                    )

                    logger.info(
                        "[ATTACK] %s | score=%.4f | conf=%.2f | reason=%s | atk=%d ctx=%d pkts",
                        flow_id, scores[i], confidence, reason, len(pkts), len(ctx_pkts),
                    )

        return attack_count


if __name__ == "__main__":
    PCAP_FILE = "forTest.pcap"
    MODEL_PATH = "anomaly_ids_model.pkl"
    OUTPUT_DIR = "./attack_pcaps"

    detector = AnomalyDetector(model_path=MODEL_PATH)
    detector.load_model()

    pipeline = AttackCapturePipeline(
        detector=detector,
        max_packets=5000,
        ttl_seconds=120.0,
        output_dir=OUTPUT_DIR,
        batch_size=100,
        confidence_threshold=0.3,
        idle_timeout=120.0,
        context_before_sec    = 10.0,
        context_after_sec     = 10.0,  
        context_max_duration  = 300.0,
    )

    result = pipeline.run_pcap(PCAP_FILE, max_flows=5000)

    print("\n" + "=" * 50)
    print("[파이프라인 종료]")
    print(f"▶ 총 처리 플로우 : {result['total_flows']:,}건")
    if result['total_flows'] > 0:
        print(f"▶ 탐지된 공격    : {result['attack_count']:,}건 "
              f"(탐지율: {result['attack_count']/result['total_flows']*100:.2f}%)")
    else:
        print("▶ 처리된 flow 없음")
    print(f"▶ 총 패킷        : {result['total_packets']:,}개")
    print(f"▶ 저장 경로      : {OUTPUT_DIR}")
    print("=" * 50)
