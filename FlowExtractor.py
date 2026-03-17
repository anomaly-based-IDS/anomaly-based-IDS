from collections import defaultdict
from datetime import datetime, timedelta
import json

class FlowExtractor: # CICFlowMeter를 사용하면 더 정확한 플로우 특징 추출가능, 이후 라이브 환경을 고려한다면 자체 구현이 필요할듯
    def __init__(self, flow_timeout_seconds=30):
        self.flows = {} # Key: src_ip, dst_ip, src_port, dst_port, protocol; Value: flow data
        self.flow_timeout = flow_timeout_seconds
        self.lock = threading.Lock()

    def update_flow(self, packet_info): # 패킷을 분석하기 용이한 플로우 데이터로 업데이트
        flow_key = (
            packet_info['src_ip'],
            packet_info['dst_ip'],
            packet_info.get('src_port', 0),
            packet_info.get('dst_port', 0),
            packet_info['protocol']
        )

        with self.lock:
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    'src_ip': packet_info['src_ip'],
                    'dst_ip': packet_info['dst_ip'],
                    'src_port': packet_info.get('src_port', 0),
                    'dst_port': packet_info.get('dst_port', 0),
                    'protocol': packet_info['protocol'],
                    'packets': 0,
                    'bytes': 0,
                    'start_time': packet_info['timestamp'],
                    'end_time': packet_info['timestamp']
                }

            flow = self.flows[flow_key]
            flow['packets'] += 1
            flow['bytes'] += packet_info['length']
            flow['end_time'] = packet_info['timestamp']

            if 'flags' in packet_info:
                flow['flags'].add(packet_info['flags'])

    def get_expired_flows(self): # 타임아웃된 플로우를 특징 벡터로 변환하여 반환
        current_time = datetime.now()
        expired = []

        with self.lock:
            for flow_key, flow_data in list(self.flows.items()):
                end_time = datetime.fromisoformat(flow_data['end_time'])
                if (current_time - end_time).total_seconds() > self.flow_timeout:
                    start = datetime.fromisoformat(flow_data['start_time'])
                    duration = (end_time - start).total_seconds()

                    feature_dict = {
                        'src_ip': flow_data['src_ip'],
                        'dst_ip': flow_data['dst_ip'],
                        'src_port': flow_data['src_port'],
                        'dst_port': flow_data['dst_port'],
                        'protocol': flow_data['protocol'],
                        'total_packets': flow_data['packets'],
                        'total_bytes': flow_data['bytes'],
                        'duration_sec': max(duration, 1e-6),
                        'packet_per_sec': flow_data['packets'] / max(duration, 1e-6),
                        'bytes_per_packet': flow_data['bytes'] / flow_data['packets'] if flow_data['packets'] > 0 else 0,
                    }
                    expired.append((flow_key, feature_dict))
                    del self.flows[flow_key]
        return expired