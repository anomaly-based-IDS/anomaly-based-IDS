"""
Sprint 1 Test
pcap_reader, csv_reader, packet_buffer, attack_writer 단위 테스트

python -m pytest test/sprint1_test.py
"""

import json
import os
import time

import numpy as np
import pandas as pd
import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import PcapWriter, rdpcap

from flow import FlowKey, FlowRecord, FEATURE_NAMES
from packet_buffer import PacketBuffer
from pcap_reader import PcapFlowReader, PacketEvent, FlowEvent, _FlowAccumulator
from attack_writer import AttackPacketWriter


@pytest.fixture
def tmp_dir(tmp_path):
    return str(tmp_path)

def make_tcp_packet(src="192.168.1.1", dst="10.0.0.2", sport=1234, dport=80, flags="PA", ts=None):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    pkt.time = ts if ts is not None else time.time()
    return pkt

def make_udp_packet(src="192.168.1.1", dst="10.0.0.2", sport=5000, dport=53, ts=None):
    pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    pkt.time = ts if ts is not None else time.time()
    return pkt

def write_test_pcap(path: str, packets: list) -> None:
    with PcapWriter(path, sync=True) as w:
        for pkt in packets:
            w.write(pkt)

def make_test_csv(path: str, rows: list[dict]) -> None:
    columns = [
        "Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Min", "Flow IAT Max",
        "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Fwd Packet Length Min", "Fwd Packet Length Max",
        "SYN Flag Count", "FIN Flag Count", "RST Flag Count",
        "PSH Flag Count", "ACK Flag Count",
        "Source IP", "Destination IP", "Source Port", "Destination Port",
        "Protocol", "Label",
    ]
    df = pd.DataFrame(rows, columns=columns)
    df.to_csv(path, index=False)

def default_csv_row(label="BENIGN", **kwargs) -> dict:
    row = {
        "Flow Duration": 1000000, "Total Fwd Packets": 10,
        "Total Length of Fwd Packets": 500,
        "Flow IAT Mean": 100.0, "Flow IAT Std": 10.0,
        "Flow IAT Min": 50.0,   "Flow IAT Max": 200.0,
        "Fwd Packet Length Mean": 50.0, "Fwd Packet Length Std": 5.0,
        "Fwd Packet Length Min": 40.0,  "Fwd Packet Length Max": 60.0,
        "SYN Flag Count": 1, "FIN Flag Count": 1,
        "RST Flag Count": 0, "PSH Flag Count": 2, "ACK Flag Count": 8,
        "Source IP": "192.168.1.1", "Destination IP": "10.0.0.2",
        "Source Port": 1234, "Destination Port": 80,
        "Protocol": 6, "Label": label,
    }
    row.update(kwargs)
    return row

# PacketBuffer 단위 테스트
class TestPacketBuffer:

    # add + peek 기본 동작 테스트
    def test_add_and_Peek(self):
        buf = PacketBuffer(evict_interval=0)
        pkt = make_tcp_packet()
        buf.add("flow-1", pkt)

        result = buf.peek("flow-1")
        assert len(result) == 1
        assert result[0] is pkt

    # 서로 다른 flow_id로 패킷 추가 시 독립적으로 저장되는지 테스트
    def test_add_multiple_flows(self):
        buf = PacketBuffer(evict_interval=0)
        for i in range(3):
            buf.add("flow-A", make_tcp_packet())
        for i in range(5):
            buf.add("flow-B", make_tcp_packet())

        assert len(buf.peek("flow-A")) == 3
        assert len(buf.peek("flow-B")) == 5
        assert buf.active_flow_count() == 2

    # flush 시 해당 flow_id의 패킷이 반환되고 버퍼에서 제거되는지 테스트
    def test_flush_returns_packet_and_removes_flow(self):
        buf = PacketBuffer(evict_interval=0)
        pkts = [make_tcp_packet() for _ in range(4)]
        for p in pkts:
            buf.add("flow-X", p)

        result = buf.flush("flow-X")

        assert len(result) == 4
        assert result == pkts
        assert buf.active_flow_count() == 0
        assert buf.peek("flow-X") == []

    # 존재하지 않은 flow_id로 peek/flush 시 빈 리스트 반환되는지 테스트
    def test_flush_nonexistent_flow_returns_empty(self):
        buf = PacketBuffer(evict_interval=0)
        result = buf.flush("no-such-flow")

        assert result == []

    # max packets 초과시 오래된 패킷이 제거되는지 테스트
    def test_maxlen_slides_old_packets(self):
        buf = PacketBuffer(max_packets_per_flow=3, evict_interval=0)
        pkts = [make_tcp_packet() for _ in range(5)]
        for p in pkts:
            buf.add("flow-1", p)

        result = buf.peek("flow-1")
        
        assert len(result) == 3
        assert result == pkts[-3:]

    # TTL 초과시 오래된 패킷이 제거되는지 테스트
    def test_evict_expired_removes_old_packets(self):
        buf = PacketBuffer(ttl_seconds=0.05, evict_interval=0)
        buf.add("flow-old", make_tcp_packet(), timestamp=time.time() - 1.0)
        buf.add("flow-new", make_tcp_packet(), timestamp=time.time())

        removed = buf.evict_expired()

        assert removed == 1
        assert buf.peek("flow-old") == []
        assert len(buf.peek("flow-new")) == 1

    # 버퍼 상태가 올바르게 반환되는지 테스트
    def test_stats_returns_correct_counts(self):
        buf = PacketBuffer(evict_interval=0)
        assert buf.stats.active_flows == 0

        for i in range(3):
            buf.add("flow-A", make_tcp_packet())
        for i in range(5):
            buf.add("flow-B", make_tcp_packet())

        s = buf.stats.active_flows
        assert s == 2
        assert len(buf.peek("flow-A")) == 3
        assert len(buf.peek("flow-B")) == 5
    
# AttackPacketWirter 단위 테스트
class TestAttackPacketWriter:

    # write() 호출 시 pcap과 json 파일이 생성되는지 테스트
    def test_write_creates_pcap_and_json(self, tmp_dir):
        writer = AttackPacketWriter(output_dir=tmp_dir)
        pkts = [make_tcp_packet(ts=time.time() + i * 0.1) for i in range(3)]
        
        save_dir = writer.write("192.168.1.1.:80-10.0.0.2:54321-TCP", pkts, anomaly_score=-0.5)

        assert save_dir is not None
        assert os.path.exists(os.path.join(save_dir, "attack.pcap"))
        assert os.path.exists(os.path.join(save_dir, "metadata.json"))

    # 저장된 pcap 파일의 패킷이 원본과 동일한지 테스트
    def test_pcap_contains_correct_packets(self, tmp_dir):
        writer = AttackPacketWriter(output_dir=tmp_dir)
        pkts = [make_tcp_packet() for _ in range(5)]

        save_dir = writer.write("test-flow", pkts)
        pcap_path = os.path.join(save_dir, "attack.pcap")
        loaded = rdpcap(pcap_path)

        assert len(loaded) == 5

    # 메타데이터 Json에 필수 필드가 모두 포함되어 생성되었는지 테스트
    def test_json_meatadata_fields(self, tmp_dir):
        writer = AttackPacketWriter(output_dir=tmp_dir)
        pkts = [make_tcp_packet(src="1.2.3.4", dst="5.6.7.8", sport=9999, dport=80, ts=time.time() + i * 0.05) for i in range(3)]

        save_dir = writer.write("1.2.3.4:9999-5.6.7.8:80-TCP", pkts, anomaly_score=-0.42)
        json_path = os.path.join(save_dir, "metadata.json")

        with open(json_path) as f:
            meta = json.load(f)

        assert meta["packet_count"]     == 3
        assert meta["src_ip"]           == "1.2.3.4"
        assert meta["dst_ip"]           == "5.6.7.8"
        assert meta["src_port"]         == 9999
        assert meta["dst_port"]         == 80
        assert meta["protocol"]         == "TCP"
        assert meta["anomaly_score"]    == pytest.approx(-0.42)
        assert meta["total_bytes"]      > 0
        assert meta["duration_seconds"] >= 0.0


# PcapFlowReader 단위 테스트
class TestPcapFlowReader:

    def _make_pcap(self, tmp_dir, packets, filename="test.pcap"):
        path = os.path.join(tmp_dir, filename)
        write_test_pcap(path, packets)
        return path
    
     # 각 패킷에 대해 PacketEvent가 발생하는지 테스트
    def test_packet_events(self, tmp_dir):
        pkts = [make_tcp_packet(ts=float(i)) for i in range(1, 4)]
        path = self._make_pcap(tmp_dir, pkts)

        events = list(PcapFlowReader(idle_timeout=999).stream(path))
        packet_events = [e for e in events if isinstance(e, PacketEvent)]

        assert len(packet_events) == 3

    # FIN 수신 시 FlowEvent가 발생하는지 테스트
    def test_flow_event_emitted_on_fin(self, tmp_dir):
        pkts = [
            make_tcp_packet(flags="S",  ts=1.0),
            make_tcp_packet(flags="PA", ts=2.0),
            make_tcp_packet(flags="FA", ts=3.0),
        ]
        path   = self._make_pcap(tmp_dir, pkts)
        events = list(PcapFlowReader(idle_timeout=999).stream(path))
 
        flow_events = [e for e in events if isinstance(e, FlowEvent)]
        assert len(flow_events) == 1

    # RST 수신 시 FlowEvent가 발생하는지 테스트
    def test_Flow_event_emitted_on_rst(self, tmp_dir):
        pkts = [
            make_tcp_packet(flags="S",  ts=1.0),
            make_tcp_packet(flags="R",  ts=2.0),  # RST
        ]
        path   = self._make_pcap(tmp_dir, pkts)
        events = list(PcapFlowReader(idle_timeout=999).stream(path))
 
        flow_events = [e for e in events if isinstance(e, FlowEvent)]
        assert len(flow_events) == 1

    # FIN/RST 없이 idle timeout 초과 시 FlowEvent가 발생하는지 테스트
    def test_incomplete_flow_flushed_at_eof(self, tmp_dir):
        pkts = [make_tcp_packet(flags="PA", ts=float(i)) for i in range(3)]
        path = self._make_pcap(tmp_dir, pkts)

        events = list(PcapFlowReader(idle_timeout=999).stream(path))
        flow_events = [e for e in events if isinstance(e, FlowEvent)]

        assert len(flow_events) == 1

    # idel timeout 초과 시 FlowEvent가 발생하는지 테스트
    def test_idle_timeout_triggers_flow_event(self, tmp_dir):
        pkts = [
            make_tcp_packet(src="1.1.1.1", dport=80, flags="PA", ts=1.0),
            make_tcp_packet(src="2.2.2.2", dport=443, flags="PA", ts=200.0),
        ]
        path = self._make_pcap(tmp_dir, pkts)
        events = list(PcapFlowReader(idle_timeout=60.0).stream(path))

        flow_events = [e for e in events if isinstance(e, FlowEvent)]

        assert len(flow_events) == 2


# Buffer -> Writer 통합 테스트
class TestBufferToWriterIntegration:

    # buffer에서 flush된 패킷이 writer에 의해 저장되는지 테스트
    def test_flushed_packets_saved_by_writer(self, tmp_dir):
        buf    = PacketBuffer(evict_interval=0)
        writer = AttackPacketWriter(output_dir=tmp_dir)
 
        flow_id = "192.168.1.1:80-10.0.0.2:54321-TCP"
        pkts    = [make_tcp_packet(ts=float(i)) for i in range(5)]
        for p in pkts:
            buf.add(flow_id, p)
 
        flushed  = buf.flush(flow_id)
        save_dir = writer.write(flow_id, flushed, anomaly_score=-0.35)
 
        assert save_dir is not None
        assert len(rdpcap(os.path.join(save_dir, "attack.pcap"))) == 5
        assert buf.active_flow_count() == 0

    # pcap_reader의 PacketEvent.flow_id와 FlowEvent.flow_id이 일치하는지 테스트
    def test_pcap_reader_provides_correct_flow_id_for_buffer(self, tmp_dir):
        pcap_path = os.path.join(tmp_dir, "test.pcap")
        pkts      = [make_tcp_packet(flags="FA", ts=float(i)) for i in range(3)]
        write_test_pcap(pcap_path, pkts)
 
        buf    = PacketBuffer(evict_interval=0)
        reader = PcapFlowReader(idle_timeout=999)
        events = list(reader.stream(pcap_path))
 
        for e in events:
            if isinstance(e, PacketEvent):
                buf.add(e.flow_id, e.packet)
 
        flow_events = [e for e in events if isinstance(e, FlowEvent)]
        assert len(flow_events) == 3

        flushed = buf.flush(flow_events[0].flow_id)
        assert len(flushed) == 3

# _FlowAccumulator 단위 테스트
class TestFlowAccumulator:
 
    def _make_key(self):
        return FlowKey("1.1.1.1", "2.2.2.2", 1234, 80, "TCP")

    # 패킷이 하나인 경우 feature 값이 올바르게 계산되는지 테스트
    def test_feature_values_single_packet(self):
        acc = _FlowAccumulator(self._make_key())
        acc.add(make_tcp_packet(flags="PA", ts=1.0))
        event = acc.to_flow_event()
 
        feat = dict(zip(FEATURE_NAMES, event.features))
        assert feat["duration"] == 0.0
        assert feat["pkt_count"] == 1.0
        assert feat["iat_mean"] == 0.0
 
    # 패킷이 여러 개인 경우 duration, pkt_count, iat_mean 등이 올바르게 계산되는지 테스트
    def test_feature_values_multiple_packets(self):
        acc  = _FlowAccumulator(self._make_key())
        for i in range(5):
            acc.add(make_tcp_packet(flags="PA", ts=float(i)))
        event = acc.to_flow_event()
 
        feat = dict(zip(FEATURE_NAMES, event.features))
        assert feat["duration"]  == pytest.approx(4.0)
        assert feat["pkt_count"] == 5.0
 
    # TCP 플래그 카운트가 올바르게 계산되는지 테스트
    def test_tcp_flag_counts(self):
        acc = _FlowAccumulator(self._make_key())
        acc.add(make_tcp_packet(flags="S",  ts=1.0))   # SYN
        acc.add(make_tcp_packet(flags="PA", ts=2.0))   # PSH+ACK
        acc.add(make_tcp_packet(flags="FA", ts=3.0))   # FIN+ACK
 
        event = acc.to_flow_event()
        feat  = dict(zip(FEATURE_NAMES, event.features))
 
        assert feat["tcp_flag_syn"] == 1.0
        assert feat["tcp_flag_fin"] == 1.0
        assert feat["tcp_flag_psh"] == 1.0
        assert feat["tcp_flag_ack"] == 2.0