"""
evaluate.py / slice_pcap.py / pcap_raw.py 테스트

python -m pytest test/
"""

import json

import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter, rdpcap

from evaluate import run_evaluation
from flow import FEATURE_NAMES
from ground_truth import BENIGN, PROFILES, GroundTruth
from pcap_raw import iter_pcap, parse_five_tuple
from slice_pcap import slice_pcap

ATK, VIC = "172.16.0.1", "192.168.10.50"
PKT_COUNT = FEATURE_NAMES.index("pkt_count")
TUESDAY = PROFILES["tuesday"]


def tcp(src, dst, sport, dport, flags="PA", ts=0.0):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    p.time = ts
    return p


def write(path, pkts):
    pkts = sorted(pkts, key=lambda p: float(p.time))
    with PcapWriter(str(path), sync=True) as w:
        for p in pkts:
            w.write(p)
    return str(path)


class FakeDetector:
    """pkt_count >= min_pkts 이면 공격"""
    is_trained = True

    def __init__(self, min_pkts=4):
        self.min_pkts = min_pkts

    def predict_batch(self, X):
        bad = X[:, PKT_COUNT] >= self.min_pkts
        return np.where(bad, -1, 1), np.where(bad, -0.8, -0.4), X

    def get_confidence(self, scores):
        return np.where(np.asarray(scores) < -0.6, 0.5, 0.0)

    def get_anomaly_reason(self, row):
        return "pkt_count"


# ── ground_truth / pcap_raw ────────────────────────────────────────────

def test_ground_truth_bidirectional_and_ports():
    assert TUESDAY.label(ATK, VIC, 40000, 21) == "FTP-Patator"
    assert TUESDAY.label(VIC, ATK, 22, 40000) == "SSH-Patator"
    assert TUESDAY.label(ATK, VIC, 40000, 80) == BENIGN
    assert TUESDAY.label("10.0.0.1", VIC, 40000, 21) == BENIGN
    again = GroundTruth.from_dict(json.loads(json.dumps(TUESDAY.to_dict())))
    assert again.label(ATK, VIC, 1, 22) == "SSH-Patator"


def test_raw_parser_matches_scapy(tmp_path):
    pkts = [tcp("1.2.3.4", "5.6.7.8", 1111, 22, ts=1.5),
            Ether() / IP(src="9.9.9.9", dst="8.8.8.8") / UDP(sport=53, dport=5353)]
    pkts[1].time = 2.0
    path = write(tmp_path / "a.pcap", pkts)
    recs = [(r.ts, parse_five_tuple(r.data, rd.linktype)) for rd, r in iter_pcap(path)]
    assert recs[0][0] == 1.5
    assert recs[0][1].src_ip == "1.2.3.4" and recs[0][1].dst_port == 22 and recs[0][1].protocol == "TCP"
    assert recs[1][1].src_port == 53 and recs[1][1].protocol == "UDP"


# ── slice_pcap ─────────────────────────────────────────────────────────

def _long_capture(tmp_path):
    """0~1000초 배경 트래픽(1초 간격), FTP 공격 t=500~, SSH 공격 t=800~"""
    pkts = [tcp("10.0.0.1", "10.0.0.2", 5000, 443, ts=float(t)) for t in range(0, 1000)]
    pkts += [tcp(ATK, VIC, 40000 + i, 21, ts=500.5 + i) for i in range(100)]
    pkts += [tcp(ATK, VIC, 50000 + i, 22, ts=800.5 + i) for i in range(100)]
    return write(tmp_path / "big.pcap", pkts), len(pkts)


def test_slice_auto_segments(tmp_path):
    src, total = _long_capture(tmp_path)
    out = str(tmp_path / "slice.pcap")
    m = slice_pcap(src, out, TUESDAY, benign_sec=50, attack_sec=30, preroll=10, progress=False)

    assert m["missing_attacks"] == []
    assert m["attack_first_seen"]["FTP-Patator"]["ts"] == 500.5
    assert m["attack_first_seen"]["SSH-Patator"]["ts"] == 800.5
    ts = [float(p.time) for p in rdpcap(out)]
    assert ts == sorted(ts)
    windows = [(0, 50), (490.5, 530.5), (790.5, 830.5)]
    assert all(any(s <= t <= e for s, e in windows) for t in ts)
    # 각 구간의 배경 트래픽(preroll 포함)이 빠짐없이 들어감
    assert sum(1 for t in ts if 490.5 <= t < 500.5) == 10
    assert len(ts) == m["packets_written"] == sum(s["packets"] for s in m["segments"])
    assert m["packets_read"] < total                 # 마지막 구간 이후는 읽지 않음
    with open(out + ".json", encoding="utf-8") as f:
        assert GroundTruth.load(f.name).label(ATK, VIC, 1, 21) == "FTP-Patator"


def test_slice_manual_range(tmp_path):
    src, _ = _long_capture(tmp_path)
    out = str(tmp_path / "manual.pcap")
    m = slice_pcap(src, out, TUESDAY, ranges=[(100, 110)], progress=False)
    ts = [float(p.time) for p in rdpcap(out)]
    assert ts == [float(t) for t in range(100, 111)]
    assert m["params"]["mode"] == "manual"


# ── evaluate ───────────────────────────────────────────────────────────

def _eval_capture(tmp_path):
    """
    - FTP 공격 flow 10개 (각 5패킷) → 탐지됨
    - SSH 공격 flow 2개 (각 2패킷)  → 미탐 (pkt_count < 4)
    - 정상 짧은 flow 20개 (각 2패킷) → TN
    - 정상 긴 flow 1개 (6패킷)       → 오탐
    """
    pkts = []
    for i in range(10):
        t0 = 10 + i * 0.5
        pkts += [tcp(ATK, VIC, 40000 + i, 21, flags=f, ts=t0 + j * 0.01)
                 for j, f in enumerate(["S", "A", "PA", "PA", "FA"])]
    for i in range(2):
        pkts += [tcp(ATK, VIC, 50000 + i, 22, flags=f, ts=30 + i + j * 0.01)
                 for j, f in enumerate(["S", "FA"])]
    for i in range(20):
        pkts += [tcp("10.0.0.5", "10.0.0.9", 6000 + i, 80, flags=f, ts=1 + i * 3 + j * 0.01)
                 for j, f in enumerate(["S", "FA"])]
    pkts += [tcp("10.0.0.7", "10.0.0.8", 7000, 8080, flags=f, ts=200 + j * 0.01)
             for j, f in enumerate(["S", "A", "PA", "PA", "PA", "FA"])]
    return write(tmp_path / "eval.pcap", pkts)


def test_run_evaluation_metrics(tmp_path):
    path = _eval_capture(tmp_path)
    r = run_evaluation(FakeDetector(), path, TUESDAY, str(tmp_path / "out"),
                       pipeline_kwargs={"batch_size": 5, "zeek_bin": "__none__"})
    d, s = r["detection"], r["storage"]

    assert (d["tp"], d["fp"], d["fn"], d["tn"]) == (10, 1, 2, 20)
    assert d["recall"] == 10 / 12
    assert d["miss_rate"] == 2 / 12
    assert d["false_positive_rate"] == 1 / 21
    assert d["precision"] == 10 / 11
    assert d["per_attack"]["FTP-Patator"]["recall"] == 1.0
    assert d["per_attack"]["SSH-Patator"]["recall"] == 0.0

    assert s["events"] == 2                          # FTP 병합 이벤트 + 오탐 이벤트
    assert s["events_with_true_attack"] == 1
    assert s["events_false_alarm"] == 1
    assert s["duplicate_packets"] == 0
    assert s["saved_packets"] <= s["processed_packets"] == r["pipeline"]["total_packets"]
    # 정답 공격 패킷 FTP 50 + SSH 4. SSH(t=30)는 FTP 이벤트의 after 구간(~24.5s) 밖이라 저장 안 됨
    assert s["gt_attack_packets_total"] == 54
    assert s["gt_attack_packets_saved"] == 50
    assert s["gt_attack_packet_coverage"] == 50 / 54
    assert r["passed"] is True


def test_duplicate_detection_flags_failure(tmp_path):
    """같은 패킷이 두 이벤트에 저장되면 무결성 검사가 실패해야 한다"""
    import shutil
    path = _eval_capture(tmp_path)
    r = run_evaluation(FakeDetector(), path, TUESDAY, str(tmp_path / "out"),
                       pipeline_kwargs={"batch_size": 5, "zeek_bin": "__none__"})
    from evaluate import integrity_checks, storage_metrics

    d0 = r["output_dir"]
    import os
    dirs = sorted(os.path.join(d0, x) for x in os.listdir(d0))
    copy = dirs[0] + "_copy"
    shutil.copytree(dirs[0], copy)
    st = storage_metrics(dirs + [copy], TUESDAY, r["storage"]["processed_packets"],
                         r["storage"]["processed_bytes"], r["storage"]["gt_attack_packets_total"])
    assert st["duplicate_packets"] > 0
    checks = {c["name"]: c["passed"] for c in integrity_checks(st, r["pipeline"])}
    assert checks["no_duplicate_packets"] is False
