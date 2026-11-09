"""
Pipeline Test
ContextBuffer, AnomalyDetector.get_confidence, AttackCapturePipeline(배치 단위 병합) 테스트

python -m pytest test/
"""

import json
import os

import numpy as np
import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import PcapWriter, rdpcap

from AnomalyDetector import AnomalyDetector
from flow import FEATURE_NAMES
from packet_buffer import ContextBuffer
from pipeline import AttackCapturePipeline

NO_ZEEK = "zeek-not-installed-for-tests"
PKT_COUNT = FEATURE_NAMES.index("pkt_count")


def pkt(src, dst, sport, dport=80, flags="PA", ts=0.0):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    p.time = ts
    return p


def write_pcap(path, packets):
    with PcapWriter(path, sync=True) as w:
        for p in packets:
            w.write(p)


class FakeDetector:
    """pkt_count >= min_pkts 인 flow를 공격으로 판정하는 테스트용 탐지기"""
    is_trained = True

    def __init__(self, min_pkts=3):
        self.min_pkts = min_pkts

    def predict_batch(self, X):
        anomalous = X[:, PKT_COUNT] >= self.min_pkts
        preds = np.where(anomalous, -1, 1)
        scores = np.where(anomalous, -0.8, -0.4)
        return preds, scores, X

    def get_confidence(self, scores):
        return np.where(np.asarray(scores) < -0.6, 0.5, 0.0)

    def get_anomaly_reason(self, row):
        return "pkt_count"


# ── ContextBuffer ──────────────────────────────────────────────────────

class TestContextBuffer:

    def _filled(self):
        buf = ContextBuffer(before_sec=5, after_sec=5, max_duration=1000)
        pkts = {
            "early":  pkt("1.1.1.1", "9.9.9.9", 1, ts=1.0),    # 구간 밖 (이전)
            "before": pkt("1.1.1.1", "9.9.9.9", 2, ts=8.0),
            "atk":    pkt("1.1.1.1", "9.9.9.9", 3, ts=10.0),
            "other":  pkt("5.5.5.5", "6.6.6.6", 4, ts=11.0),   # 무관한 IP
            "second": pkt("2.2.2.2", "9.9.9.9", 5, ts=12.0),   # 두 번째 공격 IP
            "after":  pkt("9.9.9.9", "1.1.1.1", 6, ts=14.0),
            "late":   pkt("1.1.1.1", "9.9.9.9", 7, ts=30.0),   # 구간 밖 (이후)
        }
        for p in pkts.values():
            buf.add(p, timestamp=float(p.time))
        return buf, pkts

    def test_time_window_and_ip_filter(self):
        buf, p = self._filled()
        ctx = buf.get_context("1.1.1.1", "9.9.9.9", attack_start=10.0, attack_end=10.0)
        assert ctx == [p["before"], p["atk"], p["second"], p["after"]]

    def test_ips_set_and_exclude(self):
        buf, p = self._filled()
        ctx = buf.get_context(
            ips={"2.2.2.2", "5.5.5.5"}, attack_start=10.0, attack_end=12.0,
            exclude={id(p["second"])},
        )
        assert ctx == [p["other"]]

    def test_missing_times_return_empty(self):
        buf, _ = self._filled()
        assert buf.get_context("1.1.1.1", "9.9.9.9", None, None) == []

    def test_max_duration_evicts_old(self):
        buf = ContextBuffer(max_duration=10)
        buf.add(pkt("1.1.1.1", "2.2.2.2", 1), timestamp=0.0)
        buf.add(pkt("1.1.1.1", "2.2.2.2", 2), timestamp=20.0)
        assert len(buf._timeline) == 1


# ── AnomalyDetector.get_confidence ─────────────────────────────────────

@pytest.fixture(scope="module")
def detector():
    rng = np.random.default_rng(0)
    d = AnomalyDetector(contamination=0.05)
    d.train(rng.normal(size=(2000, len(FEATURE_NAMES))))
    return d


class TestConfidence:

    def test_range_and_monotonic(self, detector):
        rng = np.random.default_rng(1)
        X = np.vstack([rng.normal(size=(200, len(FEATURE_NAMES))),
                       rng.normal(loc=8, size=(20, len(FEATURE_NAMES)))])
        preds, scores, _ = detector.predict_batch(X)
        conf = detector.get_confidence(scores)

        assert np.all((conf >= 0) & (conf <= 1))
        assert np.all(conf[preds == 1] == 0)          # 정상 판정은 0
        assert np.all(conf[preds == -1] > 0)          # 이상 판정은 0보다 큼
        order = np.argsort(scores)                    # 점수가 낮을수록(더 이상할수록)
        assert np.all(np.diff(conf[order]) <= 1e-12)  # confidence 는 커야 함

    def test_outliers_more_confident(self, detector):
        rng = np.random.default_rng(2)
        _, s_out, _ = detector.predict_batch(rng.normal(loc=8, size=(20, len(FEATURE_NAMES))))
        _, s_mid, _ = detector.predict_batch(rng.normal(loc=3, size=(20, len(FEATURE_NAMES))))
        assert detector.get_confidence(s_out).mean() > detector.get_confidence(s_mid).mean()


# ── AttackCapturePipeline ──────────────────────────────────────────────

def _read_meta(save_dir):
    with open(os.path.join(save_dir, "metadata.json"), encoding="utf-8") as f:
        return json.load(f)


class TestPipeline:

    def _scenario_pcap(self, tmp_path):
        """
        t=5    정상 1패킷 flow     (1.1.1.1 → 9.9.9.9)         ← before 컨텍스트
        t=10~12 공격 flow A1 3패킷 (1.1.1.1 → 9.9.9.9, FIN)
        t=13~15 공격 flow A2 3패킷 (2.2.2.2 → 9.9.9.9, FIN)
        t=20   정상 1패킷 flow     (9.9.9.9 → 2.2.2.2)         ← after 컨텍스트
        t=100  무관한 트래픽       (7.7.7.7 → 8.8.8.8)
        """
        pkts = [pkt("1.1.1.1", "9.9.9.9", 3000, flags="FA", ts=5.0)]
        pkts += [pkt("1.1.1.1", "9.9.9.9", 1000, flags=f, ts=10.0 + i)
                 for i, f in enumerate(["S", "PA", "FA"])]
        pkts += [pkt("2.2.2.2", "9.9.9.9", 2000, flags=f, ts=13.0 + i)
                 for i, f in enumerate(["S", "PA", "FA"])]
        pkts += [pkt("9.9.9.9", "2.2.2.2", 80, dport=2001, flags="FA", ts=20.0)]
        pkts += [pkt("7.7.7.7", "8.8.8.8", 4000, flags="FA", ts=100.0)]
        path = str(tmp_path / "scenario.pcap")
        write_pcap(path, pkts)
        return path

    def _pipeline(self, tmp_path, batch_size, detector=None):
        return AttackCapturePipeline(
            detector=detector or FakeDetector(),
            output_dir=str(tmp_path / "out"),
            batch_size=batch_size,
            context_before_sec=10.0,
            context_after_sec=10.0,
            zeek_bin=NO_ZEEK,
        )

    def test_batch_merge_saves_once_with_after_context(self, tmp_path):
        path = self._scenario_pcap(tmp_path)
        pipe = self._pipeline(tmp_path, batch_size=3)   # [정상, A1, A2] 가 한 배치
        result = pipe.run_pcap(path)

        assert result["total_flows"] == 5
        assert result["attack_count"] == 2
        assert result["saved_events"] == 1               # 두 공격이 하나로 병합
        assert result["saved_attack_packets"] == 6
        # before(t=5) + after(t=20). after 패킷은 배치 처리(t=15) 이후에 도착했지만 포함돼야 함
        assert result["saved_context_packets"] == 2

        save_dir = result["saved_dirs"][0]
        meta = _read_meta(save_dir)
        assert meta["attack_flow"]["merged_count"] == 2
        assert len(meta["attack_flow"]["merged_flows"]) == 2
        assert meta["capture"]["total_packets"] == 8
        assert len(rdpcap(os.path.join(save_dir, "capture.pcap"))) == 8
        assert 0.0 <= meta["detection"]["confidence"] <= 1.0

    def test_overlapping_batches_merged(self, tmp_path):
        # [정상, A1], [A2, ...] 로 배치가 나뉘어도 컨텍스트 구간이 겹치면 하나로 저장
        path = self._scenario_pcap(tmp_path)
        result = self._pipeline(tmp_path, batch_size=2).run_pcap(path)
        assert result["attack_count"] == 2
        assert result["saved_events"] == 1
        assert result["saved_attack_packets"] == 6
        assert result["saved_context_packets"] == 2

    def test_separate_windows_never_store_packet_twice(self, tmp_path):
        # 병합을 막으면(max_window_sec 작게) 이벤트가 2개가 되지만, 어떤 패킷도 두 번 저장되지 않아야 함
        path = self._scenario_pcap(tmp_path)
        pipe = self._pipeline(tmp_path, batch_size=2)
        pipe.window_manager.max_window_sec = 1.0
        result = pipe.run_pcap(path)

        assert result["saved_events"] == 2
        assert result["saved_attack_packets"] == 6
        stored = []
        for d in result["saved_dirs"]:
            stored += [(float(p.time), bytes(p)) for p in rdpcap(os.path.join(d, "capture.pcap"))]
        assert len(stored) == len(set(stored))
        assert len(stored) == result["saved_attack_packets"] + result["saved_context_packets"]
        assert len(stored) <= result["total_packets"]

    def test_same_five_tuple_flows_in_one_batch(self, tmp_path):
        # 같은 5-tuple로 FIN 패킷이 3번 → flow 인스턴스 3개. 예전에는 두 번째 flush가 비어 크래시가 났음
        path = str(tmp_path / "dup.pcap")
        write_pcap(path, [pkt("1.1.1.1", "9.9.9.9", 1000, flags="FA", ts=float(i)) for i in range(3)])
        pipe = self._pipeline(tmp_path, batch_size=100, detector=FakeDetector(min_pkts=1))

        result = pipe.run_pcap(path)

        assert result["attack_count"] == 3
        assert result["saved_attack_packets"] == 3
        assert pipe.buffer.active_flow_count() == 0

    def test_stats_and_threshold(self, tmp_path):
        path = self._scenario_pcap(tmp_path)
        pipe = self._pipeline(tmp_path, batch_size=3)
        pipe.confidence_threshold = 0.9                  # FakeDetector confidence(0.5) 보다 높음
        result = pipe.run_pcap(path)

        assert result["attack_count"] == 0
        assert result["saved_events"] == 0
        s = pipe.stats()
        assert s["active_flows"] == 0
        assert s["total_added"] == s["total_flushed"] == 9

    def test_untrained_detector_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            AttackCapturePipeline(detector=AnomalyDetector(), output_dir=str(tmp_path))
