"""
ground_truth.py
---------------
평가용 정답(ground truth) 라벨 규칙.

flow/패킷이 규칙의 IP 쌍(양방향) 사이에서 오가고, 출발/목적 포트 중 하나가
규칙의 포트에 속하면 해당 공격으로 라벨링한다. 나머지는 정상(BENIGN).

FlowKey는 방향별로 flow를 나누므로(요청/응답이 별개 flow) 양방향을 모두 공격으로 본다.

CIC-IDS2017 Tuesday (2017-07-04):
  - FTP-Patator : 172.16.0.1 → 192.168.10.50:21  (현지 09:20~10:20)
  - SSH-Patator : 172.16.0.1 → 192.168.10.50:22  (현지 14:00~15:00)
  공격자 205.174.165.73 은 방화벽 NAT 때문에 내부 캡처에서 172.16.0.1 로 보인다.
"""

import json
from dataclasses import asdict, dataclass, field
from typing import Optional

BENIGN = "BENIGN"


@dataclass
class AttackRule:
    name: str
    ips: tuple[str, str]           # 양방향
    ports: tuple[int, ...] = ()    # 비어 있으면 IP 쌍의 모든 트래픽
    start: Optional[float] = None  # 선택: epoch 시간 범위 (이 범위 밖이면 매칭 안 함)
    end:   Optional[float] = None

    def matches(self, src_ip, dst_ip, src_port, dst_port, ts: Optional[float] = None) -> bool:
        a, b = self.ips
        if not ((src_ip == a and dst_ip == b) or (src_ip == b and dst_ip == a)):
            return False
        if self.ports and src_port not in self.ports and dst_port not in self.ports:
            return False
        if ts is not None:
            if self.start is not None and ts < self.start:
                return False
            if self.end is not None and ts > self.end:
                return False
        return True


@dataclass
class GroundTruth:
    name: str
    rules: list[AttackRule] = field(default_factory=list)

    def label(self, src_ip, dst_ip, src_port, dst_port, ts: Optional[float] = None) -> str:
        for r in self.rules:
            if r.matches(src_ip, dst_ip, src_port, dst_port, ts):
                return r.name
        return BENIGN

    @property
    def attack_names(self) -> list[str]:
        return list(dict.fromkeys(r.name for r in self.rules))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "GroundTruth":
        rules = [
            AttackRule(
                name=r["name"], ips=tuple(r["ips"]), ports=tuple(r.get("ports", ())),
                start=r.get("start"), end=r.get("end"),
            )
            for r in d.get("rules", [])
        ]
        return cls(name=d.get("name", "custom"), rules=rules)

    @classmethod
    def load(cls, path: str) -> "GroundTruth":
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        # slice_pcap.py 매니페스트({"ground_truth": {...}})도 그대로 받는다
        return cls.from_dict(d.get("ground_truth", d))


ATTACKER = "172.16.0.1"
VICTIM = "192.168.10.50"

PROFILES: dict[str, GroundTruth] = {
    "tuesday": GroundTruth("CIC-IDS2017 Tuesday", [
        AttackRule("FTP-Patator", (ATTACKER, VICTIM), (21,)),
        AttackRule("SSH-Patator", (ATTACKER, VICTIM), (22,)),
    ]),
}


def get_profile(name: str) -> GroundTruth:
    try:
        return PROFILES[name]
    except KeyError:
        raise KeyError(f"알 수 없는 프로파일 '{name}' (가능: {', '.join(PROFILES)})") from None
