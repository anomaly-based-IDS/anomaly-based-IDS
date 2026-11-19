"""
pcap_raw.py
-----------
scapy 없이 libpcap(.pcap) 파일을 빠르게 읽고 쓰는 최소 유틸리티.

수 GB 원본 pcap을 자르거나(slice_pcap.py), 저장된 결과 pcap을 검증할 때(evaluate.py)
scapy 디코딩 비용 없이 레코드 헤더 + IPv4/TCP/UDP 헤더만 파싱한다.

지원: libpcap (usec/nsec, little/big endian), linktype 1(Ethernet, VLAN 포함)·101(raw IP)
미지원: pcapng → `editcap -F pcap in.pcapng out.pcap` 로 변환 후 사용
"""

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
_PROTO_NAMES = {6: "TCP", 17: "UDP"}


@dataclass
class RawRecord:
    ts: float          # epoch seconds
    ts_raw: tuple      # (sec, frac) — 원본 헤더 값 (동일 패킷 식별용)
    orig_len: int
    data: bytes        # 캡처된 바이트 (caplen)


@dataclass(frozen=True)
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str      # "TCP" | "UDP" | "OTHER"


class PcapFormatError(ValueError):
    pass


class RawPcapReader:
    """pcap 레코드를 (헤더, 바이트) 단위로 순회한다."""

    def __init__(self, f: BinaryIO):
        self._f = f
        hdr = f.read(24)
        if len(hdr) < 24:
            raise PcapFormatError("pcap 전역 헤더가 없음 (빈 파일?)")
        magic = hdr[:4]
        if magic == PCAPNG_MAGIC:
            raise PcapFormatError(
                "pcapng 형식은 지원하지 않음 — `editcap -F pcap in.pcapng out.pcap` 로 변환하세요")
        if magic not in _MAGICS:
            raise PcapFormatError(f"알 수 없는 pcap magic: {magic.hex()}")
        self.endian, self.ts_unit = _MAGICS[magic]
        self.global_header = hdr
        _, _, _, _, self.snaplen, self.linktype = struct.unpack(self.endian + "HHiIII", hdr[4:])
        self._rec = struct.Struct(self.endian + "IIII")

    def __iter__(self) -> Iterator[RawRecord]:
        read, unpack, unit = self._f.read, self._rec.unpack, self.ts_unit
        while True:
            h = read(16)
            if len(h) < 16:
                return
            sec, frac, caplen, orig_len = unpack(h)
            data = read(caplen)
            if len(data) < caplen:
                return  # 잘린 마지막 레코드
            yield RawRecord(sec + frac * unit, (sec, frac), orig_len, data)

    def record_bytes(self, rec: RawRecord) -> bytes:
        """레코드를 같은 형식(엔디언/정밀도)의 pcap 레코드 바이트로 직렬화"""
        sec, frac = rec.ts_raw
        return self._rec.pack(sec, frac, len(rec.data), rec.orig_len) + rec.data


def iter_pcap(path: str) -> Iterator[tuple[RawPcapReader, RawRecord]]:
    with open(path, "rb") as f:
        reader = RawPcapReader(f)
        for rec in reader:
            yield reader, rec


def _ip4(b: bytes) -> str:
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


def ip_offset(data: bytes, linktype: int) -> Optional[int]:
    """IPv4 헤더 시작 위치. IPv4가 아니면 None"""
    if linktype == LINKTYPE_RAW:
        off = 0
    elif linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        etype = (data[12] << 8) | data[13]
        off = 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:   # VLAN / QinQ
            etype = (data[off + 2] << 8) | data[off + 3]
            off += 4
        if etype != 0x0800:
            return None
    else:
        return None
    if len(data) < off + 20 or (data[off] >> 4) != 4:
        return None
    return off


def parse_five_tuple(data: bytes, linktype: int) -> Optional[FiveTuple]:
    """IPv4 패킷의 5-tuple. flow.FlowKey.from_packet 과 같은 규칙(TCP/UDP 외엔 포트 0)"""
    off = ip_offset(data, linktype)
    if off is None:
        return None
    ihl = (data[off] & 0x0F) * 4
    proto = data[off + 9]
    src, dst = _ip4(data[off + 12:off + 16]), _ip4(data[off + 16:off + 20])
    name = _PROTO_NAMES.get(proto, "OTHER")
    sport = dport = 0
    frag_offset = ((data[off + 6] & 0x1F) << 8) | data[off + 7]
    l4 = off + ihl
    if name != "OTHER" and frag_offset == 0 and len(data) >= l4 + 4:
        sport = (data[l4] << 8) | data[l4 + 1]
        dport = (data[l4 + 2] << 8) | data[l4 + 3]
    return FiveTuple(src, dst, sport, dport, name)
