from __future__ import annotations

from typing import Iterator

from scapy.all import IP, rdpcap, sniff


def iter_pcap(path: str) -> Iterator[tuple[bytes, float]]:
    packets = rdpcap(path)
    for pkt in packets:
        raw = _get_ip_bytes(pkt)
        if raw is not None:
            yield raw, float(pkt.time)


def iter_live(interface: str, count: int = 0) -> Iterator[tuple[bytes, float]]:
    packets = sniff(iface=interface, count=count)
    for pkt in packets:
        raw = _get_ip_bytes(pkt)
        if raw is not None:
            yield raw, float(pkt.time)


def _get_ip_bytes(pkt) -> bytes | None:
    if IP in pkt:
        return bytes(pkt[IP])
    return None
