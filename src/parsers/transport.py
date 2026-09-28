from __future__ import annotations
from typing import Optional

import struct
from src.errors import MalformedPacketError

# https://www.iana.org/assignments/protocol-numbers 
IPPROTO_TCP = 6 
IPPROTO_UDP = 17


TCP_MIN_HEADER = 20
# https://networklessons.com/ip-routing/tcp-header
# Đối với TCP thì có ít nhất là 20 bytes cho phần header

UDP_HEADER = 8
# https://networklessons.com/ip-routing/user-datagram-protocol-udp-packet-header 
# Đối với UDP thì header luôn có độ dài cố định là 8 bytesheader

def parse_transport(raw: bytes, ip_proto: int) -> Optional[dict]:
    if ip_proto == IPPROTO_TCP:
        return _parse_tcp(raw)
    elif ip_proto == IPPROTO_UDP:
        return _parse_udp(raw)
    return None 

# https://binarycon.com/tools/tcp-flags-calculator/ 
def _decode_tcp_flags(flags_byte: int) -> dict[str, int]:
    """Tách 8 bit TCP flags thành dict."""
    return {
        "FIN": (flags_byte >> 0) & 1, # Bit cuối cùng
        "SYN": (flags_byte >> 1) & 1, # Bit cuối cùng thứ hai 
        "RST": (flags_byte >> 2) & 1, # ... tương tự 
        "PSH": (flags_byte >> 3) & 1,
        "ACK": (flags_byte >> 4) & 1,
        "URG": (flags_byte >> 5) & 1,
        "ECE": (flags_byte >> 6) & 1,
        "CWR": (flags_byte >> 7) & 1,
    }


def _parse_tcp(data: bytes) -> dict: 
    if len(data) < TCP_MIN_HEADER:
        raise MalformedPacketError(
            f"truncated tcp header ({len(data)} < {TCP_MIN_HEADER})"
        )
    (src_port, dst_port, seq, ack, offset_reserved, flags, window, 
     _checksum, _urgent, ) = struct.unpack("!HHIIBBHHH", data[:TCP_MIN_HEADER])
    # ! là chuẩn định dạng network byte order
    # B là 1 byte, H là 2 bytes, I là 4 bytes
    # ở đây src và dst 16 bit = 2 bytes, còn lại ta unpack tương tự dựa trên thông tin header
    data_offset = (offset_reserved >> 4) * 4
    if data_offset < TCP_MIN_HEADER or data_offset > len(data):
        raise MalformedPacketError(
            f"truncated tcp header ({data_offset} < {TCP_MIN_HEADER} or {data_offset} > {len(data)})"
        )
    return {
        "transport": "TCP",
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_seq": seq, 
        "tcp_ack": ack, 
        "tcp_flags":  _decode_tcp_flags(flags),
        "tcp_window": window, 
        "payload" : data[data_offset:],

    }
def _parse_udp(data: bytes) -> dict: 
    if len(data) < UDP_HEADER:
        raise MalformedPacketError(
            f"truncated udp header ({len(data)} < {UDP_HEADER})"
        )
    src_port, dst_port, length, _checksum = struct.unpack("!HHHH", data[:UDP_HEADER])
    return {
        "transport": "UDP", 
        "src_port": src_port, 
        "dst_port": dst_port, 
        "udp_length": length, 
        "payload": data[UDP_HEADER:],   
    }