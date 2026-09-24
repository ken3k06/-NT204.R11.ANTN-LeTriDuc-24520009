# Chuẩn hóa output

from __future__ import annotations 

import json 
from dataclasses import asdict, dataclass, field 
from typing import Any, Optional 

class Transport: 
    TCP = "TCP"
    UDP = "UDP"
    UNKNOWN = "UNKNOWN"

class AppProtocol:
    HTTP = "HTTP"
    DNS = "DNS"
    SMTP = "SMTP"
    UNKNOWN = "UNKNOWN"

class ErrorHandling:
    MALFORMED = "malformed"
    TRUNCATED = "truncated"
    UNSUPPORTED = "unsupported"
    DECODE_ERROR = "decode_error"

@dataclass

class NormalizedEvent: 
    # metadata
    packet_id: int 
    timestamp: float 

    # type hint optional[str] để tránh các packet lỗi
    # 3 tầng chính 
    # - Network 
    # - Transport
    # - Application


    # Network 
    src_ip: Optional[str] = None 
    dst_ip: Optional[str] = None 
    ip_proto: Optional[str] = None # https://www.iana.org/assignments/protocol-numbers 
    ttl: Optional[int] = None 
    ip_len: Optional[int] = None 

    # Transport 
    transport: str  = Transport.UNKNOWN 
    src_port: Optional[int] = None
    dst_port: Optional[int] = None 

    # TCP 
    tcp_seq: Optional[int] = None 
    tcp_ack: Optional[int] = None 
    tcp_flags: Optional[dict[str,int]] = None 
    tcp_window: Optional[int] = None 

    # UDP 
    udp_len : Optional[int] = None 

    # Application 
    app_protocol: str = AppProtocol.UNKNOWN 
    app_data: Optional[dict[str,Any]] = None 
    payload_len: int = 0 
    error: Optional[str] = None 
    raw_hex: Optional[str] = field(default=None, repr = False)

    def to_dict(self) -> dict[str, Any]:
        # chuyển về dict cho json dump
        return asdict(self)
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True)
    # Helper 

    @property 
    def is_error(self) -> bool:
        return self.error is not None 
    @property 
    def is_unknown_protocol(self) -> bool:
        return self.app_protocol == AppProtocol.UNKNOWN 

    def __str__(self) -> str: 
        return (
            f"#{self.packet_id:<4}"
            f"{self.src_ip or '-':15} -> {self.dst_ip or '-':15}"
            f"{self.transport:<4}"
            f"{self.app_protocol:<6}"
            f"payload={self.payload_len}B"
            + (f" ERR={self.error}" if self.error else "") 
        )

def make_malformed_event(
    packet_id : int,
    timestamp: float, 
    reason: str = ErrorHandling.MALFORMED,
    raw: bytes | None = None,
) -> NormalizedEvent: 
    return NormalizedEvent(
        packet_id = packet_id,
        timestamp = timestamp,
        error = reason, 
        raw_hex = raw.hex() if raw else None,
    )
def make_unknown_event(
    packet_id: int,
    timestamp: float,
    raw: bytes | None = None,
) -> NormalizedEvent:
    """Tạo event cho packet không hỗ trợ (vd: ARP, IPv6)."""
    return NormalizedEvent(
        packet_id=packet_id,
        timestamp=timestamp,
        error=ErrorHandling.UNSUPPORTED,
        raw_hex=raw.hex() if raw else None,
    )