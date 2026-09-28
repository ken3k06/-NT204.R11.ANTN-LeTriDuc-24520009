"""Pipeline: raw bytes → NormalizedEvent."""
from __future__ import annotations

from src.errors import MalformedPacketError, ParseError
from src.models.event import (
    NormalizedEvent,
    make_malformed_event,
    make_unknown_event,
)
from src.parsers.application import parse_application
from src.parsers.network import parse_ipv4
from src.parsers.transport import parse_transport


def process(raw: bytes, timestamp: float, packet_id: int) -> NormalizedEvent:
    """Xử lý 1 packet qua pipeline. Không bao giờ raise."""
    try:
        ip = parse_ipv4(raw)
    except MalformedPacketError as e:
        return make_malformed_event(packet_id, timestamp, str(e), raw=raw)
    except ParseError as e:
        return make_malformed_event(packet_id, timestamp, str(e), raw=raw)
    except Exception as e:
        return make_malformed_event(packet_id, timestamp, f"unexpected: {e}", raw=raw)

    if ip is None:
        return make_unknown_event(packet_id, timestamp, raw=raw)

    event = NormalizedEvent(
        packet_id=packet_id,
        timestamp=timestamp,
        src_ip=ip["src_ip"],
        dst_ip=ip["dst_ip"],
        ip_proto=ip["ip_proto"],
        ttl=ip["ttl"],
        ip_len=ip["total_len"],
    )

    try:
        tp = parse_transport(ip["payload"], ip["ip_proto"])
    except MalformedPacketError as e:
        event.error = str(e)
        return event
    except ParseError as e:
        event.error = str(e)
        return event
    except Exception as e:
        event.error = f"unexpected: {e}"
        return event

    if tp is None:
        # Không phải TCP/UDP (ví dụ ICMP) → giữ nguyên, payload_len = IP payload
        event.payload_len = len(ip["payload"])
        return event

    event.transport = tp["transport"]
    event.src_port = tp["src_port"]
    event.dst_port = tp["dst_port"]
    event.payload_len = len(tp["payload"])

    if tp["transport"] == "TCP":
        event.tcp_seq = tp["tcp_seq"]
        event.tcp_ack = tp["tcp_ack"]
        event.tcp_flags = tp["tcp_flags"]
        event.tcp_window = tp["tcp_window"]
    else:
        event.udp_len = tp["udp_len"]

    try:
        app = parse_application(
            tp["payload"],
            event.transport,
            event.src_port,
            event.dst_port,
        )
    except MalformedPacketError as e:
        event.error = str(e)
        return event
    except ParseError as e:
        event.error = str(e)
        return event
    except Exception as e:
        event.error = f"unexpected: {e}"
        return event

    if app is not None:
        event.app_protocol = app["app_protocol"]
        event.app_data = app["app_data"]

    return event
