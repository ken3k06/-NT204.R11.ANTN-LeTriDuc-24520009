from __future__ import annotations

from typing import Optional

from src.errors import DecodeError, MalformedPacketError
from src.models.event import AppProtocol


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ")
HTTP_PORTS = {80, 8080, 8000}
DNS_PORTS = {53}
SMTP_PORTS = {25, 465, 587}
SMTP_COMMANDS = ("HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA", "QUIT")


def parse_application(payload: bytes, transport: str, src_port: int | None, dst_port: int | None) -> Optional[dict]:
    if not payload:
        return None

    app = detect_application(payload, transport, src_port, dst_port)
    if app == AppProtocol.HTTP:
        return _parse_http(payload)
    if app == AppProtocol.DNS:
        return _parse_dns(payload, transport)
    if app == AppProtocol.SMTP:
        return _parse_smtp(payload)
    return None


def detect_application(payload: bytes, transport: str, src_port: int | None, dst_port: int | None) -> str:
    ports = {p for p in (src_port, dst_port) if p is not None}
    upper = payload[:20].upper()

    if payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/"):
        return AppProtocol.HTTP
    if upper.startswith(tuple(cmd.encode() for cmd in SMTP_COMMANDS)) or _looks_like_smtp_response(payload):
        return AppProtocol.SMTP
    if ports & HTTP_PORTS:
        return AppProtocol.HTTP
    if ports & SMTP_PORTS:
        return AppProtocol.SMTP
    if transport == "UDP" and ports & DNS_PORTS:
        return AppProtocol.DNS
    if transport == "TCP" and ports & DNS_PORTS:
        return AppProtocol.DNS
    return AppProtocol.UNKNOWN


def _parse_http(payload: bytes) -> dict:
    text = _decode_text(payload)
    header_text, _, body = text.partition("\r\n\r\n")
    lines = header_text.split("\r\n")
    if not lines or not lines[0]:
        raise MalformedPacketError("empty http payload")

    first = lines[0]
    headers = _parse_headers(lines[1:])
    data = {
        "type": "response" if first.startswith("HTTP/") else "request",
        "headers": headers,
        "body_len": len(body.encode("latin1")),
    }

    parts = first.split(" ", 2)
    if data["type"] == "request":
        data["method"] = parts[0]
        data["path"] = parts[1] if len(parts) > 1 else ""
        data["version"] = parts[2] if len(parts) > 2 else ""
    else:
        data["version"] = parts[0]
        data["status_code"] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        data["reason"] = parts[2] if len(parts) > 2 else ""

    return {"app_protocol": AppProtocol.HTTP, "app_data": data}


def _parse_dns(payload: bytes, transport: str) -> dict:
    try:
        import dns.message
        import dns.rdatatype
    except ImportError as e:
        raise DecodeError(f"dnspython missing: {e}") from e

    wire = payload
    if transport == "TCP" and len(payload) >= 2:
        dns_len = int.from_bytes(payload[:2], "big")
        if dns_len <= len(payload) - 2:
            wire = payload[2:2 + dns_len]

    try:
        msg = dns.message.from_wire(wire)
    except Exception as e:
        raise DecodeError(f"dns decode error: {e}") from e

    questions = []
    for q in msg.question:
        questions.append({
            "name": str(q.name),
            "type": dns.rdatatype.to_text(q.rdtype),
        })

    answers = []
    for rrset in msg.answer:
        for item in rrset:
            answers.append({
                "name": str(rrset.name),
                "type": dns.rdatatype.to_text(rrset.rdtype),
                "data": item.to_text(),
            })

    return {
        "app_protocol": AppProtocol.DNS,
        "app_data": {
            "id": msg.id,
            "qr": "response" if msg.flags & 0x8000 else "query",
            "questions": questions,
            "answers": answers,
        },
    }


def _parse_smtp(payload: bytes) -> dict:
    text = _decode_text(payload).strip()
    first = text.splitlines()[0] if text else ""
    data = {"line": first}

    if len(first) >= 3 and first[:3].isdigit():
        data["type"] = "response"
        data["status_code"] = int(first[:3])
        data["message"] = first[4:] if len(first) > 4 else ""
    else:
        data["type"] = "command"
        if " " in first:
            cmd, arg = first.split(" ", 1)
        else:
            cmd, arg = first, ""
        data["command"] = cmd.upper()
        data["argument"] = arg

    return {"app_protocol": AppProtocol.SMTP, "app_data": data}


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers = {}
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def _decode_text(payload: bytes) -> str:
    try:
        return payload.decode("latin1")
    except UnicodeDecodeError as e:
        raise DecodeError(f"decode error: {e}") from e


def _looks_like_smtp_response(payload: bytes) -> bool:
    return len(payload) >= 4 and payload[:3].isdigit() and payload[3:4] in (b" ", b"-")
