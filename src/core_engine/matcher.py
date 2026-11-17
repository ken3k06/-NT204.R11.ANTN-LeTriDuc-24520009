"""Module Rule Matching Engine: so khớp một rule với normalized event.

Các nhóm kiểm tra:
- Header: protocol, src/dst IP (any / IPv4 / CIDR), port (any / single / range), direction
- Flow/State: to_server, to_client, established, not_established
- Content: nocase, offset, depth, distance, within
- Packet/TCP: flags, dsize
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

from src.core_engine.rule_parser import TCP_FLAG_MAP, ContentOption, Rule


# Thứ tự các bit TCP flag được kiểm tra khi so khớp chính xác
TRACKED_FLAGS = ("F", "S", "R", "P", "A", "U", "E", "C")


@dataclass
class MatchResult:
    """Kết quả so khớp của một rule với một event."""
    matched: bool
    sid: int = 0
    reason: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)


def match_rule(rule: Rule, event: dict[str, Any]) -> MatchResult:
    """Trả về MATCH / NO_MATCH kèm thông tin cần thiết (sid, content, ...)."""
    result = match_header(rule, event)
    if not result.matched:
        return result

    check = match_flow(rule, event)
    if not check.matched:
        return check

    check = match_packet(rule, event)
    if not check.matched:
        return check

    check = match_contents(rule, event)
    if not check.matched:
        return check

    details = dict(check.details)
    details["direction"] = rule.direction
    details["protocol"] = rule.protocol
    result.details = details
    return result


def match_header(rule: Rule, event: dict[str, Any]) -> MatchResult:
    """So khớp protocol, IP, port và chiều của rule."""
    failed = lambda why: MatchResult(matched=False, sid=rule.sid, reason=f"header: {why}")

    protocol = str(event.get("transport", "")).lower()
    if protocol != rule.protocol:
        return failed(f"protocol mismatch ({protocol} != {rule.protocol})")

    src_ip = event.get("src_ip")
    dst_ip = event.get("dst_ip")
    src_port = event.get("src_port")
    dst_port = event.get("dst_port")

    forward = (
        _ip_matches(src_ip, rule.src_ip)
        and _port_matches(src_port, rule.src_port)
        and _ip_matches(dst_ip, rule.dst_ip)
        and _port_matches(dst_port, rule.dst_port)
    )

    if rule.direction == "->":
        if not forward:
            return failed("src/dst mismatch")
    elif rule.direction == "<>":
        backward = (
            _ip_matches(src_ip, rule.dst_ip)
            and _port_matches(src_port, rule.dst_port)
            and _ip_matches(dst_ip, rule.src_ip)
            and _port_matches(dst_port, rule.src_port)
        )
        if not forward and not backward:
            return failed("bidirectional endpoints mismatch")
    else:
        return failed(f"unsupported direction {rule.direction}")

    return MatchResult(matched=True, sid=rule.sid)


def match_flow(rule: Rule, event: dict[str, Any]) -> MatchResult:
    """So khớp flow keyword bằng flow context từ Flow Tracker.

    Quy ước: rule src là phía client, rule dst là phía server.
    """
    if not rule.flow:
        return MatchResult(matched=True, sid=rule.sid)

    flow = event.get("flow")
    if not flow:
        return MatchResult(matched=False, sid=rule.sid, reason="flow: no flow context")

    state = flow.get("state", "")
    is_forward = _packet_is_forward(rule, event, flow)

    for keyword in rule.flow:
        if keyword == "to_server" and not is_forward:
            return MatchResult(matched=False, sid=rule.sid, reason="flow: not to_server")
        if keyword == "to_client" and is_forward:
            return MatchResult(matched=False, sid=rule.sid, reason="flow: not to_client")
        if keyword == "established" and state != "ESTABLISHED":
            return MatchResult(matched=False, sid=rule.sid, reason=f"flow: state={state}")
        if keyword == "not_established" and state == "ESTABLISHED":
            return MatchResult(matched=False, sid=rule.sid, reason=f"flow: state={state}")

    details = {"flow_id": flow.get("flow_id"), "flow_state": state}
    return MatchResult(matched=True, sid=rule.sid, details=details)


def match_packet(rule: Rule, event: dict[str, Any]) -> MatchResult:
    """So khớp TCP flags và dsize."""
    if rule.flags:
        flags = event.get("tcp_flags") or {}
        if not _flags_match(rule.flags, flags):
            return MatchResult(matched=False, sid=rule.sid, reason="packet: flags mismatch")

    if rule.dsize is not None:
        size = event.get("dsize")
        if size is None:
            size = event.get("payload_len", 0)
        spec = rule.dsize
        if spec.min is not None and size < spec.min:
            return MatchResult(matched=False, sid=rule.sid, reason=f"packet: dsize={size} < {spec.min}")
        if spec.max is not None and size > spec.max:
            return MatchResult(matched=False, sid=rule.sid, reason=f"packet: dsize={size} > {spec.max}")

    return MatchResult(matched=True, sid=rule.sid)


def match_contents(rule: Rule, event: dict[str, Any]) -> MatchResult:
    """Tìm các content trong payload/application data đã normalize/decode.

    Mỗi content có thể có offset/depth (tuyệt đối) hoặc distance/within (tương đối
    theo content trước đó). Rule chỉ được coi là match nếu mọi content thỏa mãn
    trên cùng một buffer.
    """
    if not rule.contents:
        return MatchResult(matched=True, sid=rule.sid, details={"content": None})

    for name, buffer in _build_buffers(event):
        matches = _match_in_buffer(rule.contents, buffer)
        if matches is not None:
            details = {
                "content": rule.contents[0].text(),
                "contents": matches,
                "buffer": name,
            }
            return MatchResult(matched=True, sid=rule.sid, details=details)

    contents = [c.text() for c in rule.contents]
    return MatchResult(
        matched=False,
        sid=rule.sid,
        reason=f"content: not found ({', '.join(contents)})",
    )


# === Các hàm phụ trợ ===

def _ip_matches(value: Any, spec: str) -> bool:
    """So khớp IP: any / IPv4 / CIDR."""
    if value is None:
        return False
    text = str(spec).strip().lower()
    if text == "any":
        return True
    try:
        address = ipaddress.IPv4Address(str(value))
    except ValueError:
        return False
    if "/" in text:
        try:
            return address in ipaddress.IPv4Network(text, strict=False)
        except ValueError:
            return False
    return str(value) == text


def _port_matches(value: Any, spec: str) -> bool:
    """So khớp port: any / single / range (a:b, :b, a:)."""
    if value is None:
        return False
    text = str(spec).strip().lower()
    if text == "any":
        return True
    try:
        port = int(value)
    except (TypeError, ValueError):
        return False
    if ":" not in text:
        return port == int(text)
    low, _, high = text.partition(":")
    if low and port < int(low):
        return False
    if high and port > int(high):
        return False
    return True


def _packet_is_forward(rule: Rule, event: dict[str, Any], flow: dict[str, Any]) -> bool:
    """Xác định gói đi theo chiều client->server của rule."""
    src_ip = event.get("src_ip")
    dst_ip = event.get("dst_ip")
    src_port = event.get("src_port")
    dst_port = event.get("dst_port")

    forward = (
        _ip_matches(src_ip, rule.src_ip)
        and _port_matches(src_port, rule.src_port)
        and _ip_matches(dst_ip, rule.dst_ip)
        and _port_matches(dst_port, rule.dst_port)
    )
    backward = (
        _ip_matches(src_ip, rule.dst_ip)
        and _port_matches(src_port, rule.dst_port)
        and _ip_matches(dst_ip, rule.src_ip)
        and _port_matches(dst_port, rule.src_port)
    )

    # any/any <> any/any -> forward và backward đều đúng, dùng initiator của flow
    if forward and backward:
        initiator_ip = flow.get("src_ip")
        initiator_port = flow.get("src_port")
        if initiator_ip is not None and str(src_ip) == str(initiator_ip):
            if initiator_port is None or src_port == initiator_port:
                return True
        if initiator_ip is not None and str(dst_ip) == str(initiator_ip):
            return False
    return forward


def _flags_match(tokens: list[str], flags: dict[str, int]) -> bool:
    """Kiểm tra flags.

    - '0'   : không flag nào được bật
    - 'S'   : chỉ SYN được bật (exact)
    - 'S+'  : SYN được bật, các flag khác không quan tâm
    - '!S'  : SYN không được bật
    """
    values = {
        TCP_FLAG_MAP[letter]: int(flags.get(TCP_FLAG_MAP[letter], 0))
        for letter in TRACKED_FLAGS
    }

    plain: set[str] = set()
    plus: set[str] = set()
    negated: set[str] = set()
    exact_zero = False

    for token in tokens:
        if token == "0":
            exact_zero = True
            continue
        modifier = token[-1] if token[-1] in "+!*" else ""
        letters = token.rstrip("+!*")
        names = {TCP_FLAG_MAP[ch] for ch in letters if ch in TCP_FLAG_MAP}
        if modifier == "+":
            plus |= names
        elif modifier == "!":
            negated |= names
        else:
            plain |= names

    if exact_zero:
        return not any(values.values())

    for name in plus:
        if values.get(name, 0) != 1:
            return False
    for name in negated:
        if values.get(name, 0) != 0:
            return False

    # Token thuần (không +/!) yêu cầu khớp chính xác tập flag được bật
    if plain:
        for name in values:
            expected = 1 if name in plain else 0
            if values[name] != expected:
                return False
    return True


def _build_buffers(event: dict[str, Any]) -> list[tuple[str, bytes]]:
    """ Gom các trường dạng text của app_data/decoded thành các buffer bytes.

    NormalizedEvent không giữ raw payload, nên content được tìm trong dữ liệu
    application đã parse/decode/normalize (path, body, header, dns name, ...).
    """
    buffers: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    for source in ("app_data", "decoded"):
        data = event.get(source)
        if not isinstance(data, dict):
            continue
        for name, text in _iter_strings(data):
            encoded = text.encode("utf-8", errors="replace")
            if encoded and encoded not in seen:
                seen.add(encoded)
                buffers.append((f"{source}.{name}", encoded))

    return buffers


def _iter_strings(data: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Duyệt đệ quy dict/list để lấy các chuỗi con."""
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _iter_strings(value, path)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            yield from _iter_strings(value, f"{prefix}[{index}]")
    elif isinstance(data, str) and data:
        yield prefix, data


def _match_in_buffer(contents: list[ContentOption], buffer: bytes) -> Optional[list[dict[str, Any]]]:
    """Thử toàn bộ content sequence trên một buffer. Trả None nếu không khớp."""
    cursor = 0
    matches: list[dict[str, Any]] = []

    for option in contents:
        needle = option.value
        hay = buffer.lower() if option.nocase else buffer
        needle_cmp = needle.lower() if option.nocase else needle

        if option.offset is not None or option.depth is not None:
            start = option.offset or 0
            end = option.depth if option.depth is not None else len(hay)
        elif option.distance is not None or option.within is not None:
            start = cursor + (option.distance or 0)
            end = start + option.within if option.within is not None else len(hay)
            end = min(end, len(hay))
        else:
            start = cursor
            end = len(hay)

        index = hay.find(needle_cmp, start, end)
        if index == -1:
            return None

        cursor = index + len(needle)
        matches.append({
            "content": option.text(),
            "offset": index,
            "length": len(needle),
            "nocase": option.nocase,
        })

    return matches
