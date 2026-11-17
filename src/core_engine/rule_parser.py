"""Module Rule Parser & Validator: chuyển rule text thành Rule Object.

Chức năng:
- Tách Rule Header và Rule Options
- Parse các keyword thuộc phạm vi (msg, sid, rev, content, flags, dsize, flow, ...)
- Kiểm tra cú pháp, kiểu dữ liệu và phân loại valid / invalid / unsupported
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

# Phạm vi Snort rule được hỗ trợ (theo đề BT3)
SUPPORTED_ACTIONS = {"alert"}
SUPPORTED_PROTOCOLS = {"tcp", "udp"}
SUPPORTED_DIRECTIONS = {"->", "<>"}

SUPPORTED_KEYWORDS = {
    "msg", "sid", "rev",
    "content", "nocase", "offset", "depth", "distance", "within",
    "flags", "dsize", "flow",
    "classtype", "priority",
}
# Các keyword thường gặp nằm ngoài phạm vi -> báo unsupported, không crash
KNOWN_UNSUPPORTED_KEYWORDS = {
    "pcre", "byte_test", "byte_jump", "byte_extract", "byte_math",
    "isdataat", "uricontent", "urilen", "file_data", "tls", "lua",
    "http_uri", "http_header", "http_method", "http_client_body",
}
NO_VALUE_KEYWORDS = {"nocase"}
FLOW_KEYWORDS = {"to_server", "to_client", "established", "not_established"}
TCP_FLAG_MAP = {
    "S": "SYN", "A": "ACK", "F": "FIN", "R": "RST",
    "P": "PSH", "U": "URG", "E": "ECE", "C": "CWR",
}

HEADER_RE = re.compile(
    r"^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$",
    re.DOTALL,
)


@dataclass
class ContentOption:
    """Một keyword content và các modifier đi kèm."""
    value: bytes
    nocase: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None

    def text(self) -> str:
        return self.value.decode("utf-8", errors="replace")


@dataclass
class DsizeSpec:
    """Giới hạn kích thước payload: dsize:<n>, >n, <n hoặc n<>m."""
    min: Optional[int] = None
    max: Optional[int] = None


@dataclass
class Rule:
    """Internal Rule Object thống nhất cho toàn bộ Core Engine."""
    raw: str
    action: str = ""
    protocol: str = ""
    src_ip: str = "any"
    src_port: str = "any"
    direction: str = "->"
    dst_ip: str = "any"
    dst_port: str = "any"

    msg: str = ""
    sid: int = 0
    rev: int = 0

    contents: list[ContentOption] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    dsize: Optional[DsizeSpec] = None
    flow: list[str] = field(default_factory=list)
    classtype: Optional[str] = None
    priority: Optional[int] = None

    status: str = "valid"            # valid | invalid | unsupported
    reason: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        return self.status == "valid"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_rule(rule_text: str) -> Rule:
    """Parse một dòng rule. Không bao giờ raise - trả về Rule có status.

    status = 'invalid' nếu sai cú pháp / sai kiểu dữ liệu,
    status = 'unsupported' nếu dùng action/protocol/keyword ngoài phạm vi.
    """
    text = rule_text.strip()
    rule = Rule(raw=text)
    errors: list[str] = []
    unsupported: list[str] = []

    match = HEADER_RE.match(text)
    if not match:
        rule.status = "invalid"
        rule.reason = "invalid rule syntax (header/options)"
        return rule

    action, protocol, src_ip, src_port, direction, dst_ip, dst_port, options_text = match.groups()
    rule.action = action.strip().lower()
    rule.protocol = protocol.strip().lower()
    rule.src_ip = src_ip.strip()
    rule.src_port = src_port.strip()
    rule.direction = direction.strip()
    rule.dst_ip = dst_ip.strip()
    rule.dst_port = dst_port.strip()

    # === Header ===
    if rule.action not in SUPPORTED_ACTIONS:
        unsupported.append(f"unsupported action: {rule.action}")
    if rule.protocol not in SUPPORTED_PROTOCOLS:
        unsupported.append(f"unsupported protocol: {rule.protocol}")
    if rule.direction not in SUPPORTED_DIRECTIONS:
        errors.append(f"invalid direction: {rule.direction}")

    for label, value in (("src_ip", rule.src_ip), ("dst_ip", rule.dst_ip)):
        err = _validate_ip(value)
        if err:
            errors.append(f"{label}: {err}")
    for label, value in (("src_port", rule.src_port), ("dst_port", rule.dst_port)):
        err = _validate_port(value)
        if err:
            errors.append(f"{label}: {err}")

    # === Options ===
    for token in _split_options(options_text):
        keyword, value = _split_option(token)
        if keyword not in SUPPORTED_KEYWORDS:
            if keyword in KNOWN_UNSUPPORTED_KEYWORDS:
                unsupported.append(f"unsupported keyword: {keyword}")
            else:
                unsupported.append(f"unknown keyword: {keyword}")
            continue

        if keyword in NO_VALUE_KEYWORDS:
            if rule.contents:
                rule.contents[-1].nocase = True
            else:
                errors.append("nocase without preceding content")
            continue

        raw_value = _unquote(value)
        if keyword == "msg":
            rule.msg = raw_value
        elif keyword == "sid":
            sid = _parse_int(raw_value, "sid", errors, minimum=1)
            if sid is not None:
                rule.sid = sid
        elif keyword == "rev":
            rev = _parse_int(raw_value, "rev", errors, minimum=0)
            if rev is not None:
                rule.rev = rev
        elif keyword == "content":
            rule.contents.append(ContentOption(value=_decode_content(raw_value)))
        elif keyword in ("offset", "depth", "distance", "within"):
            num = _parse_int(raw_value, keyword, errors, minimum=0)
            if num is not None:
                if not rule.contents:
                    errors.append(f"{keyword} without preceding content")
                else:
                    setattr(rule.contents[-1], keyword, num)
        elif keyword == "flags":
            parsed_flags, flag_errors = _parse_flags(raw_value)
            rule.flags = parsed_flags
            errors.extend(flag_errors)
        elif keyword == "dsize":
            spec, dsize_errors = _parse_dsize(raw_value)
            if spec is not None:
                rule.dsize = spec
            errors.extend(dsize_errors)
        elif keyword == "flow":
            flows, flow_unsupported = _parse_flow(raw_value)
            rule.flow = flows
            unsupported.extend(flow_unsupported)
        elif keyword == "classtype":
            rule.classtype = raw_value
        elif keyword == "priority":
            priority = _parse_int(raw_value, "priority", errors, minimum=1)
            if priority is not None:
                rule.priority = priority

    # === Trường bắt buộc ===
    if rule.sid == 0:
        errors.append("missing or invalid sid")

    if unsupported:
        rule.status = "unsupported"
    elif errors:
        rule.status = "invalid"
    else:
        rule.status = "valid"

    reasons = unsupported + errors
    rule.reason = "; ".join(reasons) if reasons else None
    return rule


# === Các hàm phụ trợ ===

def _validate_ip(value: str) -> Optional[str]:
    """Chấp nhận any / IPv4 / CIDR. Trả về lý do lỗi hoặc None."""
    if value.lower() == "any":
        return None
    try:
        if "/" in value:
            ipaddress.IPv4Network(value, strict=False)
        else:
            ipaddress.IPv4Address(value)
    except ValueError:
        return f"invalid IPv4/CIDR: {value}"
    return None


def _validate_port(value: str) -> Optional[str]:
    """Chấp nhận any / single / range (a:b, :b, a:)."""
    if value.lower() == "any":
        return None
    parts = value.split(":")
    if len(parts) > 2:
        return f"invalid port range: {value}"
    for part in parts:
        if part == "":
            continue
        if not part.isdigit() or not (0 <= int(part) <= 65535):
            return f"invalid port: {value}"
    return None


def _split_options(text: str) -> list[str]:
    """Tách options bằng ';' nhưng bỏ qua ';' nằm trong ngoặc kép."""
    parts: list[str] = []
    buf: list[str] = []
    quote = False
    escape = False
    for ch in text:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\":
            buf.append(ch)
            escape = True
            continue
        if ch == '"':
            quote = not quote
            buf.append(ch)
            continue
        if ch == ";" and not quote:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _split_option(token: str) -> tuple[str, Optional[str]]:
    """Tách 'keyword:value' thành (keyword, value), tôn trọng ngoặc kép."""
    quote = False
    escape = False
    for i, ch in enumerate(token):
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            quote = not quote
            continue
        if ch == ":" and not quote:
            return token[:i].strip().lower(), token[i + 1:].strip()
    return token.strip().lower(), None


def _unquote(value: Optional[str]) -> str:
    if value is None:
        return ""
    result = value.strip()
    if len(result) >= 2 and result[0] == '"' and result[-1] == '"':
        result = result[1:-1]
    return result


def _decode_content(value: str) -> bytes:
    """Decode nội dung content: hex |HH|, escape \\; \\" \\\\ rồi encode bytes."""
    out = bytearray()
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "|":
            end = value.find("|", i + 1)
            if end != -1:
                hex_part = value[i + 1:end].replace(" ", "")
                try:
                    out.extend(bytes.fromhex(hex_part))
                except ValueError:
                    out.extend(value[i:end + 1].encode("utf-8"))
                i = end + 1
                continue
        if ch == "\\" and i + 1 < len(value):
            out.append(ord(value[i + 1]))
            i += 2
            continue
        out.extend(ch.encode("utf-8"))
        i += 1
    return bytes(out)


def _parse_int(value: str, name: str, errors: list[str], minimum: int = 0) -> Optional[int]:
    try:
        number = int(value)
        if number < minimum:
            raise ValueError
        return number
    except ValueError:
        errors.append(f"invalid {name}: {value}")
        return None


def _parse_flags(value: str) -> tuple[list[str], list[str]]:
    """Parse flags:S,SA+ thành các token ['S', 'A+']."""
    errors: list[str] = []
    tokens: list[str] = []
    for raw in value.replace(" ", "").split(","):
        if not raw:
            continue
        if raw == "0":
            tokens.append(raw)
            continue
        for ch in raw.rstrip("+!*"):
            if ch.upper() not in TCP_FLAG_MAP:
                errors.append(f"invalid TCP flag: {ch}")
        token = raw.upper()
        # '+' / '!' / '*' ở cuối là modifier, chỉ giữ lại 1 lần
        modifier = ""
        if token and token[-1] in "+!*":
            modifier = token[-1]
            token = token.rstrip("+!*")
        token = "".join(ch for ch in token if ch in TCP_FLAG_MAP)
        if token:
            tokens.append(token + modifier)
    return tokens, errors


def _parse_dsize(value: str) -> tuple[Optional[DsizeSpec], list[str]]:
    """Parse dsize:100, dsize:>100, dsize:<100, dsize:100<>200."""
    errors: list[str] = []
    text = value.replace(" ", "")
    if "<>" in text:
        lo, _, hi = text.partition("<>")
        if lo.isdigit() and hi.isdigit():
            return DsizeSpec(min=int(lo), max=int(hi)), errors
        errors.append(f"invalid dsize: {value}")
        return None, errors
    if text.startswith(">"):
        num = _parse_int(text[1:], "dsize", errors)
        return (DsizeSpec(min=num + 1), errors) if num is not None else (None, errors)
    if text.startswith("<"):
        num = _parse_int(text[1:], "dsize", errors)
        return (DsizeSpec(max=num - 1), errors) if num is not None else (None, errors)
    num = _parse_int(text, "dsize", errors)
    return (DsizeSpec(min=num, max=num), errors) if num is not None else (None, errors)


def _parse_flow(value: str) -> tuple[list[str], list[str]]:
    """Parse flow:to_server,established;."""
    flows: list[str] = []
    unsupported: list[str] = []
    for token in value.replace(" ", "").split(","):
        if not token:
            continue
        if token in FLOW_KEYWORDS:
            flows.append(token)
        else:
            unsupported.append(f"unsupported flow option: {token}")
    return flows, unsupported
