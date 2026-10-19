"""Module Preprocessor: kiểm tra và chuẩn hóa event.

Chức năng:
- Validation: kiểm tra các trường bắt buộc, port range, timestamp, protocol
- Normalization: chuẩn hóa protocol name, IP, HTTP headers, URI, timestamp  
- Missing data handling: xử lý nhất quán bằng null hoặc []
- Metadata: thêm preprocess_status, processing_action, reason
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Danh sách protocol hợp lệ
VALID_TRANSPORTS = {"TCP", "UDP", "UNKNOWN"}
VALID_APP_PROTOCOLS = {"HTTP", "DNS", "SMTP", "UNKNOWN"}


def preprocess_event(event_dict: dict[str, Any]) -> dict[str, Any]:
    """Validate và normalize một event dict.
    
    Thêm các trường metadata:
    - preprocess_status: 'valid' | 'partial' | 'invalid'
    - processing_action: mô tả hành động đã thực hiện
    - reason: lý do nếu status không phải 'valid'
    """
    issues = []
    actions = []

    # === NORMALIZATION trước (để validate đúng giá trị đã chuẩn hóa) ===
    event_dict, n_actions = _normalize(event_dict)
    actions.extend(n_actions)

    # === VALIDATION ===
    event_dict, v_issues = _validate(event_dict)
    issues.extend(v_issues)

    # === MISSING DATA HANDLING ===
    event_dict = _handle_missing(event_dict)

    # === METADATA ===
    # Xác định status dựa trên issues
    if not issues:
        status = "valid"
    elif event_dict.get("src_ip") and event_dict.get("dst_ip"):
        # Có IP nhưng có lỗi khác -> partial
        status = "partial"
    else:
        # Thiếu IP hoặc lỗi nghiêm trọng -> invalid
        status = "invalid"

    event_dict["preprocess_status"] = status
    event_dict["processing_action"] = "; ".join(actions) if actions else "none"
    event_dict["reason"] = "; ".join(issues) if issues else None

    return event_dict


def _validate(event_dict: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Kiểm tra các trường bắt buộc và giá trị hợp lệ."""
    issues = []

    # Kiểm tra trường bắt buộc
    if event_dict.get("packet_id") is None:
        issues.append("missing packet_id")
    if event_dict.get("timestamp") is None:
        issues.append("missing timestamp")

    # Kiểm tra timestamp hợp lệ (phải là số dương)
    ts = event_dict.get("timestamp")
    if ts is not None:
        if not isinstance(ts, (int, float)) or ts < 0:
            issues.append(f"invalid timestamp: {ts}")

    # Kiểm tra port range (0-65535)
    for port_field in ("src_port", "dst_port"):
        port = event_dict.get(port_field)
        if port is not None:
            if not isinstance(port, int) or port < 0 or port > 65535:
                issues.append(f"invalid {port_field}: {port}")

    # Kiểm tra transport protocol
    transport = event_dict.get("transport", "UNKNOWN")
    if transport not in VALID_TRANSPORTS:
        issues.append(f"invalid transport: {transport}")

    # Kiểm tra app_protocol
    app_proto = event_dict.get("app_protocol", "UNKNOWN")
    if app_proto not in VALID_APP_PROTOCOLS:
        issues.append(f"invalid app_protocol: {app_proto}")

    # Kiểm tra IP có tồn tại không (cần thiết cho network analysis)
    if not event_dict.get("src_ip") or not event_dict.get("dst_ip"):
        issues.append("missing network info (src_ip/dst_ip)")

    # Kiểm tra event có lỗi từ pipeline trước không
    if event_dict.get("error"):
        issues.append(f"upstream error: {event_dict['error']}")

    return event_dict, issues


def _normalize(event_dict: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Chuẩn hóa các giá trị."""
    actions = []

    # Chuẩn hóa protocol name -> uppercase
    transport = event_dict.get("transport")
    if transport and isinstance(transport, str):
        upper = transport.upper()
        if upper != transport:
            event_dict["transport"] = upper
            actions.append(f"normalized transport: {transport} -> {upper}")

    app_proto = event_dict.get("app_protocol")
    if app_proto and isinstance(app_proto, str):
        upper = app_proto.upper()
        if upper != app_proto:
            event_dict["app_protocol"] = upper
            actions.append(f"normalized app_protocol: {app_proto} -> {upper}")

    # Chuẩn hóa IP address -> lowercase (cho IPv6 hex) và strip whitespace
    for ip_field in ("src_ip", "dst_ip"):
        ip = event_dict.get(ip_field)
        if ip and isinstance(ip, str):
            cleaned = ip.strip().lower()
            if cleaned != ip:
                event_dict[ip_field] = cleaned
                actions.append(f"normalized {ip_field}")

    # Chuẩn hóa HTTP headers -> lowercase header names
    app_data = event_dict.get("app_data")
    if app_data and isinstance(app_data, dict):
        headers = app_data.get("headers")
        if headers and isinstance(headers, dict):
            normalized_headers = {}
            for key, value in headers.items():
                normalized_headers[key.lower()] = value
            if normalized_headers != headers:
                app_data["headers"] = normalized_headers
                actions.append("normalized http header names to lowercase")

        # Chuẩn hóa HTTP path
        path = app_data.get("path")
        if path and isinstance(path, str):
            cleaned = path.strip()
            if cleaned != path:
                app_data["path"] = cleaned
                actions.append("normalized http path")

    # Chuẩn hóa timestamp thành ISO 8601 string
    ts = event_dict.get("timestamp")
    if ts is not None and isinstance(ts, (int, float)):
        try:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            event_dict["timestamp_iso"] = dt.isoformat()
            actions.append("added timestamp_iso")
        except (OSError, ValueError, OverflowError):
            pass

    return event_dict, actions


def _handle_missing(event_dict: dict[str, Any]) -> dict[str, Any]:
    """Xử lý các trường bị thiếu hoặc không hỗ trợ."""
    # Đảm bảo các trường list luôn là list (không phải None)
    app_data = event_dict.get("app_data")
    if app_data and isinstance(app_data, dict):
        for list_field in ("questions", "answers", "headers_list"):
            if list_field in app_data and app_data[list_field] is None:
                app_data[list_field] = []

    # Đảm bảo các trường quan trọng có giá trị mặc định
    defaults = {
        "transport": "UNKNOWN",
        "app_protocol": "UNKNOWN",
        "payload_len": 0,
        "error": None,
        "tcp_flags": None,
        "app_data": None,
    }
    for fld, default in defaults.items():
        if fld not in event_dict:
            event_dict[fld] = default

    return event_dict
