"""Module Decoder: giải mã dữ liệu payload sau khi parse.

Chức năng:
- HTTP URL/percent decoding
- HTML entity decoding  
- SMTP Base64 / Quoted-Printable decoding
- Character decoding (ASCII/UTF-8 an toàn)
"""
from __future__ import annotations

import base64
import html
import quopri
import re
from typing import Any, Optional
from urllib.parse import unquote


def decode_event(event_dict: dict[str, Any]) -> dict[str, Any]:
    """Nhận một event dict (từ NormalizedEvent.to_dict()) và giải mã các trường.
    
    Trả về event dict đã thêm trường 'decoded' chứa kết quả giải mã.
    Event gốc không bị thay đổi - các giá trị raw vẫn giữ nguyên.
    """
    decoded_fields = {}
    app_protocol = event_dict.get("app_protocol", "UNKNOWN")
    app_data = event_dict.get("app_data")

    if app_protocol == "HTTP" and app_data:
        decoded_fields = _decode_http(app_data)
    elif app_protocol == "SMTP" and app_data:
        decoded_fields = _decode_smtp(app_data)

    # Thêm trường decoded vào event
    event_dict["decoded"] = decoded_fields if decoded_fields else None
    return event_dict


def _decode_http(app_data: dict[str, Any]) -> dict[str, Any]:
    """Giải mã HTTP: URL percent-decoding và HTML entity decoding."""
    result = {}

    # URL percent decoding cho path
    # Ví dụ: /search?q=%27%20OR%201%3D1 -> /search?q=' OR 1=1
    raw_path = app_data.get("path", "")
    if raw_path and "%" in raw_path:
        result["decoded_path"] = url_decode(raw_path)
    
    # URL decoding cho body (application/x-www-form-urlencoded)
    # Kiểm tra Content-Type header
    headers = app_data.get("headers", {})
    content_type = ""
    for key, value in headers.items():
        if key.lower() == "content-type":
            content_type = value.lower()
            break

    if "x-www-form-urlencoded" in content_type:
        body = app_data.get("body", "")
        if body and "%" in body:
            result["decoded_body"] = url_decode(body)

    # HTML entity decoding cho response body
    # Ví dụ: &lt;script&gt;alert(1)&lt;/script&gt; -> <script>alert(1)</script>
    body_text = app_data.get("body", "")
    if body_text and "&" in body_text and ";" in body_text:
        decoded = html_entity_decode(body_text)
        if decoded != body_text:
            result["html_decoded_body"] = decoded

    return result


def _decode_smtp(app_data: dict[str, Any]) -> dict[str, Any]:
    """Giải mã SMTP: Base64 và Quoted-Printable."""
    result = {}
    line = app_data.get("line", "")
    encoding = app_data.get("encoding", "")

    # Tự động detect encoding từ header hoặc nội dung
    if not encoding:
        encoding = _detect_smtp_encoding(line)

    if encoding == "base64":
        decoded = decode_base64(line)
        if decoded is not None:
            result["decoded_content"] = decoded
            result["encoding"] = "base64"
    elif encoding == "quoted-printable":
        decoded = decode_quoted_printable(line)
        if decoded is not None:
            result["decoded_content"] = decoded
            result["encoding"] = "quoted-printable"

    return result


def _detect_smtp_encoding(text: str) -> str:
    """Phát hiện encoding của SMTP content."""
    # Kiểm tra xem có phải Base64 không (chỉ chứa ký tự base64)
    base64_pattern = re.compile(r'^[A-Za-z0-9+/=\s]+$')
    if base64_pattern.match(text) and len(text) > 10:
        return "base64"
    
    # Kiểm tra Quoted-Printable (chứa =XX patterns)
    if "=" in text and re.search(r'=[0-9A-Fa-f]{2}', text):
        return "quoted-printable"
    
    return ""


# === Các hàm decode đơn lẻ ===

def url_decode(text: str) -> str:
    """URL percent decoding.
    Ví dụ: %27%20OR%201%3D1 -> ' OR 1=1
    """
    try:
        return unquote(text, encoding="utf-8", errors="replace")
    except Exception:
        return text


def html_entity_decode(text: str) -> str:
    """HTML entity decoding.
    Ví dụ: &lt;script&gt;alert(1)&lt;/script&gt; -> <script>alert(1)</script>
    """
    try:
        return html.unescape(text)
    except Exception:
        return text


def decode_base64(text: str) -> Optional[str]:
    """Base64 decoding.
    Ví dụ: SGVsbG8gV29ybGQ= -> Hello World
    """
    try:
        # Loại bỏ whitespace
        cleaned = text.strip()
        decoded_bytes = base64.b64decode(cleaned, validate=True)
        return safe_decode_bytes(decoded_bytes)
    except Exception:
        return None


def decode_quoted_printable(text: str) -> Optional[str]:
    """Quoted-Printable decoding.
    Ví dụ: Hello=20World=21 -> Hello World!
    """
    try:
        decoded_bytes = quopri.decodestring(text.encode("ascii", errors="replace"))
        return safe_decode_bytes(decoded_bytes)
    except Exception:
        return None


def safe_decode_bytes(data: bytes) -> str:
    """Decode bytes an toàn - thử UTF-8 trước, fallback ASCII.
    Không bao giờ crash khi gặp byte lỗi.
    """
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # Fallback: decode ASCII, thay thế byte lỗi bằng ?
        return data.decode("ascii", errors="replace")
