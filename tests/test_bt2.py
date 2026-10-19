"""Tests cho Bài tập 2: Decoder, Preprocessor, Flow Tracker.

14 test cases theo yêu cầu đề bài:
T01-T04: Decoder (URL decode, HTML entity, SMTP Base64/QP, Invalid bytes)
T05-T06: Preprocessor (Normalization, Missing fields)
T07-T14: Flow Tracker (TCP handshake, Bidirectional, TCP close, UDP, 
                        Concurrent flows, Idle timeout, Flow stats, Malformed)
"""
import copy

from src.decoder.decoder import (
    decode_base64,
    decode_event,
    decode_quoted_printable,
    html_entity_decode,
    safe_decode_bytes,
    url_decode,
)
from src.flow_tracker.flow_tracker import FlowTracker, _make_flow_id
from src.preprocessor.preprocessor import preprocess_event


# ============================================================
# T01: URL Decode
# ============================================================
def test_t01_url_decode():
    """HTTP URL percent decoding: %27%20OR%201%3D1 -> ' OR 1=1"""
    # Test hàm đơn lẻ
    assert url_decode("%27%20OR%201%3D1") == "' OR 1=1"
    assert url_decode("/search%3Fq%3Dhello") == "/search?q=hello"

    # Test qua decode_event
    event = {
        "app_protocol": "HTTP",
        "app_data": {
            "type": "request",
            "method": "GET",
            "path": "/search?q=%27%20OR%201%3D1",
            "headers": {},
        },
    }
    result = decode_event(event)
    assert result["decoded"] is not None
    assert result["decoded"]["decoded_path"] == "/search?q=' OR 1=1"


# ============================================================
# T02: HTML Entity Decode
# ============================================================
def test_t02_html_entity_decode():
    """HTML entity decoding: &lt;script&gt; -> <script>"""
    assert html_entity_decode("&lt;script&gt;alert(1)&lt;/script&gt;") == "<script>alert(1)</script>"
    assert html_entity_decode("&amp;") == "&"
    assert html_entity_decode("&#60;") == "<"

    # Test qua decode_event
    event = {
        "app_protocol": "HTTP",
        "app_data": {
            "type": "response",
            "body": "&lt;script&gt;alert(1)&lt;/script&gt;",
            "headers": {},
        },
    }
    result = decode_event(event)
    assert result["decoded"] is not None
    assert result["decoded"]["html_decoded_body"] == "<script>alert(1)</script>"


# ============================================================
# T03: SMTP Base64 Decode
# ============================================================
def test_t03_smtp_base64_decode():
    """SMTP Base64 decoding: SGVsbG8gV29ybGQ= -> Hello World"""
    assert decode_base64("SGVsbG8gV29ybGQ=") == "Hello World"

    # Test qua decode_event với encoding hint
    event = {
        "app_protocol": "SMTP",
        "app_data": {
            "line": "SGVsbG8gV29ybGQ=",
            "encoding": "base64",
        },
    }
    result = decode_event(event)
    assert result["decoded"] is not None
    assert result["decoded"]["decoded_content"] == "Hello World"
    assert result["decoded"]["encoding"] == "base64"


# ============================================================
# T04: Invalid Bytes / Quoted-Printable + Safe decode
# ============================================================
def test_t04_invalid_bytes():
    """Xử lý an toàn byte lỗi - không crash."""
    # Byte UTF-8 lỗi
    bad_bytes = b"\xff\xfe\x80\x81"
    result = safe_decode_bytes(bad_bytes)
    assert isinstance(result, str)  # Không crash, trả về string

    # Quoted-Printable decode
    assert decode_quoted_printable("Hello=20World=21") == "Hello World!"

    # Test decode_event cho SMTP QP
    event = {
        "app_protocol": "SMTP",
        "app_data": {
            "line": "Hello=20World=21",
            "encoding": "quoted-printable",
        },
    }
    result = decode_event(event)
    assert result["decoded"]["decoded_content"] == "Hello World!"


# ============================================================
# T05: Preprocessor Normalization
# ============================================================
def test_t05_normalization():
    """Chuẩn hóa: protocol uppercase, IP lowercase, HTTP header lowercase, timestamp ISO."""
    event = {
        "packet_id": 1,
        "timestamp": 1700000000.0,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "transport": "tcp",        # chữ thường
        "app_protocol": "http",    # chữ thường
        "src_port": 1234,
        "dst_port": 80,
        "app_data": {
            "headers": {"Content-Type": "text/html", "Host": "example.com"},
        },
    }
    result = preprocess_event(event)

    assert result["transport"] == "TCP"
    assert result["app_protocol"] == "HTTP"
    assert result["preprocess_status"] == "valid"
    assert "timestamp_iso" in result
    # Headers phải được chuẩn hóa lowercase
    assert "content-type" in result["app_data"]["headers"]


# ============================================================
# T06: Missing Fields
# ============================================================
def test_t06_missing_fields():
    """Event thiếu trường -> status partial/invalid, giá trị mặc định."""
    # Thiếu src_ip và dst_ip -> invalid
    event_invalid = {
        "packet_id": 1,
        "timestamp": 1700000000.0,
    }
    result = preprocess_event(event_invalid)
    assert result["preprocess_status"] == "invalid"
    assert result["transport"] == "UNKNOWN"
    assert result["payload_len"] == 0

    # Có IP nhưng thiếu port -> partial (vì src_port/dst_port là None = ko check)
    event_partial = {
        "packet_id": 2,
        "timestamp": 1700000000.0,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": -1,          # Port lỗi
    }
    result2 = preprocess_event(event_partial)
    assert result2["preprocess_status"] == "partial"
    assert "invalid src_port" in result2["reason"]


# ============================================================
# T07: TCP 3-Way Handshake
# ============================================================
def test_t07_tcp_handshake():
    """TCP 3-way handshake: SYN -> SYN+ACK -> ACK."""
    tracker = FlowTracker()

    # Bước 1: Client gửi SYN
    syn = {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "src_port": 5000, "dst_port": 80,
        "transport": "TCP", "timestamp": 1.0, "payload_len": 0,
        "tcp_flags": {"SYN": 1, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0},
    }
    result = tracker.process_event(syn)
    assert result["flow"]["state"] == "HANDSHAKE"

    # Bước 2: Server trả SYN+ACK
    syn_ack = {
        "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
        "src_port": 80, "dst_port": 5000,
        "transport": "TCP", "timestamp": 1.1, "payload_len": 0,
        "tcp_flags": {"SYN": 1, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 0},
    }
    result = tracker.process_event(syn_ack)
    assert result["flow"]["state"] == "HANDSHAKE"

    # Bước 3: Client gửi ACK
    ack = {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "src_port": 5000, "dst_port": 80,
        "transport": "TCP", "timestamp": 1.2, "payload_len": 0,
        "tcp_flags": {"SYN": 0, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 0},
    }
    result = tracker.process_event(ack)
    assert result["flow"]["state"] == "ESTABLISHED"


# ============================================================
# T08: Bidirectional Flow
# ============================================================
def test_t08_bidirectional_flow():
    """A->B và B->A phải cùng flow_id."""
    # Kiểm tra flow_id ổn định
    id_ab = _make_flow_id("10.0.0.1", 5000, "10.0.0.2", 80, "TCP")
    id_ba = _make_flow_id("10.0.0.2", 80, "10.0.0.1", 5000, "TCP")
    assert id_ab == id_ba

    # Kiểm tra qua FlowTracker
    tracker = FlowTracker()

    ev_forward = {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "src_port": 5000, "dst_port": 80,
        "transport": "TCP", "timestamp": 1.0, "payload_len": 100,
        "tcp_flags": {"SYN": 1, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0},
    }
    r1 = tracker.process_event(ev_forward)

    ev_backward = {
        "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
        "src_port": 80, "dst_port": 5000,
        "transport": "TCP", "timestamp": 1.1, "payload_len": 200,
        "tcp_flags": {"SYN": 1, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 0},
    }
    r2 = tracker.process_event(ev_backward)

    # Cùng flow_id
    assert r1["flow"]["flow_id"] == r2["flow"]["flow_id"]
    # Forward/backward đúng
    assert r2["flow"]["forward_packets"] == 1
    assert r2["flow"]["backward_packets"] == 1
    assert r2["flow"]["forward_bytes"] == 100
    assert r2["flow"]["backward_bytes"] == 200


# ============================================================
# T09: TCP Close (FIN)
# ============================================================
def test_t09_tcp_close():
    """TCP close: ESTABLISHED -> FIN -> CLOSING -> CLOSED."""
    tracker = FlowTracker()

    # Thiết lập connection
    for flags in [
        {"SYN": 1, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0},
    ]:
        tracker.process_event({
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 5000, "dst_port": 80,
            "transport": "TCP", "timestamp": 1.0, "payload_len": 0,
            "tcp_flags": flags,
        })

    tracker.process_event({
        "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
        "src_port": 80, "dst_port": 5000,
        "transport": "TCP", "timestamp": 1.1, "payload_len": 0,
        "tcp_flags": {"SYN": 1, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 0},
    })
    
    r = tracker.process_event({
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "src_port": 5000, "dst_port": 80,
        "transport": "TCP", "timestamp": 1.2, "payload_len": 0,
        "tcp_flags": {"SYN": 0, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 0},
    })
    assert r["flow"]["state"] == "ESTABLISHED"

    # FIN -> CLOSING
    r = tracker.process_event({
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "src_port": 5000, "dst_port": 80,
        "transport": "TCP", "timestamp": 2.0, "payload_len": 0,
        "tcp_flags": {"SYN": 0, "ACK": 0, "FIN": 1, "RST": 0, "PSH": 0},
    })
    assert r["flow"]["state"] == "CLOSING"

    # ACK cuối -> CLOSED
    r = tracker.process_event({
        "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
        "src_port": 80, "dst_port": 5000,
        "transport": "TCP", "timestamp": 2.1, "payload_len": 0,
        "tcp_flags": {"SYN": 0, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 0},
    })
    assert r["flow"]["state"] == "CLOSED"


# ============================================================
# T10: UDP Query/Response
# ============================================================
def test_t10_udp_query_response():
    """UDP flow: NEW -> ESTABLISHED khi có gói phản hồi."""
    tracker = FlowTracker()

    # Client gửi DNS query
    query = {
        "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
        "src_port": 4444, "dst_port": 53,
        "transport": "UDP", "timestamp": 1.0, "payload_len": 40,
    }
    r1 = tracker.process_event(query)
    assert r1["flow"]["state"] == "NEW"

    # Server trả response
    response = {
        "src_ip": "8.8.8.8", "dst_ip": "10.0.0.1",
        "src_port": 53, "dst_port": 4444,
        "transport": "UDP", "timestamp": 1.05, "payload_len": 100,
    }
    r2 = tracker.process_event(response)
    assert r2["flow"]["state"] == "ESTABLISHED"
    assert r2["flow"]["flow_id"] == r1["flow"]["flow_id"]


# ============================================================
# T11: Concurrent Flows
# ============================================================
def test_t11_concurrent_flows():
    """Nhiều flow đồng thời phải được track riêng biệt."""
    tracker = FlowTracker()

    # Flow 1: 10.0.0.1:5000 -> 10.0.0.2:80
    tracker.process_event({
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "src_port": 5000, "dst_port": 80,
        "transport": "TCP", "timestamp": 1.0, "payload_len": 50,
        "tcp_flags": {"SYN": 1, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0},
    })

    # Flow 2: 10.0.0.1:5001 -> 10.0.0.3:443
    tracker.process_event({
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3",
        "src_port": 5001, "dst_port": 443,
        "transport": "TCP", "timestamp": 1.1, "payload_len": 60,
        "tcp_flags": {"SYN": 1, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0},
    })

    # Flow 3: UDP 10.0.0.1:4444 -> 8.8.8.8:53
    tracker.process_event({
        "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
        "src_port": 4444, "dst_port": 53,
        "transport": "UDP", "timestamp": 1.2, "payload_len": 40,
    })

    summary = tracker.get_summary()
    assert summary["active_flows"] == 3
    assert summary["tcp_flows"] == 2
    assert summary["udp_flows"] == 1


# ============================================================
# T12: Idle Timeout
# ============================================================
def test_t12_idle_timeout():
    """Flow hết idle timeout phải bị expire."""
    tracker = FlowTracker(tcp_timeout=10, udp_timeout=5)

    # Tạo UDP flow tại t=1
    tracker.process_event({
        "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
        "src_port": 4444, "dst_port": 53,
        "transport": "UDP", "timestamp": 1.0, "payload_len": 40,
    })
    assert len(tracker.active_flows) == 1

    # Sau 6 giây (> udp_timeout=5) -> expire
    tracker.process_event({
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3",
        "src_port": 5000, "dst_port": 80,
        "transport": "TCP", "timestamp": 7.0, "payload_len": 0,
        "tcp_flags": {"SYN": 1, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0},
    })

    # UDP flow phải bị expire, chỉ còn TCP flow
    assert len(tracker.active_flows) == 1
    assert len(tracker.expired_flows) == 1
    assert tracker.expired_flows[0].state == "EXPIRED"
    assert tracker.expired_flows[0].protocol == "UDP"


# ============================================================
# T13: Flow Statistics
# ============================================================
def test_t13_flow_statistics():
    """Thống kê flow chính xác: packet_count, byte_count, duration, flag counters."""
    tracker = FlowTracker()

    # 3 gói forward, 2 gói backward
    events = [
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 5000, "dst_port": 80,
         "transport": "TCP", "timestamp": 1.0, "payload_len": 0,
         "tcp_flags": {"SYN": 1, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0}},
        {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 5000,
         "transport": "TCP", "timestamp": 1.1, "payload_len": 0,
         "tcp_flags": {"SYN": 1, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 0}},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 5000, "dst_port": 80,
         "transport": "TCP", "timestamp": 1.2, "payload_len": 0,
         "tcp_flags": {"SYN": 0, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 0}},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 5000, "dst_port": 80,
         "transport": "TCP", "timestamp": 2.0, "payload_len": 500,
         "tcp_flags": {"SYN": 0, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 1}},
        {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 5000,
         "transport": "TCP", "timestamp": 2.5, "payload_len": 1000,
         "tcp_flags": {"SYN": 0, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 1}},
    ]

    for ev in events:
        result = tracker.process_event(ev)

    flow = result["flow"]
    assert flow["packet_count"] == 5
    assert flow["byte_count"] == 1500
    assert flow["forward_packets"] == 3
    assert flow["forward_bytes"] == 500       # chỉ gói thứ 4 có payload
    assert flow["backward_packets"] == 2
    assert flow["backward_bytes"] == 1000
    assert flow["duration"] == 1.5            # 2.5 - 1.0
    assert flow["syn_count"] == 2             # SYN ở gói 1 và 2
    assert flow["ack_count"] == 4             # ACK ở gói 2,3,4,5
    assert flow["psh_count"] == 2             # PSH ở gói 4 và 5


# ============================================================
# T14: Malformed Events
# ============================================================
def test_t14_malformed_events():
    """Event lỗi/thiếu thông tin -> flow = None, preprocessor = invalid."""
    tracker = FlowTracker()

    # Event thiếu IP -> không track được
    malformed = {
        "src_ip": None, "dst_ip": None,
        "transport": "UNKNOWN", "timestamp": 1.0, "payload_len": 0,
        "error": "malformed",
    }
    result = tracker.process_event(malformed)
    assert result["flow"] is None

    # Preprocessor đánh giá event lỗi
    preprocessed = preprocess_event({
        "packet_id": 1,
        "timestamp": 1700000000.0,
        "error": "malformed",
    })
    assert preprocessed["preprocess_status"] == "invalid"

    # Decoder với event không có app_data
    decoded = decode_event({"app_protocol": "UNKNOWN", "app_data": None})
    assert decoded["decoded"] is None
