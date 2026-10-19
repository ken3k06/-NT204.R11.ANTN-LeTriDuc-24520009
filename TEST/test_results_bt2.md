# Test results - Bài tập 2

Chạy bằng lệnh:

```bash
conda run -n ids python -m pytest tests/test_bt2.py -v
```

Kết quả:

```text
============================= test session starts ==============================
platform linux -- Python 3.12.14, pytest-9.1.1, pluggy-1.6.0

tests/test_bt2.py::test_t01_url_decode PASSED                            [  7%]
tests/test_bt2.py::test_t02_html_entity_decode PASSED                    [ 14%]
tests/test_bt2.py::test_t03_smtp_base64_decode PASSED                    [ 21%]
tests/test_bt2.py::test_t04_invalid_bytes PASSED                         [ 28%]
tests/test_bt2.py::test_t05_normalization PASSED                         [ 35%]
tests/test_bt2.py::test_t06_missing_fields PASSED                        [ 42%]
tests/test_bt2.py::test_t07_tcp_handshake PASSED                         [ 50%]
tests/test_bt2.py::test_t08_bidirectional_flow PASSED                    [ 57%]
tests/test_bt2.py::test_t09_tcp_close PASSED                             [ 64%]
tests/test_bt2.py::test_t10_udp_query_response PASSED                    [ 71%]
tests/test_bt2.py::test_t11_concurrent_flows PASSED                      [ 78%]
tests/test_bt2.py::test_t12_idle_timeout PASSED                          [ 85%]
tests/test_bt2.py::test_t13_flow_statistics PASSED                       [ 92%]
tests/test_bt2.py::test_t14_malformed_events PASSED                      [100%]

============================== 14 passed in 0.02s ==============================
```

## Mô tả test cases

| Test | Module | Mô tả |
|------|--------|-------|
| T01 | Decoder | URL percent decoding: `%27%20OR%201%3D1` → `' OR 1=1` |
| T02 | Decoder | HTML entity decoding: `&lt;script&gt;` → `<script>` |
| T03 | Decoder | SMTP Base64 decoding: `SGVsbG8gV29ybGQ=` → `Hello World` |
| T04 | Decoder | Invalid bytes + Quoted-Printable: xử lý an toàn byte lỗi |
| T05 | Preprocessor | Normalization: protocol uppercase, header lowercase, timestamp ISO |
| T06 | Preprocessor | Missing fields: status invalid/partial, giá trị mặc định |
| T07 | Flow Tracker | TCP 3-way handshake: SYN → SYN+ACK → ACK |
| T08 | Flow Tracker | Bidirectional flow: A→B và B→A cùng flow_id |
| T09 | Flow Tracker | TCP close: ESTABLISHED → FIN → CLOSING → CLOSED |
| T10 | Flow Tracker | UDP query/response: NEW → ESTABLISHED |
| T11 | Flow Tracker | Concurrent flows: 3 flow đồng thời track riêng biệt |
| T12 | Flow Tracker | Idle timeout: flow hết hạn bị expire |
| T13 | Flow Tracker | Flow statistics: packet_count, byte_count, duration, flags |
| T14 | Flow Tracker | Malformed events: event lỗi → flow=None, status=invalid |
