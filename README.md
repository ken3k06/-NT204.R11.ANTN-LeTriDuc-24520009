# IDS
Bài tập xây dựng 1 hệ thống IDS dựa trên ngôn ngữ lập trình Python 


## Bài tập 01 

Trước tiên ta sẽ setup môi trường ảo để cài đặt các thư viện cần thiết cho bài tập. Ở đây ta sẽ sử dụng conda để làm việc đó. 

```bash 
conda create --name ids python=3.12
```

Khởi chạy môi trường ảo:

```bash 
conda activate ids
```

Tải các thư viện cần thiết 
```
scapy>=2.5.0
netifaces
# protocol parsers
dnspython>=2.4.0        # DNS
httptools>=0.6.0        # HTTP

# Testing
pytest>=7.0.0
```

Kể từ giờ các thư viện cần thiết trong quá trình phát triển IDS sẽ được cập nhật tại đây để thuận tiện theo dõi

### Task 1: Chuẩn hóa output 

Tạo module `models` để chuẩn hóa output của các protocol parsers. 

Chi tiết xem trong file `event.py`

Note: Để xem qua các trường thông tin cần parse thì có thể tham khảo tài liệu RFC hoặc sử dụng trực tiếp scapy như sau:
```python
from scapy.all import *
ls(IP)
ls(UDP)
ls(TCP)
```

Tham khảo: 
- https://www.forum.vnpro.org/forum/ccna%C2%AE/ccna-200-301/439058-tcp-header-%E2%80%93-ph%C3%A2n-t%C3%ADch-chi-ti%E1%BA%BFt-c%E1%BA%A5u-tr%C3%BAc-g%C3%B3i-tin-c%E1%BB%A7a-transmission-control-protocol

### Task 2: Viết parser cho IPv4 

Luồng dữ liệu sẽ đi như sau:

```
raw_bytes -> parse_ipv4() -> normalized output {src_ip, dst_ip, ...}
```

Tham khảo:
- https://www.forum.vnpro.org/forum/ccna%C2%AE/cyber-security/432692-ipv4-header

Sau khi parse xong ta cần chuẩn hóa output. Chi tiết tại file `pipeline.py`

### Task 3: Capture và application parser

Chương trình hỗ trợ đọc packet từ live interface hoặc file pcap, sau đó đưa vào cùng pipeline:

```bash
python3 main.py --pcap test.pcap --output events.jsonl
python3 main.py --interface eth0 --count 10 --output events.jsonl
```

Output được ghi theo JSON Lines, mỗi dòng là một `NormalizedEvent`.

Application parser hiện có:
- HTTP request/response: method, path, status code, headers, body length
- DNS query/response: domain, query type, answer
- SMTP command/response: command hoặc status code

Test:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/pytest -q
```

---

## Bài tập 02: Decoder, Preprocessor, Flow Tracker

Mở rộng pipeline từ Bài tập 01 với 3 module xử lý trung gian:

```
Packet Capture & Parser → Decoder → Preprocessor → Flow/Connection Tracker
```

### Pipeline tổng quan

```
┌──────────────────┐     ┌─────────┐     ┌──────────────┐     ┌──────────────┐
│ Packet Capture   │ ──> │ Decoder │ ──> │ Preprocessor │ ──> │ Flow Tracker │
│ & Parser (BT1)   │     │         │     │              │     │              │
└──────────────────┘     └─────────┘     └──────────────┘     └──────────────┘
     raw bytes →          giải mã         validate &           theo dõi
     NormalizedEvent      payload         chuẩn hóa            connection
```

### Module 1: Decoder (`src/decoder/decoder.py`)

**Mục đích**: Giải mã (decode) các dữ liệu đã được encode trong payload.

**Chức năng chính**:

1. **HTTP URL/Percent Decoding**: Giải mã các ký tự percent-encoded trong URL
   - Ví dụ: `%27%20OR%201%3D1` → `' OR 1=1` (phát hiện SQL injection)
   - Sử dụng `urllib.parse.unquote()` 

2. **HTML Entity Decoding**: Giải mã HTML entities
   - Ví dụ: `&lt;script&gt;alert(1)&lt;/script&gt;` → `<script>alert(1)</script>` (phát hiện XSS)
   - Sử dụng `html.unescape()`

3. **SMTP MIME Decoding**: 
   - **Base64**: Giải mã nội dung email được mã hóa Base64
   - **Quoted-Printable**: Giải mã format QP (`=20` → space, `=21` → `!`)
   - Sử dụng `base64.b64decode()` và `quopri.decodestring()`

4. **Character Decoding**: Xử lý an toàn UTF-8/ASCII
   - Thử decode UTF-8 trước, fallback ASCII với `errors="replace"`
   - **Không bao giờ crash** khi gặp byte lỗi

**Cách hoạt động**: Hàm `decode_event()` nhận một event dict, tự động detect app_protocol rồi giải mã tương ứng. Kết quả được thêm vào trường `"decoded"` mà **không thay đổi dữ liệu gốc** (giữ nguyên raw để so sánh).

**Tại sao cần Decoder?**  
Kẻ tấn công thường encode payload để bypass IDS. Ví dụ:
- SQL Injection: `' OR 1=1` → `%27%20OR%201%3D1` (URL encoded)
- XSS: `<script>` → `&lt;script&gt;` (HTML encoded)
- Malware trong email: nội dung được mã hóa Base64

Decoder giải mã để module detection phía sau có thể kiểm tra nội dung thực sự.

### Module 2: Preprocessor (`src/preprocessor/preprocessor.py`)

**Mục đích**: Kiểm tra tính hợp lệ và chuẩn hóa dữ liệu event trước khi phân tích.

**Chức năng chính**:

1. **Validation** - Kiểm tra:
   - Trường bắt buộc: `packet_id`, `timestamp`
   - Port range: 0-65535
   - Timestamp: phải là số dương
   - Protocol: phải nằm trong danh sách hỗ trợ (TCP/UDP/UNKNOWN)
   - Network info: phải có `src_ip` và `dst_ip`

2. **Normalization** - Chuẩn hóa:
   - Protocol name → UPPERCASE (`tcp` → `TCP`, `http` → `HTTP`)
   - IP address → lowercase + strip whitespace
   - HTTP header names → lowercase (`Content-Type` → `content-type`)
   - Timestamp → thêm format ISO 8601 (`timestamp_iso`)

3. **Missing Data Handling**:
   - Trường list (`questions`, `answers`) = `None` → gán `[]`
   - Trường thiếu → gán giá trị mặc định (`transport="UNKNOWN"`, `payload_len=0`)

4. **Metadata** - Gán trạng thái:
   - `preprocess_status`: `"valid"` | `"partial"` | `"invalid"`
   - `processing_action`: mô tả các bước đã thực hiện
   - `reason`: lý do nếu status không phải valid

**Logic xác định status**:
- `valid`: không có issue nào
- `partial`: có issue nhưng vẫn có đủ IP (phân tích được một phần)
- `invalid`: thiếu IP hoặc lỗi nghiêm trọng

**Thứ tự xử lý**: Normalization chạy **trước** Validation. Lý do: cần uppercase protocol trước rồi mới validate xem có hợp lệ không.

### Module 3: Flow Tracker (`src/flow_tracker/flow_tracker.py`) ⭐ Trọng tâm

**Mục đích**: Gom nhóm các packet riêng lẻ thành các **flow** (luồng kết nối) và theo dõi trạng thái.

**Khái niệm cốt lõi**:
- **Flow**: Một chuỗi packet giữa 2 endpoint, được xác định bởi **5-tuple**: `(src_ip, dst_ip, src_port, dst_port, protocol)`
- **Bidirectional**: A→B và B→A thuộc **cùng một flow** (cùng `flow_id`)

**Cách tạo flow_id ổn định 2 chiều**:
```python
# Sắp xếp 2 endpoint theo thứ tự alphabet
# A→B và B→A đều tạo ra cùng một flow_id
endpoint_a = "10.0.0.1:5000"
endpoint_b = "10.0.0.2:80"
sorted → "10.0.0.1:5000-10.0.0.2:80-TCP"
flow_id = md5(sorted_string)[:16]
```

**TCP State Machine**:
```
                    SYN
        NEW ──────────────> HANDSHAKE
                            │
                     ACK    │  SYN+ACK (vẫn HANDSHAKE)
                            v
                         ESTABLISHED
                            │
                     FIN    │
                            v
                         CLOSING
                            │
                  FIN/ACK   │
                            v
                         CLOSED
                         
    Bất kỳ state ─── RST ──> RESET
```

- `NEW`: Gói đầu tiên của flow
- `HANDSHAKE`: Đang thực hiện TCP 3-way handshake (SYN đã gửi)
- `ESTABLISHED`: Handshake hoàn tất (nhận ACK cuối cùng)
- `CLOSING`: Đang đóng kết nối (FIN đã gửi)
- `CLOSED`: Kết nối đã đóng hoàn toàn
- `RESET`: Kết nối bị reset bất thường (RST flag)

**UDP Tracking**:
- `NEW`: Chỉ có gói một chiều (query)
- `ESTABLISHED`: Có gói phản hồi từ phía đối diện (response)
- Không có handshake hay close như TCP

**Idle Timeout**:
- TCP: 300 giây (5 phút)
- UDP: 30 giây
- Khi flow không có packet mới quá timeout → chuyển sang `EXPIRED` và đẩy vào `expired_flows`
- Cleanup chạy mỗi khi có event mới

**Thống kê mỗi flow**:
| Trường | Mô tả |
|--------|-------|
| `packet_count` | Tổng số packet (cả 2 chiều) |
| `byte_count` | Tổng byte payload |
| `forward_packets/bytes` | Packet/bytes chiều forward (từ initiator) |
| `backward_packets/bytes` | Packet/bytes chiều backward (từ responder) |
| `start_time` | Timestamp gói đầu tiên |
| `last_seen` | Timestamp gói cuối cùng |
| `duration` | `last_seen - start_time` |
| `syn_count`, `ack_count`, ... | Số lần xuất hiện mỗi TCP flag |

### Chạy test

```bash
conda activate ids

# Test riêng BT2
python -m pytest tests/test_bt2.py -v

# Test tất cả (BT1 + BT2)
python -m pytest tests/ -v
```

Kết quả: **26 passed** (12 BT1 + 14 BT2)

### Cấu trúc thư mục

```
src/
├── capture/                # BT1: bắt packet
│   └── packet_capture.py
├── parsers/                # BT1: parse protocol
│   ├── network.py          #   IPv4 header parser
│   ├── transport.py        #   TCP/UDP parser  
│   └── application.py      #   HTTP/DNS/SMTP parser
├── models/                 # BT1: chuẩn hóa output
│   └── event.py
├── decoder/                # BT2: giải mã payload
│   └── decoder.py
├── preprocessor/           # BT2: validate & normalize
│   └── preprocessor.py
├── flow_tracker/           # BT2: theo dõi connection
│   └── flow_tracker.py
├── pipeline.py             # BT1: pipeline chính
└── errors.py               # Error classes
tests/
├── test_pipeline.py        # 12 test cases BT1
└── test_bt2.py             # 14 test cases BT2
TEST/
├── test_results.md         # Kết quả BT1
└── test_results_bt2.md     # Kết quả BT2
```

### 14 Test Cases BT2

| Test | Module | Mô tả |
|------|--------|-------|
| T01 | Decoder | URL percent decoding (`%27` → `'`) |
| T02 | Decoder | HTML entity decoding (`&lt;` → `<`) |
| T03 | Decoder | SMTP Base64 decoding |
| T04 | Decoder | Invalid bytes + Quoted-Printable |
| T05 | Preprocessor | Normalization: protocol, headers, timestamp |
| T06 | Preprocessor | Missing fields: status invalid/partial |
| T07 | Flow Tracker | TCP 3-way handshake (SYN→SYN+ACK→ACK) |
| T08 | Flow Tracker | Bidirectional flow (cùng flow_id 2 chiều) |
| T09 | Flow Tracker | TCP close (FIN→CLOSING→CLOSED) |
| T10 | Flow Tracker | UDP query/response |
| T11 | Flow Tracker | Concurrent flows (3 flow đồng thời) |
| T12 | Flow Tracker | Idle timeout (flow expire) |
| T13 | Flow Tracker | Flow statistics (packet/byte count, duration) |
| T14 | Flow Tracker | Malformed events (event lỗi) |

### Ghi chú AI

Có sử dụng AI (Google Antigravity / Claude) để hỗ trợ:
- Viết code cho 3 module: Decoder, Preprocessor, Flow Tracker
- Viết 14 test cases
- Viết README giải thích chi tiết
