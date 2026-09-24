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