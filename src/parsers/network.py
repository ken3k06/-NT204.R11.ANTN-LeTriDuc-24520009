from __future__ import annotations
import struct 
from typing import Optional 


from src.errors import * 



def parse_ipv4(raw:bytes) -> Optional[dict]:
    "Parse 20 bytes của IP Header"
    "RFC 791"
    if len(raw) < 1:
        raise MalformedPacketError
    '''
    Theo RFC 791 thì byte đầu tiên sẽ chứa thông tin về version và ihl 
    4 bit đầu sẽ chỉ version của IP ở đây là 4 
    4 bit cuối sẽ chỉ IHL - Internet header length 
    '''
    
    version = raw[0] >> 4 
    ihl = raw[0] & 0x0F
    if version != 4:
        return None 
    header_len = ihl * 4 
    '''
    Giá trị tối thiểu cho một header chuẩn phải là ihl = 5, cho nên nếu nó bé hơn 5 
    thì khả năng cao đó là packet lỗi. Đơn vị tính của IHL sẽ là một word.
    Một word có giá trị là 32 bits hay 4 bytes
    '''
    if ihl < 5:
        raise MalformedPacketError 
    if len(raw) < header_len:
        raise MalformedPacketError(
            f" truncated IPv4 Header ({len(raw)} < {header_len})"
        )
    (
        _ver_ihl, _tos, total_len, _id, _flags_frag, ttl, proto, _checksum, src_ip, dst_ip 
    ) = struct.unpack("!BBHHHBBH4s4s", raw[:20])
    return {
        "version" : version, 
        "header_len": header_len, 
        "tos": _tos,
        "total_len" : total_len,
        "ttl" : ttl ,
        "ip_proto": proto,
        "src_ip": ".".join(str(b) for b in src_ip), 
        "dst_ip": ".".join(str(b) for b in dst_ip), 
        "payload": raw[header_len:], 
    }
