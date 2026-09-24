from src.parsers.network import parse_ipv4

# IPv4 header tối thiểu, proto=6 (TCP), src=10.0.0.1, dst=10.0.0.2
raw = bytes.fromhex('4500002800000000400600000a0000010a000002')
print(parse_ipv4(raw))

print('---')
# Packet rác (không phải IPv4)
print(parse_ipv4(b'\\x00\\x01\\x02'))

# Packet rỗng
try:
    parse_ipv4(b'')
except Exception as e:
    print('raised:', type(e).__name__, e)