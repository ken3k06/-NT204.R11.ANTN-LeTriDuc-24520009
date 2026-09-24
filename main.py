
from src.models.event import NormalizedEvent, AppProtocol, ErrorHandling, make_malformed_event

e = NormalizedEvent(packet_id=1, timestamp=1700000000.123, src_ip='10.0.0.1', dst_ip='10.0.0.2')
print(e)
print(e.to_json())

bad = make_malformed_event(2, 1700000000.5, raw=b'\x00\x01\x02')
print(bad)
print(bad.is_error)
print(bad.to_json())
