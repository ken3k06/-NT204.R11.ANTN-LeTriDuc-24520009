from src.pipeline import process

raw = bytes.fromhex('450000540bec400040015bfec0a8020708080808')
event = process(raw, timestamp=1700000000.0, packet_id=1)
print(event)
print(event.to_json())
