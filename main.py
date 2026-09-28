from __future__ import annotations

import argparse
import time

from src.capture.packet_capture import iter_live, iter_pcap
from src.pipeline import process


def main() -> None:
    parser = argparse.ArgumentParser(description="Packet parser IDS")
    parser.add_argument("--interface", help="network interface để bắt live traffic")
    parser.add_argument("--pcap", help="đường dẫn file pcap")
    parser.add_argument("--output", default="events.jsonl", help="file output json lines")
    parser.add_argument("--count", type=int, default=0, help="số packet cần bắt live, 0 là không giới hạn")
    args = parser.parse_args()

    if bool(args.interface) == bool(args.pcap):
        parser.error("chọn một trong hai: --interface hoặc --pcap")

    packets = iter_pcap(args.pcap) if args.pcap else iter_live(args.interface, args.count)

    with open(args.output, "w", encoding="utf-8") as f:
        for packet_id, (raw, timestamp) in enumerate(packets, start=1):
            event = process(raw, timestamp or time.time(), packet_id)
            f.write(event.to_json() + "\n")
            print(event)


if __name__ == "__main__":
    main()
