from __future__ import annotations

import argparse
import json
import time

from src.capture.packet_capture import iter_live, iter_pcap
from src.decoder.decoder import decode_event
from src.flow_tracker.flow_tracker import FlowTracker
from src.pipeline import process
from src.preprocessor.preprocessor import preprocess_event


def main() -> None:
    parser = argparse.ArgumentParser(description="Packet parser & IDS Processor (BT1 + BT2)")
    parser.add_argument("--interface", help="network interface để bắt live traffic (ví dụ: wlp8s0, lo)")
    parser.add_argument("--pcap", help="đường dẫn file pcap")
    parser.add_argument("--output", default="events.jsonl", help="file output json lines")
    parser.add_argument("--count", type=int, default=0, help="số packet cần bắt live, 0 là không giới hạn")
    parser.add_argument("--tcp-timeout", type=float, default=300.0, help="TCP idle timeout (giây)")
    parser.add_argument("--udp-timeout", type=float, default=30.0, help="UDP idle timeout (giây)")
    args = parser.parse_args()

    if bool(args.interface) == bool(args.pcap):
        parser.error("chọn một trong hai: --interface hoặc --pcap")

    packets = iter_pcap(args.pcap) if args.pcap else iter_live(args.interface, args.count)
    tracker = FlowTracker(tcp_timeout=args.tcp_timeout, udp_timeout=args.udp_timeout)

    print(f"[*] Bắt đầu xử lý traffic -> Ghi kết quả vào: {args.output}")

    with open(args.output, "w", encoding="utf-8") as f:
        for packet_id, (raw, timestamp) in enumerate(packets, start=1):
            ts = timestamp or time.time()
            
            # 1. Packet Parser (Bài tập 1)
            event = process(raw, ts, packet_id)
            event_dict = event.to_dict()

            # 2. Decoder (Bài tập 2)
            event_dict = decode_event(event_dict)

            # 3. Preprocessor (Bài tập 2)
            event_dict = preprocess_event(event_dict)

            # 4. Flow Tracker (Bài tập 2)
            event_dict = tracker.process_event(event_dict)

            # Ghi ra file JSONL
            f.write(json.dumps(event_dict, ensure_ascii=False) + "\n")

            # In thông tin tóm tắt ra màn hình terminal
            flow_info = event_dict.get("flow")
            flow_state = flow_info.get("state") if flow_info else "N/A"
            flow_id = flow_info.get("flow_id", "N/A")[:8] if flow_info else "N/A"
            prep_status = event_dict.get("preprocess_status", "N/A")

            print(
                f"{event} | Status: {prep_status:<7} | Flow [{flow_id}]: {flow_state}"
            )

    print(f"\n[*] Hoàn tất. Thống kê flow:")
    summary = tracker.get_summary()
    print(f"    - Active flows:  {summary['active_flows']}")
    print(f"    - Expired flows: {summary['expired_flows']}")
    print(f"    - TCP flows:     {summary['tcp_flows']}")
    print(f"    - UDP flows:     {summary['udp_flows']}")


if __name__ == "__main__":
    main()
