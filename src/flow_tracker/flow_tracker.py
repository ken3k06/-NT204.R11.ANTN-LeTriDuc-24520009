"""Module Flow/Connection Tracker: theo dõi luồng kết nối.

Chức năng:
- Nhận diện flow 2 chiều bằng 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
- TCP state tracking: NEW -> HANDSHAKE -> ESTABLISHED -> CLOSING -> CLOSED/RESET
- UDP flow tracking theo bidirectional 5-tuple
- Idle timeout: tự động đẩy flow hết hạn
- Thống kê flow: packet_count, byte_count, duration, TCP flag counters
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

# Timeout mặc định (giây)
TCP_IDLE_TIMEOUT = 300      # 5 phút
UDP_IDLE_TIMEOUT = 30       # 30 giây


@dataclass
class FlowStats:
    """Thống kê cho một flow."""
    packet_count: int = 0
    byte_count: int = 0
    
    # Thống kê theo hướng
    forward_packets: int = 0
    forward_bytes: int = 0
    backward_packets: int = 0
    backward_bytes: int = 0
    
    # Thời gian
    start_time: Optional[float] = None
    last_seen: Optional[float] = None
    
    # TCP flag counters
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0

    @property
    def duration(self) -> float:
        """Thời gian tồn tại của flow (giây)."""
        if self.start_time is not None and self.last_seen is not None:
            return self.last_seen - self.start_time
        return 0.0


@dataclass
class Flow:
    """Một flow/connection trong hệ thống."""
    flow_id: str                    # ID ổn định cho cả 2 chiều
    src_ip: str                     # IP khởi tạo flow (gói đầu tiên)
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str                   # TCP hoặc UDP
    state: str = "NEW"              # Trạng thái hiện tại
    stats: FlowStats = field(default_factory=FlowStats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "state": self.state,
            "packet_count": self.stats.packet_count,
            "byte_count": self.stats.byte_count,
            "forward_packets": self.stats.forward_packets,
            "forward_bytes": self.stats.forward_bytes,
            "backward_packets": self.stats.backward_packets,
            "backward_bytes": self.stats.backward_bytes,
            "start_time": self.stats.start_time,
            "last_seen": self.stats.last_seen,
            "duration": self.stats.duration,
            "syn_count": self.stats.syn_count,
            "ack_count": self.stats.ack_count,
            "fin_count": self.stats.fin_count,
            "rst_count": self.stats.rst_count,
            "psh_count": self.stats.psh_count,
        }


def _make_flow_id(ip_a: str, port_a: int, ip_b: str, port_b: int, protocol: str) -> str:
    """Tạo flow_id ổn định cho cả 2 chiều.
    
    Sắp xếp 2 endpoint để A->B và B->A có cùng flow_id.
    """
    endpoint_a = f"{ip_a}:{port_a}"
    endpoint_b = f"{ip_b}:{port_b}"
    
    # Sắp xếp để đảm bảo thứ tự nhất quán
    if endpoint_a > endpoint_b:
        endpoint_a, endpoint_b = endpoint_b, endpoint_a
    
    raw = f"{endpoint_a}-{endpoint_b}-{protocol}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


class FlowTracker:
    """Quản lý tất cả các flow đang active."""

    def __init__(
        self,
        tcp_timeout: float = TCP_IDLE_TIMEOUT,
        udp_timeout: float = UDP_IDLE_TIMEOUT,
    ):
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.active_flows: dict[str, Flow] = {}     # flow_id -> Flow
        self.expired_flows: list[Flow] = []          # Các flow đã hết hạn

    def process_event(self, event_dict: dict[str, Any]) -> dict[str, Any]:
        """Xử lý một event và cập nhật flow tracking.
        
        Thêm trường 'flow' vào event_dict chứa thông tin flow.
        """
        # Kiểm tra event có đủ thông tin để track không
        src_ip = event_dict.get("src_ip")
        dst_ip = event_dict.get("dst_ip")
        src_port = event_dict.get("src_port")
        dst_port = event_dict.get("dst_port")
        transport = event_dict.get("transport", "UNKNOWN")
        timestamp = event_dict.get("timestamp", 0.0)
        payload_len = event_dict.get("payload_len", 0)

        if not all([src_ip, dst_ip, transport in ("TCP", "UDP")]):
            event_dict["flow"] = None
            return event_dict

        # Nếu port bị None thì gán 0
        src_port = src_port if src_port is not None else 0
        dst_port = dst_port if dst_port is not None else 0

        # Cleanup expired flows trước
        self._cleanup_expired(timestamp)

        # Tạo flow_id
        flow_id = _make_flow_id(src_ip, src_port, dst_ip, dst_port, transport)

        # Lấy hoặc tạo flow mới
        if flow_id in self.active_flows:
            flow = self.active_flows[flow_id]
            is_forward = (src_ip == flow.src_ip and src_port == flow.src_port)
        else:
            # Flow mới - gói đầu tiên xác định hướng forward
            flow = Flow(
                flow_id=flow_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=transport,
                state="NEW",
            )
            flow.stats.start_time = timestamp
            self.active_flows[flow_id] = flow
            is_forward = True

        # Cập nhật thống kê
        flow.stats.packet_count += 1
        flow.stats.byte_count += payload_len
        flow.stats.last_seen = timestamp

        if is_forward:
            flow.stats.forward_packets += 1
            flow.stats.forward_bytes += payload_len
        else:
            flow.stats.backward_packets += 1
            flow.stats.backward_bytes += payload_len

        # Cập nhật TCP flag counters và state
        if transport == "TCP":
            tcp_flags = event_dict.get("tcp_flags", {})
            if tcp_flags:
                self._update_tcp_flags(flow, tcp_flags)
                self._update_tcp_state(flow, tcp_flags, is_forward)
        elif transport == "UDP":
            # UDP: chuyển sang ESTABLISHED khi có gói backward
            if flow.state == "NEW" and not is_forward:
                flow.state = "ESTABLISHED"

        # Thêm thông tin flow vào event
        event_dict["flow"] = flow.to_dict()
        return event_dict

    def _update_tcp_flags(self, flow: Flow, tcp_flags: dict[str, int]) -> None:
        """Cập nhật bộ đếm TCP flags."""
        flow.stats.syn_count += tcp_flags.get("SYN", 0)
        flow.stats.ack_count += tcp_flags.get("ACK", 0)
        flow.stats.fin_count += tcp_flags.get("FIN", 0)
        flow.stats.rst_count += tcp_flags.get("RST", 0)
        flow.stats.psh_count += tcp_flags.get("PSH", 0)

    def _update_tcp_state(self, flow: Flow, tcp_flags: dict[str, int], is_forward: bool) -> None:
        """Cập nhật trạng thái TCP connection.
        
        State machine:
        NEW -> HANDSHAKE -> ESTABLISHED -> CLOSING -> CLOSED/RESET
        """
        syn = tcp_flags.get("SYN", 0)
        ack = tcp_flags.get("ACK", 0)
        fin = tcp_flags.get("FIN", 0)
        rst = tcp_flags.get("RST", 0)

        # RST -> RESET ngay lập tức
        if rst:
            flow.state = "RESET"
            return

        if flow.state == "NEW":
            # SYN -> đang handshake
            if syn and not ack:
                flow.state = "HANDSHAKE"
            # SYN+ACK -> đã nhận SYN-ACK (bước 2 của 3-way handshake)
            elif syn and ack:
                flow.state = "HANDSHAKE"

        elif flow.state == "HANDSHAKE":
            # ACK thuần (không SYN, không FIN) -> hoàn tất handshake
            if ack and not syn and not fin:
                flow.state = "ESTABLISHED"
            # SYN+ACK -> vẫn đang handshake
            elif syn and ack:
                flow.state = "HANDSHAKE"

        elif flow.state == "ESTABLISHED":
            # FIN -> bắt đầu đóng
            if fin:
                flow.state = "CLOSING"

        elif flow.state == "CLOSING":
            # FIN+ACK hoặc ACK cuối -> đóng hoàn toàn
            if fin or (ack and not syn):
                flow.state = "CLOSED"

    def _cleanup_expired(self, current_time: float) -> None:
        """Xóa các flow đã hết idle timeout."""
        expired_ids = []
        for flow_id, flow in self.active_flows.items():
            if flow.stats.last_seen is None:
                continue
            
            timeout = self.tcp_timeout if flow.protocol == "TCP" else self.udp_timeout
            idle_time = current_time - flow.stats.last_seen
            
            if idle_time > timeout:
                expired_ids.append(flow_id)

        for flow_id in expired_ids:
            flow = self.active_flows.pop(flow_id)
            flow.state = "EXPIRED"
            self.expired_flows.append(flow)

    def get_active_flows(self) -> list[dict[str, Any]]:
        """Lấy danh sách tất cả flow đang active."""
        return [f.to_dict() for f in self.active_flows.values()]

    def get_expired_flows(self) -> list[dict[str, Any]]:
        """Lấy danh sách các flow đã expired."""
        return [f.to_dict() for f in self.expired_flows]

    def get_flow_by_id(self, flow_id: str) -> Optional[dict[str, Any]]:
        """Lấy thông tin một flow theo ID."""
        flow = self.active_flows.get(flow_id)
        if flow:
            return flow.to_dict()
        # Tìm trong expired
        for f in self.expired_flows:
            if f.flow_id == flow_id:
                return f.to_dict()
        return None

    def get_summary(self) -> dict[str, Any]:
        """Tổng quan về tình trạng tracking."""
        return {
            "active_flows": len(self.active_flows),
            "expired_flows": len(self.expired_flows),
            "total_flows": len(self.active_flows) + len(self.expired_flows),
            "tcp_flows": sum(1 for f in self.active_flows.values() if f.protocol == "TCP"),
            "udp_flows": sum(1 for f in self.active_flows.values() if f.protocol == "UDP"),
        }
