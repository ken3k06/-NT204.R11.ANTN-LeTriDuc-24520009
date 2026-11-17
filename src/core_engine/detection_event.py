"""Module Detection Event Generator: sinh Detection Event khi rule match.

Matching Engine không tự in cảnh báo; module này chuyển kết quả match thành
DetectionEvent thống nhất để Alert/Logging/Response dùng ở bài tiếp theo.
"""
from __future__ import annotations

from src.core_engine.matcher import MatchResult
from src.core_engine.rule_parser import Rule
from src.models.event import DetectionEvent


def build_detection_event(
    rule: Rule,
    event: dict,
    match_result: MatchResult,
) -> DetectionEvent:
    """Tạo DetectionEvent từ rule + normalized event + kết quả match."""
    flow = event.get("flow") or {}

    return DetectionEvent(
        timestamp=event.get("timestamp", 0.0),
        sid=rule.sid,
        rev=rule.rev,
        msg=rule.msg,
        src_ip=event.get("src_ip"),
        dst_ip=event.get("dst_ip"),
        src_port=event.get("src_port"),
        dst_port=event.get("dst_port"),
        protocol=event.get("transport", "UNKNOWN"),
        application_protocol=event.get("app_protocol", "UNKNOWN"),
        flow_id=flow.get("flow_id"),
        packet_id=event.get("packet_id"),
        action=rule.action or "alert",
        priority=rule.priority,
        classtype=rule.classtype,
        match=dict(match_result.details),
        rule=rule.raw,
    )
