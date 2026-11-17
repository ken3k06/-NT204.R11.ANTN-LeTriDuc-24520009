"""Module Rule Evaluation Engine: điều phối toàn bộ Core Engine.

Pipeline:
    Normalized Event + Flow Context
        -> Evaluation Engine
        -> Repository/Indexer (chọn candidate)
        -> Matching Engine (so khớp từng candidate)
        -> Detection Event

Một event có thể match nhiều rule; engine không dừng ở match đầu tiên.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.core_engine.detection_event import build_detection_event
from src.core_engine.matcher import MatchResult, match_rule
from src.core_engine.rule_repository import RuleRepository
from src.models.event import DetectionEvent


@dataclass
class EvaluationStats:
    """Thống kê tối thiểu để kiểm tra hiệu năng evaluation."""
    events_evaluated: int = 0
    candidates_total: int = 0
    matches_total: int = 0


class EvaluationEngine:
    """Nhận event + flow context, trả về danh sách DetectionEvent."""

    def __init__(self, repository: RuleRepository):
        self.repository = repository
        self.stats = EvaluationStats()

    def evaluate(self, event: dict[str, Any]) -> list[DetectionEvent]:
        """Đánh giá một event với mọi candidate rule."""
        self.stats.events_evaluated += 1

        candidates = self.repository.get_candidates(event)
        self.stats.candidates_total += len(candidates)

        detections: list[DetectionEvent] = []
        for rule in candidates:
            result: MatchResult = match_rule(rule, event)
            if result.matched:
                detections.append(build_detection_event(rule, event, result))
                self.stats.matches_total += 1

        return detections

    def evaluate_many(self, events: list[dict[str, Any]]) -> list[DetectionEvent]:
        """Đánh giá nhiều event, gom tất cả DetectionEvent lại."""
        detections: list[DetectionEvent] = []
        for event in events:
            detections.extend(self.evaluate(event))
        return detections

    def reset_stats(self) -> None:
        self.stats = EvaluationStats()

    def get_stats(self) -> dict[str, int]:
        return {
            "events_evaluated": self.stats.events_evaluated,
            "candidates_total": self.stats.candidates_total,
            "matches_total": self.stats.matches_total,
        }
