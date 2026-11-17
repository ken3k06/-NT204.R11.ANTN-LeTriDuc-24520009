"""Facade CoreEngine: nối Rule Loader -> Repository -> Evaluation Engine.

Dùng ở main.py hoặc ở bài Alert/Logging/Response sau này.
"""
from __future__ import annotations

from typing import Any, Optional

from src.core_engine.evaluator import EvaluationEngine
from src.core_engine.rule_loader import LoaderConfig, LoadResult, load_rules
from src.core_engine.rule_repository import RuleRepository
from src.models.event import DetectionEvent


class CoreEngine:
    """Khởi tạo một lần từ file rule, sau đó process() cho từng event."""

    def __init__(
        self,
        rule_paths: str | list[str],
        config: Optional[LoaderConfig] = None,
        verbose: bool = False,
    ):
        self.load_result: LoadResult = load_rules(rule_paths, config, verbose=verbose)
        self.repository = RuleRepository(self.load_result.rules)
        self.evaluator = EvaluationEngine(self.repository)

    def process(self, event: dict[str, Any]) -> list[DetectionEvent]:
        """Đánh giá một normalized event (đã có flow context)."""
        return self.evaluator.evaluate(event)

    def get_stats(self) -> dict[str, Any]:
        """Gồm thống kê nạp rule, kho rule và evaluation."""
        stats: dict[str, Any] = {}
        stats.update(self.evaluator.get_stats())
        stats.update(self.repository.get_stats())
        stats["loaded_files"] = len(self.load_result.loaded_files)
        stats["load_warnings"] = len(self.load_result.warnings)
        return stats
