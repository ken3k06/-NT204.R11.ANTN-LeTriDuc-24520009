"""Module Rule Repository / Indexer: lưu và đánh chỉ mục rule.

Chức năng:
- Chỉ giữ các rule validate hợp lệ; rule invalid/unsupported đưa vào rejected
- Đánh chỉ mục theo protocol + port (single / any / range)
- Truy vấn nhanh tập candidate rule cho một event, không duyệt toàn bộ rule
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from src.core_engine.rule_parser import Rule


class RuleRepository:
    """Kho rule đã validate, có index để chọn candidate theo header."""

    def __init__(self, rules: Optional[Iterable[Rule]] = None):
        self.rules: list[Rule] = []
        self.rejected: list[Rule] = []

        self._by_protocol: dict[str, list[Rule]] = {}
        self._by_port: dict[str, dict[int, list[Rule]]] = {}
        self._any_port: dict[str, list[Rule]] = {}
        self._ranged: dict[str, list[Rule]] = {}

        if rules:
            self.add_rules(rules)

    def add_rules(self, rules: Iterable[Rule]) -> None:
        for rule in rules:
            self.add_rule(rule)

    def add_rule(self, rule: Rule) -> None:
        """Chỉ index rule hợp lệ. Rule lỗi được giữ lại để báo cáo."""
        if not rule.is_valid:
            self.rejected.append(rule)
            return

        self.rules.append(rule)
        protocol = rule.protocol

        self._by_protocol.setdefault(protocol, []).append(rule)
        self._by_port.setdefault(protocol, {})
        self._any_port.setdefault(protocol, [])
        self._ranged.setdefault(protocol, [])

        # Một rule có thể có port ở src hoặc dst (đặc biệt với '<>')
        seen_kind = set()
        specs = []
        for spec in (rule.src_port, rule.dst_port):
            kind = _port_kind(spec)
            if kind not in seen_kind:
                seen_kind.add(kind)
                specs.append((kind, spec))

        indexed = False
        for kind, spec in specs:
            if kind == "any":
                self._any_port[protocol].append(rule)
                indexed = True
            elif kind == "single":
                self._by_port[protocol].setdefault(int(spec), []).append(rule)
                indexed = True
            else:
                # Range không expand thành từng port -> đưa vào nhóm luôn được xét
                self._ranged[protocol].append(rule)
                indexed = True
        if not indexed:
            self._any_port[protocol].append(rule)

    def get_candidates(self, event: dict[str, Any]) -> list[Rule]:
        """Chọn rule theo protocol + port của event (lọc nhanh bằng header)."""
        protocol = str(event.get("transport", "")).lower()
        if protocol not in self._by_protocol:
            return []

        candidates: dict[int, Rule] = {}

        def collect(group: list[Rule]) -> None:
            for rule in group:
                candidates[id(rule)] = rule

        for field in ("dst_port", "src_port"):
            port = event.get(field)
            if isinstance(port, int):
                collect(self._by_port.get(protocol, {}).get(port, []))
        collect(self._any_port.get(protocol, []))
        collect(self._ranged.get(protocol, []))

        return list(candidates.values())

    def get_by_sid(self, sid: int) -> list[Rule]:
        """Lấy rule theo sid (có thể trùng sid khi nhiều file)."""
        return [r for r in self.rules if r.sid == sid]

    def get_stats(self) -> dict[str, Any]:
        """Thống kê kho rule: tổng số, theo trạng thái và theo protocol."""
        return {
            "total_rules": len(self.rules) + len(self.rejected),
            "valid_rules": len(self.rules),
            "rejected_rules": len(self.rejected),
            "by_protocol": {
                proto: len(rules) for proto, rules in self._by_protocol.items()
            },
        }


# === Hàm phụ trợ ===

def _port_kind(spec: str) -> str:
    """Phân loại port spec: any | single | range."""
    text = str(spec).strip().lower()
    if text == "any":
        return "any"
    if ":" in text:
        return "range"
    return "single"
