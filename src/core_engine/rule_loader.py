"""Module Rule Loader: nạp rule từ file .rules.

Chức năng:
- Đọc một hoặc nhiều file .rules, bỏ dòng trống / comment
- Cho phép enable/disable rule (theo sid) hoặc file rule bằng cấu hình
- Một rule lỗi không làm dừng việc nạp các rule khác (ghi cảnh báo)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.core_engine.rule_parser import Rule, parse_rule


@dataclass
class LoaderConfig:
    """Cấu hình bật/tắt rule hoặc file rule."""
    enabled_files: Optional[list[str]] = None      # None = nạp tất cả
    disabled_files: list[str] = field(default_factory=list)
    enabled_sids: Optional[set[int]] = None        # None = nạp tất cả sid
    disabled_sids: set[int] = field(default_factory=set)


@dataclass
class LoadResult:
    """Kết quả sau khi nạp rule."""
    rules: list[Rule] = field(default_factory=list)
    loaded_files: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    line_count: int = 0                 # số dòng rule (sau khi bỏ comment/blank)
    warnings: list[str] = field(default_factory=list)

    @property
    def valid_rules(self) -> list[Rule]:
        return [r for r in self.rules if r.is_valid]


def load_rules(
    paths: str | list[str],
    config: Optional[LoaderConfig] = None,
    verbose: bool = False,
) -> LoadResult:
    """Nạp rule từ file hoặc thư mục chứa file .rules.

    Trả về LoadResult. Mọi lỗi đều được ghi vào warnings và tiếp tục nạp.
    """
    config = config or LoaderConfig()
    result = LoadResult()

    for path in _collect_rule_files(paths):
        name = str(path)
        if path.name in config.disabled_files or name in config.disabled_files:
            result.skipped_files.append(name)
            _warn(result, verbose, f"disabled rule file: {name}")
            continue
        if config.enabled_files is not None:
            if path.name not in config.enabled_files and name not in config.enabled_files:
                result.skipped_files.append(name)
                _warn(result, verbose, f"rule file not enabled: {name}")
                continue

        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            _warn(result, verbose, f"cannot read {name}: {exc}")
            continue

        result.loaded_files.append(name)
        for line_no, line in enumerate(lines, start=1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue

            # enabled_sids là whitelist: nếu có thì chỉ giữ các sid này
            sid = _peek_sid(text)
            if sid is not None:
                if sid in config.disabled_sids:
                    _warn(result, verbose, f"disabled sid {sid} at {name}:{line_no}")
                    continue
                if config.enabled_sids is not None and sid not in config.enabled_sids:
                    continue

            result.line_count += 1
            rule = parse_rule(text)
            if not rule.is_valid:
                _warn(
                    result,
                    verbose,
                    f"{name}:{line_no}: [{rule.status}] {rule.reason}",
                )
            result.rules.append(rule)

    return result


# === Các hàm phụ trợ ===

def _collect_rule_files(paths: str | list[str]) -> list[Path]:
    """Chuẩn hóa input: nhận file, thư mục hoặc danh sách."""
    if isinstance(paths, str):
        paths = [paths]
    files: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            files.extend(sorted(path.glob("*.rules")))
        else:
            files.append(path)
    return files


def _peek_sid(text: str) -> Optional[int]:
    """Lấy sid thô để lọc enable/disable trước khi parse đầy đủ."""
    for part in text.split(";"):
        part = part.strip()
        if part.lower().startswith("sid:"):
            try:
                return int(part[4:].strip())
            except ValueError:
                return None
    return None


def _warn(result: LoadResult, verbose: bool, message: str) -> None:
    result.warnings.append(message)
    if verbose:
        print(f"[!] {message}")
