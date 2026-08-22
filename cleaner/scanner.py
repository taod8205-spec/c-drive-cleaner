from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import Candidate, FileFingerprint, ScanReport, ScanRule

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_reparse_point(stat_result: os.stat_result) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0)
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def _matches(filename: str, patterns: tuple[str, ...]) -> bool:
    lowered = filename.casefold()
    return any(fnmatch.fnmatchcase(lowered, pattern.casefold()) for pattern in patterns)


class CleanupScanner:
    """只读扫描器；不会打开、修改或删除候选文件。"""

    def __init__(
        self,
        rules: Iterable[ScanRule],
        *,
        now: Callable[[], datetime] | None = None,
        max_candidates: int = 50_000,
    ) -> None:
        self._rules = tuple(rule for rule in rules if rule.enabled)
        self._now = now or (lambda: datetime.now(UTC))
        self._max_candidates = max_candidates

    def scan(self) -> ScanReport:
        report = ScanReport()
        current_time = self._now()
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=UTC)

        for rule in self._rules:
            if len(report.candidates) >= self._max_candidates:
                report.warnings.append(
                    f"候选项已达到安全上限 {self._max_candidates:,}，扫描提前停止。"
                )
                break
            self._scan_rule(rule, current_time, report)

        report.candidates.sort(
            key=lambda item: (int(item.risk), -item.size_bytes, str(item.path).casefold())
        )
        return report

    def _scan_rule(
        self, rule: ScanRule, current_time: datetime, report: ScanReport
    ) -> None:
        root = rule.root
        try:
            root_stat = root.stat(follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            report.warnings.append(f"无法读取扫描源 {root}：{exc}")
            return
        if not stat.S_ISDIR(root_stat.st_mode):
            report.warnings.append(f"跳过非目录扫描源：{root}")
            return
        if stat.S_ISLNK(root_stat.st_mode) or _is_reparse_point(root_stat):
            report.warnings.append(f"为防止越界，已跳过链接或重解析点：{root}")
            return

        cutoff = current_time - timedelta(days=rule.min_age_days)
        for path, path_stat in self._walk_files(rule, report):
            report.scanned_files += 1
            modified_at = datetime.fromtimestamp(path_stat.st_mtime, UTC)
            if modified_at > cutoff:
                continue
            fingerprint = FileFingerprint.from_stat(path_stat)
            identity = (
                f"{rule.rule_id}\0{path}\0{fingerprint.size}\0"
                f"{fingerprint.modified_ns}\0{fingerprint.device}\0{fingerprint.inode}"
            )
            report.candidates.append(
                Candidate(
                    candidate_id=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
                    path=path,
                    source_root=root,
                    rule_id=rule.rule_id,
                    category=rule.category,
                    size_bytes=path_stat.st_size,
                    modified_at=modified_at,
                    risk=rule.risk,
                    reason=rule.reason,
                    fingerprint=fingerprint,
                )
            )
            if len(report.candidates) >= self._max_candidates:
                return

    def _walk_files(
        self, rule: ScanRule, report: ScanReport
    ) -> Iterator[tuple[Path, os.stat_result]]:
        pending = [rule.root]
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        path = Path(entry.path)
                        try:
                            entry_stat = entry.stat(follow_symlinks=False)
                            if entry.is_symlink() or _is_reparse_point(entry_stat):
                                report.warnings.append(
                                    f"为防止越界，已跳过链接或重解析点：{path}"
                                )
                                continue
                            if stat.S_ISDIR(entry_stat.st_mode):
                                if rule.recursive:
                                    pending.append(path)
                                continue
                            if not stat.S_ISREG(entry_stat.st_mode):
                                continue
                            if _matches(entry.name, rule.patterns):
                                yield path, entry_stat
                        except OSError as exc:
                            report.warnings.append(f"无法读取 {path}：{exc}")
            except OSError as exc:
                report.warnings.append(f"无法访问目录 {directory}：{exc}")
