from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import Candidate, DirectoryIdentity, FileFingerprint, ScanReport, ScanRule
from .safety import DirectoryChainLock, DirectoryLockError, is_reparse_point


def _matches(filename: str, patterns: tuple[str, ...]) -> bool:
    """文件名匹配；patterns 必须已完成 casefold。"""
    lowered = filename.casefold()
    return any(fnmatch.fnmatchcase(lowered, pattern) for pattern in patterns)


class CleanupScanner:
    """只读扫描器；不会打开、修改或删除候选文件。"""

    def __init__(
        self,
        rules: Iterable[ScanRule],
        *,
        now: Callable[[], datetime] | None = None,
        max_candidates: int = 50_000,
        allowed_drive: str = "C:",
    ) -> None:
        self._rules = tuple(rule for rule in rules if rule.enabled)
        self._now = now or (lambda: datetime.now(UTC))
        self._max_candidates = max_candidates
        self._allowed_drive = allowed_drive.rstrip("\\/").casefold()

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

    def _scan_rule(self, rule: ScanRule, current_time: datetime, report: ScanReport) -> None:
        root = rule.root
        if not root.is_absolute() or root.drive.casefold() != self._allowed_drive:
            report.warnings.append(f"已跳过非 C 盘绝对扫描源：{root}")
            return
        try:
            with DirectoryChainLock(root):
                root_stat = root.stat(follow_symlinks=False)
                if not stat.S_ISDIR(root_stat.st_mode):
                    report.warnings.append(f"跳过非目录扫描源：{root}")
                    return
                if stat.S_ISLNK(root_stat.st_mode) or is_reparse_point(root_stat):
                    report.warnings.append(f"为防止越界，已跳过链接或重解析点：{root}")
                    return

                cutoff = current_time - timedelta(days=rule.min_age_days)
                source_root_identity = DirectoryIdentity.from_stat(root_stat)
                lowered_patterns = tuple(pattern.casefold() for pattern in rule.patterns)
                for path, path_stat in self._walk_files(rule, lowered_patterns, report):
                    report.scanned_files += 1
                    modified_at = datetime.fromtimestamp(path_stat.st_mtime, UTC)
                    if modified_at > cutoff:
                        continue
                    fingerprint = FileFingerprint.from_stat(path_stat)
                    identity = (
                        f"{rule.rule_id}\0{path}\0{fingerprint.size}\0"
                        f"{fingerprint.modified_ns}\0{fingerprint.device}\0"
                        f"{fingerprint.inode}"
                    )
                    report.candidates.append(
                        Candidate(
                            candidate_id=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
                            path=path,
                            source_root=root,
                            source_root_identity=source_root_identity,
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
        except DirectoryLockError as exc:
            if exc.errno in (2, 3):
                return
            report.warnings.append(f"为防止越界，已跳过扫描源 {root}：{exc}")

    def _walk_files(
        self, rule: ScanRule, patterns: tuple[str, ...], report: ScanReport
    ) -> Iterator[tuple[Path, os.stat_result]]:
        pending = [rule.root]
        while pending:
            directory = pending.pop()
            try:
                with DirectoryChainLock(directory):
                    directory_stat = directory.stat(follow_symlinks=False)
                    if not stat.S_ISDIR(directory_stat.st_mode):
                        report.warnings.append(f"扫描期间目录类型已改变，已跳过：{directory}")
                        continue
                    if stat.S_ISLNK(directory_stat.st_mode) or is_reparse_point(directory_stat):
                        report.warnings.append(f"扫描期间检测到链接或重解析点，已跳过：{directory}")
                        continue
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            path = Path(entry.path)
                            try:
                                entry_stat = os.stat(entry.path, follow_symlinks=False)
                                if entry.is_symlink() or is_reparse_point(entry_stat):
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
                                if _matches(entry.name, patterns):
                                    yield path, entry_stat
                            except OSError as exc:
                                report.warnings.append(f"无法读取 {path}：{exc}")
            except DirectoryLockError as exc:
                report.warnings.append(f"为防止越界，已跳过目录 {directory}：{exc}")
            except OSError as exc:
                report.warnings.append(f"无法访问目录 {directory}：{exc}")
