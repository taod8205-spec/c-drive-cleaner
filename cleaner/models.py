from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Any


class RiskLevel(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return {
            RiskLevel.LOW: "低",
            RiskLevel.MEDIUM: "中",
            RiskLevel.HIGH: "高",
        }[self]


@dataclass(frozen=True, slots=True)
class ScanRule:
    rule_id: str
    category: str
    root: Path
    min_age_days: int
    risk: RiskLevel
    reason: str
    patterns: tuple[str, ...] = ("*",)
    recursive: bool = True
    enabled: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root))
        if not self.rule_id.strip():
            raise ValueError("rule_id 不能为空")
        if self.min_age_days < 1:
            raise ValueError("保守策略的最短保留期不能少于 1 天")
        if not self.patterns:
            raise ValueError("至少需要一个文件匹配模式")


@dataclass(frozen=True, slots=True)
class FileFingerprint:
    size: int
    modified_ns: int
    device: int
    inode: int

    @classmethod
    def from_stat(cls, value: Any) -> FileFingerprint:
        return cls(
            size=value.st_size,
            modified_ns=value.st_mtime_ns,
            device=value.st_dev,
            inode=value.st_ino,
        )


@dataclass(frozen=True, slots=True)
class Candidate:
    candidate_id: str
    path: Path
    source_root: Path
    rule_id: str
    category: str
    size_bytes: int
    modified_at: datetime
    risk: RiskLevel
    reason: str
    fingerprint: FileFingerprint

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", Path(self.path))
        object.__setattr__(self, "source_root", Path(self.source_root))


@dataclass(slots=True)
class ScanReport:
    candidates: list[Candidate] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scanned_files: int = 0

    @property
    def total_bytes(self) -> int:
        return sum(item.size_bytes for item in self.candidates)


@dataclass(frozen=True, slots=True)
class CleanupItemResult:
    candidate: Candidate
    success: bool
    message: str


@dataclass(slots=True)
class CleanupResult:
    items: list[CleanupItemResult] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return sum(item.success for item in self.items)

    @property
    def failure_count(self) -> int:
        return len(self.items) - self.success_count

    @property
    def processed_bytes(self) -> int:
        return sum(item.candidate.size_bytes for item in self.items if item.success)
