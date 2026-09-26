"""后台线程投递到界面线程的事件。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

from ..cleanup import CleanupMode
from ..models import CleanupResult, ScanReport


@dataclass(frozen=True, slots=True)
class ScanCompletedEvent:
    report: ScanReport


@dataclass(frozen=True, slots=True)
class ScanFailedEvent:
    message: str


@dataclass(frozen=True, slots=True)
class CleanupCompletedEvent:
    result: CleanupResult
    mode: CleanupMode


@dataclass(frozen=True, slots=True)
class CleanupFailedEvent:
    message: str


WorkerEvent: TypeAlias = (
    ScanCompletedEvent | ScanFailedEvent | CleanupCompletedEvent | CleanupFailedEvent
)
