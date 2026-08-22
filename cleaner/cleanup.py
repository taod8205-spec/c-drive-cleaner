from __future__ import annotations

import ctypes
import os
import stat
from enum import Enum
from pathlib import Path
from typing import Protocol

from .models import (
    Candidate,
    CleanupItemResult,
    CleanupResult,
    FileFingerprint,
    RiskLevel,
)
from .scanner import _is_reparse_point


class CleanupMode(Enum):
    RECYCLE = "recycle"
    PERMANENT = "permanent"


class RemovalBackend(Protocol):
    def recycle(self, path: Path) -> None: ...

    def permanently_delete(self, path: Path) -> None: ...


def _is_descendant(path: Path, root: Path) -> bool:
    normalized_path = Path(os.path.abspath(path))
    normalized_root = Path(os.path.abspath(root))
    try:
        normalized_path.relative_to(normalized_root)
    except ValueError:
        return False
    return normalized_path != normalized_root


class WindowsRemovalBackend:
    """使用 Windows 回收站，或在用户二次确认后永久删除普通文件。"""

    def recycle(self, path: Path) -> None:
        if os.name != "nt":
            raise RuntimeError("移动到回收站仅支持 Windows")

        class SHFILEOPSTRUCTW(ctypes.Structure):
            _fields_ = [
                ("hwnd", ctypes.c_void_p),
                ("wFunc", ctypes.c_uint),
                ("pFrom", ctypes.c_wchar_p),
                ("pTo", ctypes.c_wchar_p),
                ("fFlags", ctypes.c_ushort),
                ("fAnyOperationsAborted", ctypes.c_int),
                ("hNameMappings", ctypes.c_void_p),
                ("lpszProgressTitle", ctypes.c_wchar_p),
            ]

        operation = SHFILEOPSTRUCTW()
        operation.wFunc = 3  # FO_DELETE
        operation.pFrom = f"{path}\0\0"
        operation.fFlags = 0x0040 | 0x0010 | 0x0004 | 0x0400
        result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(operation))
        if result != 0:
            raise OSError(result, "Windows 无法把文件移到回收站", str(path))
        if operation.fAnyOperationsAborted:
            raise OSError("回收操作已取消")

    def permanently_delete(self, path: Path) -> None:
        path.unlink()


class CleanupExecutor:
    """在执行前重新验证每个候选项，避免越界和扫描后的替换竞争。"""

    def __init__(
        self,
        *,
        backend: RemovalBackend | None = None,
        protected_roots: tuple[Path, ...] = (),
    ) -> None:
        self._backend = backend or WindowsRemovalBackend()
        self._protected_roots = tuple(Path(path) for path in protected_roots)

    def execute(
        self, candidates: list[Candidate], *, mode: CleanupMode
    ) -> CleanupResult:
        result = CleanupResult()
        seen_ids: set[str] = set()
        for candidate in candidates:
            if candidate.candidate_id in seen_ids:
                result.items.append(
                    CleanupItemResult(candidate, False, "重复候选项已拒绝")
                )
                continue
            seen_ids.add(candidate.candidate_id)

            if mode is CleanupMode.PERMANENT and candidate.risk is RiskLevel.HIGH:
                result.items.append(
                    CleanupItemResult(
                        candidate, False, "高风险项目禁止永久删除，只允许移到回收站"
                    )
                )
                continue

            error = self._validate(candidate)
            if error:
                result.items.append(CleanupItemResult(candidate, False, error))
                continue

            try:
                if mode is CleanupMode.RECYCLE:
                    self._backend.recycle(candidate.path)
                    message = "已移到回收站"
                else:
                    self._backend.permanently_delete(candidate.path)
                    message = "已永久删除"
                result.items.append(CleanupItemResult(candidate, True, message))
            except OSError as exc:
                result.items.append(
                    CleanupItemResult(candidate, False, f"操作失败：{exc}")
                )
        return result

    def _validate(self, candidate: Candidate) -> str | None:
        if not _is_descendant(candidate.path, candidate.source_root):
            return "路径不在允许的清理目录内"
        if any(
            _is_descendant(candidate.path, root) or candidate.path == root
            for root in self._protected_roots
        ):
            return "路径位于受保护目录内"
        try:
            current_stat = candidate.path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return "文件已不存在"
        except OSError as exc:
            return f"无法重新验证文件：{exc}"
        if stat.S_ISLNK(current_stat.st_mode) or _is_reparse_point(current_stat):
            return "链接或重解析点不允许清理"
        if not stat.S_ISREG(current_stat.st_mode):
            return "只允许清理普通文件"
        if FileFingerprint.from_stat(current_stat) != candidate.fingerprint:
            return "文件在扫描后已发生变化，需重新扫描"
        return None
