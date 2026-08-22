from __future__ import annotations

import os
import stat
from enum import Enum
from pathlib import Path
from typing import Protocol

from .models import (
    Candidate,
    CleanupItemResult,
    CleanupResult,
    DirectoryIdentity,
    FileFingerprint,
    RiskLevel,
)
from .quarantine import QuarantineStore
from .safety import (
    DirectoryChainLock,
    DirectoryLockError,
    ExactFileError,
    close_windows_handle,
    get_opened_file_identity,
    is_reparse_point,
    mark_opened_file_for_deletion,
    open_exact_windows_file,
)


class CleanupMode(Enum):
    QUARANTINE = "quarantine"
    PERMANENT = "permanent"


class RemovalBackend(Protocol):
    def quarantine(self, candidate: Candidate) -> None: ...

    def permanently_delete(self, candidate: Candidate) -> None: ...


def _is_descendant(path: Path, root: Path) -> bool:
    normalized_path = Path(os.path.abspath(path))
    normalized_root = Path(os.path.abspath(root))
    try:
        normalized_path.relative_to(normalized_root)
    except ValueError:
        return False
    return normalized_path != normalized_root


class WindowsRemovalBackend:
    """按句柄移动到安全隔离区，或在用户二次确认后永久删除。"""

    def __init__(self, quarantine_store: QuarantineStore | None = None) -> None:
        self._quarantine_store = quarantine_store or QuarantineStore()

    def quarantine(self, candidate: Candidate) -> None:
        if os.name != "nt":
            raise RuntimeError("安全隔离仅支持 Windows")

        handle = self._open_verified_candidate(candidate)
        entry = self._quarantine_store.prepare(candidate)
        try:
            self._quarantine_store.commit(entry, handle)
        except Exception:
            self._quarantine_store.discard_prepared(entry)
            raise
        finally:
            close_windows_handle(handle)

    def permanently_delete(self, candidate: Candidate) -> None:
        handle = self._open_verified_candidate(candidate)
        try:
            mark_opened_file_for_deletion(handle)
        finally:
            close_windows_handle(handle)

    @staticmethod
    def _open_verified_candidate(candidate: Candidate) -> int:
        handle = open_exact_windows_file(candidate.path)
        try:
            identity = get_opened_file_identity(handle)
            fingerprint = candidate.fingerprint
            if identity.is_reparse_point:
                raise ExactFileError("候选文件已变成重解析点")
            if (
                identity.size != fingerprint.size
                or identity.modified_ns != fingerprint.modified_ns
                or identity.file_index != fingerprint.inode
            ):
                raise ExactFileError("候选文件在最终句柄锁定前已发生变化")
        except Exception:
            close_windows_handle(handle)
            raise
        return handle


class CleanupExecutor:
    """在执行前重新验证每个候选项，避免越界和扫描后的替换竞争。"""

    def __init__(
        self,
        *,
        backend: RemovalBackend | None = None,
        protected_roots: tuple[Path, ...] = (),
        allowed_drive: str = "C:",
    ) -> None:
        self._backend = backend or WindowsRemovalBackend()
        self._protected_roots = tuple(Path(path) for path in protected_roots)
        self._allowed_drive = allowed_drive.rstrip("\\/").casefold()

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
                        candidate, False, "高风险项目禁止永久删除，只允许移到安全隔离区"
                    )
                )
                continue

            scope_error = self._validate_scope(candidate)
            if scope_error:
                result.items.append(CleanupItemResult(candidate, False, scope_error))
                continue

            try:
                with DirectoryChainLock(candidate.path.parent):
                    error = self._validate_locked(candidate)
                    if error:
                        result.items.append(CleanupItemResult(candidate, False, error))
                        continue

                    if mode is CleanupMode.QUARANTINE:
                        self._backend.quarantine(candidate)
                        message = "已移到安全隔离区"
                    else:
                        self._backend.permanently_delete(candidate)
                        message = "已永久删除"
                    result.items.append(CleanupItemResult(candidate, True, message))
            except DirectoryLockError as exc:
                result.items.append(
                    CleanupItemResult(candidate, False, f"目录安全锁失败：{exc}")
                )
            except (OSError, ValueError) as exc:
                result.items.append(
                    CleanupItemResult(candidate, False, f"操作失败：{exc}")
                )
        return result

    def _validate_scope(self, candidate: Candidate) -> str | None:
        if (
            not candidate.path.is_absolute()
            or not candidate.source_root.is_absolute()
            or not candidate.path.anchor
            or not candidate.source_root.anchor
        ):
            return "只允许清理 C 盘内的绝对路径"
        if (
            candidate.path.drive.casefold() != self._allowed_drive
            or candidate.source_root.drive.casefold() != self._allowed_drive
        ):
            return "只允许清理 C 盘内的候选文件"
        if not _is_descendant(candidate.path, candidate.source_root):
            return "路径不在允许的清理目录内"
        if any(
            _is_descendant(candidate.path, root) or candidate.path == root
            for root in self._protected_roots
        ):
            return "路径位于受保护目录内"
        return None

    def _validate_locked(self, candidate: Candidate) -> str | None:
        try:
            source_stat = candidate.source_root.stat(follow_symlinks=False)
        except FileNotFoundError:
            return "允许的清理目录已不存在"
        except OSError as exc:
            return f"无法重新验证清理目录：{exc}"
        if not stat.S_ISDIR(source_stat.st_mode):
            return "允许的清理目录类型已改变"
        if stat.S_ISLNK(source_stat.st_mode) or is_reparse_point(source_stat):
            return "允许的清理目录变成了链接或重解析点"
        if DirectoryIdentity.from_stat(source_stat) != candidate.source_root_identity:
            return "允许的清理目录在扫描后已被替换"

        normalized_path = Path(os.path.abspath(candidate.path))
        normalized_root = Path(os.path.abspath(candidate.source_root))
        relative_path = normalized_path.relative_to(normalized_root)
        current_parent = normalized_root
        for part in relative_path.parts[:-1]:
            current_parent /= part
            try:
                parent_stat = current_parent.stat(follow_symlinks=False)
            except OSError as exc:
                return f"无法重新验证父目录：{exc}"
            if not stat.S_ISDIR(parent_stat.st_mode):
                return "候选文件的父目录类型已改变"
            if stat.S_ISLNK(parent_stat.st_mode) or is_reparse_point(parent_stat):
                return "候选文件的父目录变成了链接或重解析点"
        try:
            current_stat = candidate.path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return "文件已不存在"
        except OSError as exc:
            return f"无法重新验证文件：{exc}"
        if stat.S_ISLNK(current_stat.st_mode) or is_reparse_point(current_stat):
            return "链接或重解析点不允许清理"
        if not stat.S_ISREG(current_stat.st_mode):
            return "只允许清理普通文件"
        if FileFingerprint.from_stat(current_stat) != candidate.fingerprint:
            return "文件在扫描后已发生变化，需重新扫描"
        try:
            if candidate.path.resolve(strict=True).drive.casefold() != self._allowed_drive:
                return "候选路径实际指向 C 盘以外的位置"
        except OSError as exc:
            return f"无法解析候选文件的最终路径：{exc}"
        return None
