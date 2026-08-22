from __future__ import annotations

import json
import os
import shutil
import stat
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from .models import Candidate, DirectoryIdentity, FileFingerprint, RiskLevel
from .safety import (
    DirectoryChainLock,
    DirectoryLockError,
    ExactFileError,
    close_windows_handle,
    get_opened_file_identity,
    is_reparse_point,
    open_exact_windows_file,
    rename_opened_file,
)


@dataclass(frozen=True, slots=True)
class QuarantineEntry:
    entry_id: str
    original_path: Path
    stored_path: Path
    manifest_path: Path
    quarantined_at: datetime
    size_bytes: int
    category: str
    risk: RiskLevel
    reason: str
    fingerprint: FileFingerprint
    entry_dir_identity: DirectoryIdentity


class QuarantineStore:
    def __init__(
        self,
        root: Path | None = None,
        *,
        allowed_drive: str = "C:",
        environment: Mapping[str, str] | None = None,
    ) -> None:
        env = environment if environment is not None else os.environ
        local_app_data = Path(env.get("LOCALAPPDATA") or "")
        self.root = Path(root) if root is not None else local_app_data / "慎清" / "Quarantine"
        self.allowed_drive = allowed_drive.rstrip("\\/").casefold()

    def prepare(self, candidate: Candidate) -> QuarantineEntry:
        self._validate_root()
        local_base = self.root.parent.parent
        with DirectoryChainLock(local_base):
            self.root.parent.mkdir(exist_ok=True)
        with DirectoryChainLock(self.root.parent):
            self.root.mkdir(exist_ok=True)
        with DirectoryChainLock(self.root):
            entry_id = uuid.uuid4().hex
            entry_dir = self.root / entry_id
            entry_dir.mkdir()
            entry_dir_identity = DirectoryIdentity.from_stat(
                entry_dir.stat(follow_symlinks=False)
            )
            entry = QuarantineEntry(
                entry_id=entry_id,
                original_path=candidate.path,
                stored_path=entry_dir / "payload",
                manifest_path=entry_dir / "manifest.json",
                quarantined_at=datetime.now(UTC),
                size_bytes=candidate.size_bytes,
                category=candidate.category,
                risk=candidate.risk,
                reason=candidate.reason,
                fingerprint=candidate.fingerprint,
                entry_dir_identity=entry_dir_identity,
            )
            payload = {
                "version": 1,
                "entry_id": entry.entry_id,
                "original_path": str(entry.original_path),
                "stored_path": str(entry.stored_path),
                "quarantined_at": entry.quarantined_at.isoformat(),
                "size_bytes": entry.size_bytes,
                "category": entry.category,
                "risk": int(entry.risk),
                "reason": entry.reason,
                "fingerprint": asdict(entry.fingerprint),
            }
            try:
                with entry.manifest_path.open("x", encoding="utf-8") as handle:
                    json.dump(payload, handle, ensure_ascii=False, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                shutil.rmtree(entry_dir, ignore_errors=True)
                raise
            return entry

    def discard_prepared(self, entry: QuarantineEntry) -> None:
        try:
            self._validate_entry_paths(entry)
            with DirectoryChainLock(entry.manifest_path.parent):
                if not self._entry_directory_matches(entry):
                    return
                if entry.stored_path.exists():
                    return
                entry.manifest_path.unlink(missing_ok=True)
                entry.manifest_path.parent.rmdir()
        except (OSError, ValueError):
            pass

    def commit(self, entry: QuarantineEntry, handle: int) -> None:
        self._validate_entry_paths(entry)
        with DirectoryChainLock(entry.stored_path.parent):
            if not self._entry_directory_matches(entry):
                raise ExactFileError("隔离目录在准备后已发生变化")
            if os.path.lexists(entry.stored_path):
                raise FileExistsError(f"隔离目标已存在：{entry.stored_path}")
            rename_opened_file(handle, entry.stored_path)

    def list_entries(self) -> list[QuarantineEntry]:
        try:
            self._validate_root()
            with DirectoryChainLock(self.root):
                entries: list[QuarantineEntry] = []
                with os.scandir(self.root) as directories:
                    for directory in directories:
                        try:
                            directory_stat = directory.stat(follow_symlinks=False)
                            if (
                                not is_reparse_point(directory_stat)
                                and directory.is_dir(follow_symlinks=False)
                            ):
                                entry = self._read_entry(Path(directory.path))
                                if entry is not None:
                                    entries.append(entry)
                        except (OSError, ValueError, KeyError, json.JSONDecodeError):
                            continue
                entries.sort(key=lambda item: item.quarantined_at, reverse=True)
                return entries
        except (FileNotFoundError, DirectoryLockError, OSError):
            return []

    def restore(self, entry: QuarantineEntry) -> None:
        self._validate_entry_paths(entry)
        with DirectoryChainLock(entry.stored_path.parent):
            if not self._entry_directory_matches(entry):
                raise ExactFileError("隔离目录在列出后已发生变化")
            with DirectoryChainLock(entry.original_path.parent):
                if os.path.lexists(entry.original_path):
                    raise FileExistsError(
                        f"原路径已有文件，已拒绝覆盖：{entry.original_path}"
                    )
                handle = open_exact_windows_file(entry.stored_path)
                try:
                    identity = get_opened_file_identity(handle)
                    fingerprint = entry.fingerprint
                    if identity.is_reparse_point or (
                        identity.size != fingerprint.size
                        or identity.modified_ns != fingerprint.modified_ns
                        or identity.file_index != fingerprint.inode
                    ):
                        raise ExactFileError("隔离文件身份与清单不一致，已拒绝恢复")
                    rename_opened_file(handle, entry.original_path)
                finally:
                    close_windows_handle(handle)
                entry.manifest_path.unlink(missing_ok=True)
                try:
                    entry.manifest_path.parent.rmdir()
                except OSError:
                    pass

    def _read_entry(self, entry_dir: Path) -> QuarantineEntry | None:
        manifest_path = entry_dir / "manifest.json"
        with manifest_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        fingerprint = FileFingerprint(**payload["fingerprint"])
        entry_dir_stat = entry_dir.stat(follow_symlinks=False)
        entry = QuarantineEntry(
            entry_id=str(payload["entry_id"]),
            original_path=Path(payload["original_path"]),
            stored_path=Path(payload["stored_path"]),
            manifest_path=manifest_path,
            quarantined_at=datetime.fromisoformat(payload["quarantined_at"]),
            size_bytes=int(payload["size_bytes"]),
            category=str(payload["category"]),
            risk=RiskLevel(int(payload["risk"])),
            reason=str(payload["reason"]),
            fingerprint=fingerprint,
            entry_dir_identity=DirectoryIdentity.from_stat(entry_dir_stat),
        )
        self._validate_entry_paths(entry)
        return entry if entry.stored_path.is_file() else None

    def _validate_root(self) -> None:
        if (
            not self.root.is_absolute()
            or self.root.drive.casefold() != self.allowed_drive
        ):
            raise ValueError("安全隔离区必须位于 C 盘的绝对路径")

    def _validate_entry_paths(self, entry: QuarantineEntry) -> None:
        if not entry.original_path.is_absolute():
            raise ValueError("隔离清单中的原路径不是绝对路径")
        if entry.original_path.drive.casefold() != self.allowed_drive:
            raise ValueError("隔离清单中的原路径不在 C 盘")
        stored = Path(os.path.abspath(entry.stored_path))
        root = Path(os.path.abspath(self.root))
        try:
            relative = stored.relative_to(root)
        except ValueError as exc:
            raise ValueError("隔离清单中的存储路径越界") from exc
        if len(relative.parts) != 2 or relative.name != "payload":
            raise ValueError("隔离清单中的存储路径格式异常")
        if relative.parts[0] != entry.entry_id:
            raise ValueError("隔离清单中的项目编号与目录不一致")
        expected_manifest = root / entry.entry_id / "manifest.json"
        if Path(os.path.abspath(entry.manifest_path)) != expected_manifest:
            raise ValueError("隔离清单路径异常")
        try:
            stored_stat = os.stat(stored, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISREG(stored_stat.st_mode) and not is_reparse_point(stored_stat):
            return
        raise ValueError("隔离文件是链接或重解析点")

    @staticmethod
    def _entry_directory_matches(entry: QuarantineEntry) -> bool:
        try:
            current = entry.stored_path.parent.stat(follow_symlinks=False)
        except OSError:
            return False
        return (
            stat.S_ISDIR(current.st_mode)
            and not stat.S_ISLNK(current.st_mode)
            and not is_reparse_point(current)
            and DirectoryIdentity.from_stat(current) == entry.entry_dir_identity
        )
