from __future__ import annotations

import json
import os
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
    mark_opened_file_for_deletion,
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


@dataclass(slots=True)
class QuarantineReport:
    entries: list[QuarantineEntry]
    warnings: list[str]


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
                with DirectoryChainLock(entry_dir):
                    if not self._entry_directory_matches(entry):
                        raise ExactFileError("隔离目录在创建后已发生变化")
                    with entry.manifest_path.open("x", encoding="utf-8") as handle:
                        json.dump(payload, handle, ensure_ascii=False, indent=2)
                        handle.flush()
                        os.fsync(handle.fileno())
            except Exception:
                self.discard_prepared(entry)
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

    def inspect_entries(self) -> QuarantineReport:
        self._validate_root()
        try:
            root_stat = os.stat(self.root, follow_symlinks=False)
        except FileNotFoundError:
            return QuarantineReport([], [])
        if not stat.S_ISDIR(root_stat.st_mode) or is_reparse_point(root_stat):
            raise DirectoryLockError("安全隔离区不是普通目录")

        entries: list[QuarantineEntry] = []
        warnings: list[str] = []
        with DirectoryChainLock(self.root):
            with os.scandir(self.root) as directories:
                for directory in directories:
                    entry_dir = Path(directory.path)
                    try:
                        directory_stat = os.stat(
                            directory.path, follow_symlinks=False
                        )
                        if (
                            not stat.S_ISDIR(directory_stat.st_mode)
                            or is_reparse_point(directory_stat)
                        ):
                            raise ValueError("项目目录是链接、重解析点或非目录")
                        expected_identity = DirectoryIdentity.from_stat(directory_stat)
                        with DirectoryChainLock(entry_dir):
                            current_stat = entry_dir.stat(follow_symlinks=False)
                            if (
                                DirectoryIdentity.from_stat(current_stat)
                                != expected_identity
                            ):
                                raise ExactFileError("项目目录在读取前已发生变化")
                            entry = self._read_entry(entry_dir)
                        if entry is not None:
                            entries.append(entry)
                    except (
                        OSError,
                        ValueError,
                        KeyError,
                        TypeError,
                        OverflowError,
                        json.JSONDecodeError,
                    ) as exc:
                        warnings.append(f"无法读取隔离项目 {entry_dir}：{exc}")
        entries.sort(key=lambda item: item.quarantined_at, reverse=True)
        return QuarantineReport(entries, warnings)

    def list_entries(self) -> list[QuarantineEntry]:
        return self.inspect_entries().entries

    def restore(self, entry: QuarantineEntry) -> str | None:
        self._validate_entry_paths(entry)
        with DirectoryChainLock(entry.stored_path.parent):
            if not self._entry_directory_matches(entry):
                raise ExactFileError("隔离目录在列出后已发生变化")
            with DirectoryChainLock(entry.original_path.parent):
                if os.path.lexists(entry.original_path):
                    raise FileExistsError(
                        f"原路径已有文件，已拒绝覆盖：{entry.original_path}"
                    )
                handle = self._open_verified_entry(entry)
                try:
                    rename_opened_file(handle, entry.original_path)
                finally:
                    close_windows_handle(handle)
                return self._cleanup_metadata(entry)

    def permanently_delete(self, entry: QuarantineEntry) -> str | None:
        if entry.risk is RiskLevel.HIGH:
            raise ValueError("高风险隔离项目禁止永久删除")
        self._validate_entry_paths(entry)
        with DirectoryChainLock(entry.stored_path.parent):
            if not self._entry_directory_matches(entry):
                raise ExactFileError("隔离目录在列出后已发生变化")
            handle = self._open_verified_entry(entry)
            try:
                mark_opened_file_for_deletion(handle)
            finally:
                close_windows_handle(handle)
            return self._cleanup_metadata(entry)

    def _read_entry(self, entry_dir: Path) -> QuarantineEntry:
        manifest_path = entry_dir / "manifest.json"
        manifest_stat = os.stat(manifest_path, follow_symlinks=False)
        if (
            not stat.S_ISREG(manifest_stat.st_mode)
            or is_reparse_point(manifest_stat)
            or manifest_stat.st_size > 65_536
        ):
            raise ValueError("隔离清单不是普通小型文件")
        with manifest_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if (
            not isinstance(payload, Mapping)
            or type(payload.get("version")) is not int
            or payload.get("version") != 1
        ):
            raise ValueError("隔离清单格式或版本无效")
        fingerprint_payload = payload["fingerprint"]
        if not isinstance(fingerprint_payload, Mapping):
            raise TypeError("隔离清单中的文件身份格式无效")
        fingerprint_values = {
            name: fingerprint_payload[name]
            for name in ("size", "modified_ns", "device", "inode")
        }
        if any(type(value) is not int for value in fingerprint_values.values()):
            raise TypeError("隔离清单中的文件身份必须是整数")
        if (
            fingerprint_values["size"] < 0
            or fingerprint_values["modified_ns"] < 0
            or fingerprint_values["device"] < 0
            or fingerprint_values["inode"] <= 0
        ):
            raise ValueError("隔离清单中的文件身份超出有效范围")
        fingerprint = FileFingerprint(**fingerprint_values)
        size_bytes = payload["size_bytes"]
        if type(size_bytes) is not int or not 0 <= size_bytes <= (2**63 - 1):
            raise ValueError("隔离清单中的文件大小超出有效范围")
        if size_bytes != fingerprint.size:
            raise ValueError("隔离清单中的文件大小与身份不一致")
        timestamp = payload["quarantined_at"]
        if not isinstance(timestamp, str):
            raise TypeError("隔离时间必须是带时区的文本")
        quarantined_at = datetime.fromisoformat(timestamp)
        if quarantined_at.tzinfo is None or quarantined_at.utcoffset() is None:
            raise ValueError("隔离时间缺少时区")
        for field in ("entry_id", "original_path", "stored_path", "category", "reason"):
            if not isinstance(payload[field], str):
                raise TypeError(f"隔离清单字段 {field} 必须是文本")
        risk_value = payload["risk"]
        if type(risk_value) is not int:
            raise TypeError("隔离清单中的风险等级必须是整数")
        entry_dir_stat = entry_dir.stat(follow_symlinks=False)
        entry = QuarantineEntry(
            entry_id=payload["entry_id"],
            original_path=Path(payload["original_path"]),
            stored_path=Path(payload["stored_path"]),
            manifest_path=manifest_path,
            quarantined_at=quarantined_at,
            size_bytes=size_bytes,
            category=payload["category"],
            risk=RiskLevel(risk_value),
            reason=payload["reason"],
            fingerprint=fingerprint,
            entry_dir_identity=DirectoryIdentity.from_stat(entry_dir_stat),
        )
        self._validate_entry_paths(entry)
        if not entry.stored_path.is_file():
            raise FileNotFoundError("隔离清单存在，但 payload 文件缺失")
        return entry

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
    def _open_verified_entry(entry: QuarantineEntry) -> int:
        handle = open_exact_windows_file(entry.stored_path)
        try:
            identity = get_opened_file_identity(handle)
            fingerprint = entry.fingerprint
            if identity.is_reparse_point or (
                identity.size != fingerprint.size
                or identity.modified_ns != fingerprint.modified_ns
                or identity.file_index != fingerprint.inode
            ):
                raise ExactFileError("隔离文件身份与清单不一致")
        except Exception:
            close_windows_handle(handle)
            raise
        return handle

    @staticmethod
    def _cleanup_metadata(entry: QuarantineEntry) -> str | None:
        try:
            entry.manifest_path.unlink(missing_ok=True)
        except OSError as exc:
            return f"文件操作已完成，但隔离清单未能移除：{exc}"
        try:
            entry.manifest_path.parent.rmdir()
        except OSError as exc:
            return f"文件操作已完成，但空的隔离项目目录未能移除：{exc}"
        return None

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
