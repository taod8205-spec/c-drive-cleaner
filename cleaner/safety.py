from __future__ import annotations

import ctypes
import os
import stat
from dataclasses import dataclass
from pathlib import Path

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
FILE_READ_ATTRIBUTES = 0x00000080
DELETE_ACCESS = 0x00010000
OPEN_EXISTING = 3
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
FILE_RENAME_INFO_CLASS = 3
FILE_DISPOSITION_INFO_CLASS = 4
WINDOWS_TO_UNIX_EPOCH_100NS = 116_444_736_000_000_000


class DirectoryLockError(OSError):
    pass


class ExactFileError(OSError):
    pass


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation_time", _FileTime),
        ("last_access_time", _FileTime),
        ("last_write_time", _FileTime),
        ("volume_serial_number", ctypes.c_uint32),
        ("file_size_high", ctypes.c_uint32),
        ("file_size_low", ctypes.c_uint32),
        ("number_of_links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


class _FileRenameInfoHeader(ctypes.Structure):
    _fields_ = [
        ("replace_if_exists", ctypes.c_uint32),
        ("root_directory", ctypes.c_void_p),
        ("file_name_length", ctypes.c_uint32),
        ("file_name", ctypes.c_wchar * 1),
    ]


class _FileDispositionInfo(ctypes.Structure):
    _fields_ = [("delete_file", ctypes.c_ubyte)]


@dataclass(frozen=True, slots=True)
class OpenedFileIdentity:
    size: int
    modified_ns: int
    volume_serial_number: int
    file_index: int
    is_reparse_point: bool


def is_reparse_point(stat_result: os.stat_result) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0)
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def _directory_components(path: Path) -> list[Path]:
    if not path.is_absolute() or not path.anchor:
        raise DirectoryLockError(f"目录必须是绝对路径：{path}")
    current = Path(path.anchor)
    components: list[Path] = []
    for part in path.parts[1:]:
        current /= part
        components.append(current)
    return components


def _open_windows_directory(path: Path) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(path),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        error_code = ctypes.get_last_error()
        raise DirectoryLockError(error_code, "无法锁定目录进行安全检查", str(path))
    return handle


def open_exact_windows_file(path: Path) -> int:
    if os.name != "nt":
        raise ExactFileError("精确文件句柄仅支持 Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(path),
        FILE_READ_ATTRIBUTES | DELETE_ACCESS,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        error_code = ctypes.get_last_error()
        raise ExactFileError(error_code, "无法锁定候选文件", str(path))
    return handle


def get_opened_file_identity(handle: int) -> OpenedFileIdentity:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ByHandleFileInformation)]
    get_information.restype = ctypes.c_int
    information = _ByHandleFileInformation()
    if not get_information(handle, ctypes.byref(information)):
        error_code = ctypes.get_last_error()
        raise ExactFileError(error_code, "无法读取候选文件句柄信息")
    file_time = (information.last_write_time.high << 32) | information.last_write_time.low
    modified_ns = (file_time - WINDOWS_TO_UNIX_EPOCH_100NS) * 100
    return OpenedFileIdentity(
        size=(information.file_size_high << 32) | information.file_size_low,
        modified_ns=modified_ns,
        volume_serial_number=information.volume_serial_number,
        file_index=(information.file_index_high << 32) | information.file_index_low,
        is_reparse_point=bool(information.attributes & FILE_ATTRIBUTE_REPARSE_POINT),
    )


def rename_opened_file(handle: int, target: Path) -> None:
    if not target.is_absolute():
        raise ExactFileError(f"暂存路径必须是绝对路径：{target}")
    encoded_target = str(target).encode("utf-16-le")
    filename_offset = _FileRenameInfoHeader.file_name.offset
    # Older Windows builds may inspect the WCHAR following FileNameLength even
    # though the documented length excludes a terminator. Keep an explicit NUL
    # inside the allocated buffer so the exact target name cannot gain garbage.
    buffer_size = filename_offset + len(encoded_target) + ctypes.sizeof(ctypes.c_wchar)
    buffer = ctypes.create_string_buffer(buffer_size)
    information = _FileRenameInfoHeader.from_buffer(buffer)
    information.replace_if_exists = 0
    information.root_directory = None
    information.file_name_length = len(encoded_target)
    ctypes.memmove(
        ctypes.addressof(buffer) + filename_offset, encoded_target, len(encoded_target)
    )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    set_information.restype = ctypes.c_int
    if not set_information(
        handle, FILE_RENAME_INFO_CLASS, ctypes.byref(buffer), buffer_size
    ):
        error_code = ctypes.get_last_error()
        raise ExactFileError(error_code, "无法按句柄暂存候选文件", str(target))


def mark_opened_file_for_deletion(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    set_information.restype = ctypes.c_int
    information = _FileDispositionInfo(delete_file=1)
    if not set_information(
        handle,
        FILE_DISPOSITION_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        error_code = ctypes.get_last_error()
        raise ExactFileError(error_code, "无法按句柄永久删除候选文件")


def close_windows_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.CloseHandle(handle)


class DirectoryChainLock:
    """在检查和文件操作期间阻止目录链被重命名或替换。"""

    def __init__(self, directory: Path) -> None:
        self._directory = Path(directory)
        self._handles: list[int] = []

    def __enter__(self) -> DirectoryChainLock:
        try:
            for component in _directory_components(self._directory):
                if os.name == "nt":
                    self._handles.append(_open_windows_directory(component))
                component_stat = component.stat(follow_symlinks=False)
                if not stat.S_ISDIR(component_stat.st_mode):
                    raise DirectoryLockError(f"目录链中的项目不是目录：{component}")
                if stat.S_ISLNK(component_stat.st_mode) or is_reparse_point(
                    component_stat
                ):
                    raise DirectoryLockError(f"目录链包含链接或重解析点：{component}")
        except OSError as exc:
            self._close_all()
            if isinstance(exc, DirectoryLockError):
                raise
            raise DirectoryLockError(f"无法验证目录链 {self._directory}：{exc}") from exc
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self._close_all()

    def _close_all(self) -> None:
        if os.name == "nt":
            for handle in reversed(self._handles):
                close_windows_handle(handle)
        self._handles.clear()
