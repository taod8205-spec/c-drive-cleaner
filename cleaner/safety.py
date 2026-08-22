from __future__ import annotations

import ctypes
import os
import stat
from pathlib import Path

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class DirectoryLockError(OSError):
    pass


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


def _close_windows_handle(handle: int) -> None:
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
                _close_windows_handle(handle)
        self._handles.clear()
