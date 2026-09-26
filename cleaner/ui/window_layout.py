"""初始窗口限制在显示器工作区内（排除任务栏）。"""

from __future__ import annotations

import ctypes
import os
import tkinter as tk
from ctypes import wintypes


def work_area(window: tk.Misc) -> tuple[int, int, int, int]:
    if os.name == "nt":

        class MonitorInfo(ctypes.Structure):
            _fields_ = [
                ("size", wintypes.DWORD),
                ("monitor", wintypes.RECT),
                ("work", wintypes.RECT),
                ("flags", wintypes.DWORD),
            ]

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        nearest = user32.MonitorFromWindow
        nearest.argtypes = [wintypes.HWND, wintypes.DWORD]
        nearest.restype = wintypes.HANDLE
        get_info = user32.GetMonitorInfoW
        get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(MonitorInfo)]
        get_info.restype = wintypes.BOOL
        info = MonitorInfo()
        info.size = ctypes.sizeof(info)
        if get_info(nearest(window.winfo_id(), 2), ctypes.byref(info)):
            return info.work.left, info.work.top, info.work.right, info.work.bottom
    return 0, 0, window.winfo_screenwidth(), window.winfo_screenheight()


def fit_window(
    window: tk.Tk | tk.Toplevel,
    *,
    preferred: tuple[int, int],
    minimum: tuple[int, int],
) -> None:
    left, top, right, bottom = work_area(window.master or window)
    # geometry 使用客户区尺寸；额外留下标题栏、边框和工作区边缘。
    available_width = max(1, right - left - 32)
    available_height = max(1, bottom - top - 80)
    width = min(preferred[0], available_width)
    height = min(preferred[1], available_height)
    window.minsize(min(minimum[0], available_width), min(minimum[1], available_height))
    x = left + max(0, (right - left - width) // 2)
    y = top + max(0, (bottom - top - height - 40) // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")
