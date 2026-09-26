"""兼容旧的启动/导入路径；界面实现在 cleaner.ui 中。"""

from .ui import CleanerApp, run
from .ui.theme import format_size

__all__ = ["CleanerApp", "format_size", "run"]
