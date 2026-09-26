"""可缩放的表格与自动换行的工具栏。"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from .theme import configure_risk_tags


class FlowToolbar(ttk.Frame):
    """按控件实际请求宽度换行，不让右侧操作被窗口截断。"""

    def __init__(self, parent: tk.Misc, **kwargs: object) -> None:
        super().__init__(parent, **kwargs)
        self.bind("<Configure>", self._layout)

    def _layout(self, _event: tk.Event | None = None) -> None:
        width = self.winfo_width()
        x = y = row_height = 0
        for child in self.winfo_children():
            child_width = child.winfo_reqwidth()
            child_height = child.winfo_reqheight()
            if x and x + child_width > width:
                x = 0
                y += row_height + 4
                row_height = 0
            child.place(x=x, y=y, width=min(child_width, width), height=child_height)
            x += child_width + 6
            row_height = max(row_height, child_height)
        self.configure(height=y + row_height)


def make_scrolled_tree(
    parent: tk.Misc,
    *,
    columns: tuple[str, ...],
    headings: dict[str, str],
    widths: dict[str, int],
    stretch_column: str,
    selectmode: str = "browse",
) -> ttk.Treeview:
    """父容器只放表格和双向滚动条，操作按钮由外层布局预留空间。"""
    parent.rowconfigure(0, weight=1)
    parent.columnconfigure(0, weight=1)
    tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode=selectmode, height=4)
    for column in columns:
        tree.heading(column, text=headings[column])
        tree.column(
            column,
            width=widths[column],
            minwidth=widths[column] if column != stretch_column else 240,
            stretch=column == stretch_column,
            anchor="center" if column != stretch_column else "w",
        )
    configure_risk_tags(tree)
    vertical = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    return tree
