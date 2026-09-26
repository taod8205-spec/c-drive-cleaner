"""界面主题：配色、字体样式与共享的展示辅助函数。"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..models import RiskLevel

COLORS = {
    "background": "#F4F6F8",
    "surface": "#FFFFFF",
    "ink": "#17212B",
    "muted": "#607080",
    "border": "#DCE2E8",
    "accent": "#1769E0",
    "accent_hover": "#0E55BD",
    "low": "#237A4B",
    "low_bg": "#E8F5EE",
    "medium": "#9A5B00",
    "medium_bg": "#FFF4D8",
    "high": "#B42318",
    "high_bg": "#FDECEA",
}

_RISK_TAGS = {
    RiskLevel.LOW: "risk_low",
    RiskLevel.MEDIUM: "risk_medium",
    RiskLevel.HIGH: "risk_high",
}

_RISK_COLORS = {
    RiskLevel.LOW: COLORS["low"],
    RiskLevel.MEDIUM: COLORS["medium"],
    RiskLevel.HIGH: COLORS["high"],
}


def format_size(size: int) -> str:
    value = float(size)
    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value):,} {unit}"
            return f"{value:,.1f} {unit}"
        value /= 1024
    return f"{size:,} B"


def risk_tag(risk: RiskLevel) -> str:
    return _RISK_TAGS[risk]


def configure_risk_tags(tree: ttk.Treeview) -> None:
    """为列表按风险等级着色。"""
    for risk, tag in _RISK_TAGS.items():
        tree.tag_configure(tag, foreground=_RISK_COLORS[risk])


def configure_styles(root: tk.Misc) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("vista")
    except tk.TclError:
        style.theme_use("clam")

    style.configure("App.TFrame", background=COLORS["background"])
    style.configure("Surface.TFrame", background=COLORS["surface"])
    style.configure(
        "Title.TLabel",
        background=COLORS["background"],
        foreground=COLORS["ink"],
        font=("Microsoft YaHei UI", 16, "bold"),
    )
    style.configure(
        "Subtitle.TLabel",
        background=COLORS["background"],
        foreground=COLORS["muted"],
        font=("Microsoft YaHei UI", 10),
    )
    style.configure(
        "CardTitle.TLabel",
        background=COLORS["surface"],
        foreground=COLORS["muted"],
        font=("Microsoft YaHei UI", 9),
    )
    style.configure(
        "CardValue.TLabel",
        background=COLORS["surface"],
        foreground=COLORS["ink"],
        font=("Microsoft YaHei UI", 13, "bold"),
    )
    style.configure(
        "Body.TLabel",
        background=COLORS["surface"],
        foreground=COLORS["ink"],
        font=("Microsoft YaHei UI", 9),
    )
    style.configure(
        "Muted.TLabel",
        background=COLORS["surface"],
        foreground=COLORS["muted"],
        font=("Microsoft YaHei UI", 9),
    )
    style.configure(
        "Accent.TButton",
        font=("Microsoft YaHei UI", 10, "bold"),
        padding=(12, 6),
    )
    style.configure("Soft.TButton", font=("Microsoft YaHei UI", 9), padding=(8, 5))
    style.configure(
        "Treeview",
        background=COLORS["surface"],
        fieldbackground=COLORS["surface"],
        foreground=COLORS["ink"],
        borderwidth=0,
        rowheight=31,
        font=("Microsoft YaHei UI", 9),
    )
    style.configure(
        "Treeview.Heading",
        background="#EDF1F5",
        foreground=COLORS["ink"],
        font=("Microsoft YaHei UI", 9, "bold"),
        padding=(7, 8),
    )


def stat_card(parent: ttk.Frame, title: str, initial: str) -> ttk.Label:
    """创建统计卡片，返回可更新数值的标签。"""
    card = tk.Frame(
        parent,
        background=COLORS["surface"],
        highlightbackground=COLORS["border"],
        highlightthickness=1,
        padx=10,
        pady=6,
    )
    card.pack(side="left", fill="x", expand=True, padx=(0, 8))
    ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
    value = ttk.Label(card, text=initial, style="CardValue.TLabel")
    value.pack(anchor="w", pady=(3, 0))
    return value
