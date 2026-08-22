from __future__ import annotations

import csv
import subprocess
import threading
import tkinter as tk
from collections import Counter
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from .cleanup import CleanupExecutor, CleanupMode
from .models import Candidate, CleanupResult, RiskLevel, ScanReport
from .policy import CleanupPolicy, build_default_policy
from .scanner import CleanupScanner

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


def _risk_tag(risk: RiskLevel) -> str:
    return {
        RiskLevel.LOW: "risk_low",
        RiskLevel.MEDIUM: "risk_medium",
        RiskLevel.HIGH: "risk_high",
    }[risk]


class CleanerApp(tk.Tk):
    def __init__(self, policy: CleanupPolicy | None = None) -> None:
        super().__init__()
        self.policy = policy or build_default_policy()
        self.candidates: dict[str, Candidate] = {}
        self.selected_ids: set[str] = set()
        self.last_warnings: list[str] = []
        self._busy = False

        self.title("慎清 · C 盘清理审查器")
        self.geometry("1240x800")
        self.minsize(1000, 680)
        self.configure(background=COLORS["background"])
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._configure_styles()
        self._build_layout()
        self.after(250, self.start_scan)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
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
            font=("Microsoft YaHei UI", 21, "bold"),
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
            font=("Microsoft YaHei UI", 17, "bold"),
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
            padding=(16, 9),
        )
        style.configure("Soft.TButton", font=("Microsoft YaHei UI", 9), padding=(12, 7))
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

    def _build_layout(self) -> None:
        shell = ttk.Frame(self, style="App.TFrame", padding=(24, 18, 24, 18))
        shell.pack(fill="both", expand=True)

        header = ttk.Frame(shell, style="App.TFrame")
        header.pack(fill="x")
        title_box = ttk.Frame(header, style="App.TFrame")
        title_box.pack(side="left", fill="x", expand=True)
        ttk.Label(title_box, text="慎清", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            title_box,
            text="C 盘清理审查器 · 先扫描、逐项审查、默认不勾选",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(2, 0))
        self.scan_button = ttk.Button(
            header, text="重新扫描", style="Accent.TButton", command=self.start_scan
        )
        self.scan_button.pack(side="right", padx=(12, 0))

        safety = tk.Frame(
            shell,
            background="#EAF2FF",
            highlightbackground="#B9D2FA",
            highlightthickness=1,
            padx=14,
            pady=10,
        )
        safety.pack(fill="x", pady=(16, 12))
        tk.Label(
            safety,
            text="安全原则",
            background="#EAF2FF",
            foreground="#174A8B",
            font=("Microsoft YaHei UI", 10, "bold"),
        ).pack(side="left")
        tk.Label(
            safety,
            text=(
                "  不扫描个人文档/下载/桌面，不跟随链接；所有项目默认未选中；"
                "执行前会再次校验文件是否被替换。"
            ),
            background="#EAF2FF",
            foreground="#2D5685",
            font=("Microsoft YaHei UI", 9),
        ).pack(side="left")

        cards = ttk.Frame(shell, style="App.TFrame")
        cards.pack(fill="x", pady=(0, 12))
        self.count_value = self._stat_card(cards, "候选项目", "—")
        self.size_value = self._stat_card(cards, "候选大小", "—")
        self.selected_value = self._stat_card(cards, "已勾选", "0 项")
        self.risk_value = self._stat_card(cards, "最高风险", "—")

        toolbar = ttk.Frame(shell, style="Surface.TFrame", padding=(12, 9))
        toolbar.pack(fill="x")
        ttk.Button(
            toolbar, text="勾选全部低风险", style="Soft.TButton", command=self.select_low_risk
        ).pack(side="left")
        ttk.Button(
            toolbar, text="全部取消", style="Soft.TButton", command=self.clear_selection
        ).pack(side="left", padx=(6, 0))
        ttk.Button(
            toolbar, text="导出审查清单", style="Soft.TButton", command=self.export_review
        ).pack(side="left", padx=(6, 0))
        ttk.Button(
            toolbar, text="查看跳过记录", style="Soft.TButton", command=self.show_warnings
        ).pack(side="left", padx=(6, 0))
        ttk.Button(
            toolbar, text="打开所在位置", style="Soft.TButton", command=self.open_location
        ).pack(side="left", padx=(6, 0))

        ttk.Label(toolbar, text="风险筛选", style="Muted.TLabel").pack(
            side="left", padx=(24, 6)
        )
        self.risk_filter = tk.StringVar(value="全部")
        risk_combo = ttk.Combobox(
            toolbar,
            textvariable=self.risk_filter,
            values=("全部", "低", "中", "高"),
            width=6,
            state="readonly",
        )
        risk_combo.pack(side="left")
        risk_combo.bind("<<ComboboxSelected>>", lambda _event: self.refresh_table())

        self.search_text = tk.StringVar()
        search = ttk.Entry(toolbar, textvariable=self.search_text, width=28)
        search.pack(side="right")
        search.bind("<KeyRelease>", lambda _event: self.refresh_table())
        ttk.Label(toolbar, text="筛选路径", style="Muted.TLabel").pack(
            side="right", padx=(0, 6)
        )

        table_frame = ttk.Frame(shell, style="Surface.TFrame")
        table_frame.pack(fill="both", expand=True, pady=(1, 0))
        columns = ("pick", "risk", "category", "size", "modified", "path")
        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "pick": "选择",
            "risk": "风险",
            "category": "类别",
            "size": "大小",
            "modified": "最后修改",
            "path": "完整路径",
        }
        widths = {
            "pick": 56,
            "risk": 64,
            "category": 180,
            "size": 94,
            "modified": 145,
            "path": 560,
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(
                column,
                width=widths[column],
                minwidth=widths[column] if column != "path" else 240,
                stretch=column == "path",
                anchor="center" if column != "path" else "w",
            )
        self.tree.tag_configure("risk_low", foreground=COLORS["low"])
        self.tree.tag_configure("risk_medium", foreground=COLORS["medium"])
        self.tree.tag_configure("risk_high", foreground=COLORS["high"])
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<space>", self._on_tree_space)
        self.tree.bind("<<TreeviewSelect>>", self._show_candidate_details)

        detail = ttk.Frame(shell, style="Surface.TFrame", padding=(12, 8))
        detail.pack(fill="x", pady=(8, 0))
        self.detail_label = ttk.Label(
            detail,
            text="选择一项可查看风险理由。",
            style="Body.TLabel",
            wraplength=1120,
            justify="left",
        )
        self.detail_label.pack(anchor="w")

        footer = ttk.Frame(shell, style="App.TFrame")
        footer.pack(fill="x", pady=(12, 0))
        self.status_var = tk.StringVar(value="准备扫描。")
        ttk.Label(footer, textvariable=self.status_var, style="Subtitle.TLabel").pack(
            side="left", fill="x", expand=True
        )
        self.mode = tk.StringVar(value=CleanupMode.RECYCLE.value)
        ttk.Radiobutton(
            footer,
            text="移到回收站（推荐）",
            value=CleanupMode.RECYCLE.value,
            variable=self.mode,
        ).pack(side="left", padx=(10, 4))
        ttk.Radiobutton(
            footer,
            text="永久删除",
            value=CleanupMode.PERMANENT.value,
            variable=self.mode,
        ).pack(side="left", padx=4)
        self.clean_button = ttk.Button(
            footer, text="清理已勾选项目", style="Accent.TButton", command=self.clean_selected
        )
        self.clean_button.pack(side="right", padx=(12, 0))

    def _stat_card(self, parent: ttk.Frame, title: str, initial: str) -> ttk.Label:
        card = tk.Frame(
            parent,
            background=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            padx=16,
            pady=10,
        )
        card.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
        value = ttk.Label(card, text=initial, style="CardValue.TLabel")
        value.pack(anchor="w", pady=(3, 0))
        return value

    def start_scan(self) -> None:
        if self._busy:
            return
        self._set_busy(True, "正在只读扫描明确的缓存目录……")
        self.candidates.clear()
        self.selected_ids.clear()
        self.refresh_table()

        def worker() -> None:
            try:
                report = CleanupScanner(self.policy.rules).scan()
            except Exception as exc:  # UI boundary: always restore controls.
                error_message = str(exc)
                self.after(0, lambda: self._scan_failed(error_message))
                return
            self.after(0, lambda: self._scan_completed(report))

        threading.Thread(target=worker, daemon=True, name="conservative-scan").start()

    def _scan_completed(self, report: ScanReport) -> None:
        self.candidates = {item.candidate_id: item for item in report.candidates}
        self.selected_ids.clear()
        self.last_warnings = list(report.warnings)
        self._set_busy(False, "")
        self.refresh_table()
        suffix = f"；{len(report.warnings)} 条路径被安全跳过" if report.warnings else ""
        self.status_var.set(
            f"扫描完成：检查了 {report.scanned_files:,} 个文件，"
            f"列出 {len(report.candidates):,} 个候选项{suffix}。"
        )

    def _scan_failed(self, message: str) -> None:
        self._set_busy(False, "扫描失败。")
        messagebox.showerror("扫描失败", message, parent=self)

    def refresh_table(self) -> None:
        current = self.tree.selection() if hasattr(self, "tree") else ()
        if not hasattr(self, "tree"):
            return
        self.tree.delete(*self.tree.get_children())
        risk_filter = self.risk_filter.get()
        query = self.search_text.get().strip().casefold()
        for item in self.candidates.values():
            if risk_filter != "全部" and item.risk.label != risk_filter:
                continue
            if (
                query
                and query not in str(item.path).casefold()
                and query not in item.category.casefold()
            ):
                continue
            selected = item.candidate_id in self.selected_ids
            self.tree.insert(
                "",
                "end",
                iid=item.candidate_id,
                values=(
                    "☑" if selected else "☐",
                    item.risk.label,
                    item.category,
                    format_size(item.size_bytes),
                    item.modified_at.astimezone().strftime("%Y-%m-%d %H:%M"),
                    str(item.path),
                ),
                tags=(_risk_tag(item.risk),),
            )
        if current and self.tree.exists(current[0]):
            self.tree.selection_set(current[0])
        self._update_stats()

    def _update_stats(self) -> None:
        items = list(self.candidates.values())
        selected = [
            self.candidates[item_id]
            for item_id in self.selected_ids
            if item_id in self.candidates
        ]
        self.count_value.configure(text=f"{len(items):,} 项")
        self.size_value.configure(text=format_size(sum(item.size_bytes for item in items)))
        self.selected_value.configure(
            text=f"{len(selected):,} 项 · {format_size(sum(item.size_bytes for item in selected))}"
        )
        highest = max((item.risk for item in items), default=None)
        self.risk_value.configure(text=highest.label if highest else "—")

    def _toggle(self, item_id: str) -> None:
        if item_id not in self.candidates or self._busy:
            return
        if item_id in self.selected_ids:
            self.selected_ids.remove(item_id)
        else:
            self.selected_ids.add(item_id)
        self.tree.set(item_id, "pick", "☑" if item_id in self.selected_ids else "☐")
        self._update_stats()

    def _on_tree_click(self, event: tk.Event) -> None:
        item_id = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        if item_id and column == "#1":
            self.after_idle(lambda: self._toggle(item_id))

    def _on_tree_double_click(self, event: tk.Event) -> None:
        item_id = self.tree.identify_row(event.y)
        if item_id:
            self._toggle(item_id)

    def _on_tree_space(self, _event: tk.Event) -> str:
        selected = self.tree.selection()
        if selected:
            self._toggle(selected[0])
        return "break"

    def _show_candidate_details(self, _event: tk.Event | None = None) -> None:
        selected = self.tree.selection()
        if not selected or selected[0] not in self.candidates:
            self.detail_label.configure(text="选择一项可查看风险理由。")
            return
        item = self.candidates[selected[0]]
        self.detail_label.configure(
            text=(
                f"风险 {item.risk.label} · {item.reason}    "
                f"扫描范围：{item.source_root}"
            )
        )

    def select_low_risk(self) -> None:
        self.selected_ids = {
            item.candidate_id
            for item in self.candidates.values()
            if item.risk is RiskLevel.LOW
        }
        self.refresh_table()
        self.status_var.set("仅勾选了低风险项；仍建议逐项查看路径和风险理由。")

    def clear_selection(self) -> None:
        self.selected_ids.clear()
        self.refresh_table()
        self.status_var.set("已取消全部勾选。")

    def export_review(self) -> None:
        if not self.candidates:
            messagebox.showinfo("没有清单", "请先完成扫描。", parent=self)
            return
        default_name = f"C盘清理审查清单_{datetime.now():%Y%m%d_%H%M}.csv"
        target = filedialog.asksaveasfilename(
            parent=self,
            title="导出审查清单",
            defaultextension=".csv",
            initialfile=default_name,
            filetypes=(("CSV 文件", "*.csv"),),
        )
        if not target:
            return
        try:
            with Path(target).open("w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow(
                    ["已勾选", "风险", "类别", "大小(字节)", "最后修改", "路径", "风险理由"]
                )
                for item in self.candidates.values():
                    writer.writerow(
                        [
                            "是" if item.candidate_id in self.selected_ids else "否",
                            item.risk.label,
                            item.category,
                            item.size_bytes,
                            item.modified_at.astimezone().isoformat(timespec="seconds"),
                            str(item.path),
                            item.reason,
                        ]
                    )
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc), parent=self)
            return
        self.status_var.set(f"审查清单已导出到：{target}")

    def show_warnings(self) -> None:
        if not self.last_warnings:
            messagebox.showinfo(
                "跳过记录", "本次扫描没有因权限、链接或读取错误跳过路径。", parent=self
            )
            return
        preview = "\n".join(f"• {item}" for item in self.last_warnings[:20])
        if len(self.last_warnings) > 20:
            preview += f"\n……另有 {len(self.last_warnings) - 20} 条"
        messagebox.showinfo(
            "安全跳过记录",
            "以下位置未被列入候选项，也不会被清理：\n\n" + preview,
            parent=self,
        )

    def open_location(self) -> None:
        selected = self.tree.selection()
        if not selected or selected[0] not in self.candidates:
            messagebox.showinfo("请选择项目", "请先在列表中选择一个项目。", parent=self)
            return
        path = self.candidates[selected[0]].path
        try:
            subprocess.Popen(["explorer.exe", "/select,", str(path)])
        except OSError as exc:
            messagebox.showerror("无法打开", str(exc), parent=self)

    def clean_selected(self) -> None:
        if self._busy:
            return
        selected = [
            self.candidates[item_id]
            for item_id in self.selected_ids
            if item_id in self.candidates
        ]
        if not selected:
            messagebox.showinfo(
                "尚未勾选", "默认不会清理任何内容。请审查后再勾选项目。", parent=self
            )
            return

        mode = CleanupMode(self.mode.get())
        risk_counts = Counter(item.risk.label for item in selected)
        summary = "、".join(f"{risk}风险 {count} 项" for risk, count in risk_counts.items())
        size = format_size(sum(item.size_bytes for item in selected))

        if mode is CleanupMode.PERMANENT:
            if any(item.risk is RiskLevel.HIGH for item in selected):
                messagebox.showerror(
                    "已阻止永久删除",
                    "高风险项目不能在本软件中永久删除。请取消这些项目，或改用回收站模式。",
                    parent=self,
                )
                return
            confirmation = simpledialog.askstring(
                "确认永久删除",
                f"将永久删除 {len(selected)} 项（{size}，{summary}），无法恢复。\n\n"
                "请输入“永久删除”继续：",
                parent=self,
            )
            if confirmation != "永久删除":
                self.status_var.set("已取消永久删除。")
                return
        else:
            if any(item.risk is RiskLevel.HIGH for item in selected):
                confirmation = simpledialog.askstring(
                    "高风险项目复核",
                    f"已选择高风险项目（共 {len(selected)} 项，{size}）。\n\n"
                    "请输入“我已审查”后才可移到回收站：",
                    parent=self,
                )
                if confirmation != "我已审查":
                    self.status_var.set("已取消高风险清理。")
                    return
            if not messagebox.askyesno(
                "确认移到回收站",
                f"将把 {len(selected)} 项（{size}，{summary}）移到回收站。\n\n"
                "此操作可恢复，但在手动清空回收站之前不会释放 C 盘空间。"
                "软件不会替你清空回收站。\n\n"
                "确定继续吗？",
                parent=self,
            ):
                return

        self._set_busy(True, f"正在处理 {len(selected)} 个已审查项目……")

        def worker() -> None:
            executor = CleanupExecutor(protected_roots=self.policy.protected_roots)
            result = executor.execute(selected, mode=mode)
            self.after(0, lambda: self._cleanup_completed(result, mode))

        threading.Thread(target=worker, daemon=True, name="conservative-cleanup").start()

    def _cleanup_completed(self, result: CleanupResult, mode: CleanupMode) -> None:
        succeeded = {
            item.candidate.candidate_id for item in result.items if item.success
        }
        for item_id in succeeded:
            self.candidates.pop(item_id, None)
            self.selected_ids.discard(item_id)
        self._set_busy(False, "")
        self.refresh_table()
        action = "移到回收站" if mode is CleanupMode.RECYCLE else "永久删除"
        self.status_var.set(
            f"完成：{result.success_count} 项已{action}，"
            f"{result.failure_count} 项未处理；处理大小 {format_size(result.processed_bytes)}。"
        )
        failures = [item for item in result.items if not item.success]
        detail = "\n".join(
            f"• {item.candidate.path}\n  {item.message}" for item in failures[:6]
        )
        if len(failures) > 6:
            detail += f"\n……另有 {len(failures) - 6} 项"
        if failures:
            messagebox.showwarning(
                "清理已完成，但有项目被保留",
                f"成功 {result.success_count} 项，保留 {result.failure_count} 项。\n\n{detail}",
                parent=self,
            )
        else:
            messagebox.showinfo(
                "清理完成",
                f"成功{action} {result.success_count} 项，处理大小 "
                f"{format_size(result.processed_bytes)}。",
                parent=self,
            )

    def _set_busy(self, busy: bool, status: str) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        self.scan_button.configure(state=state)
        self.clean_button.configure(state=state)
        if status:
            self.status_var.set(status)
        self.configure(cursor="watch" if busy else "")

    def _on_close(self) -> None:
        if self._busy and not messagebox.askyesno(
            "操作仍在进行",
            "后台操作尚未结束。现在关闭只会停止界面，不会撤销已经完成的文件操作。确定关闭吗？",
            parent=self,
        ):
            return
        self.destroy()


def run() -> None:
    app = CleanerApp()
    app.mainloop()
