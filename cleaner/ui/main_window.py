"""主窗口：扫描、审查、勾选与清理的界面编排。"""

from __future__ import annotations

import csv
import queue
import subprocess
import threading
import tkinter as tk
from collections import Counter
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from ..cleanup import CleanupExecutor, CleanupMode, WindowsRemovalBackend
from ..models import Candidate, CleanupResult, RiskLevel, ScanReport
from ..policy import CleanupPolicy, build_default_policy
from ..quarantine import QuarantineStore
from ..safety import windows_explorer_path
from ..scanner import CleanupScanner
from .events import (
    CleanupCompletedEvent,
    CleanupFailedEvent,
    ScanCompletedEvent,
    ScanFailedEvent,
    WorkerEvent,
)
from .quarantine_window import QuarantineWindow
from .theme import COLORS, configure_styles, format_size, risk_tag, stat_card
from .widgets import FlowToolbar, make_scrolled_tree
from .window_layout import fit_window

CONFIRM_PERMANENT_PHRASE = "永久删除"
CONFIRM_HIGH_RISK_PHRASE = "我已审查"


class CleanerApp(tk.Tk):
    def __init__(self, policy: CleanupPolicy | None = None) -> None:
        super().__init__()
        self.policy = policy or build_default_policy()
        self.candidates: dict[str, Candidate] = {}
        self.selected_ids: set[str] = set()
        self.last_warnings: list[str] = []
        self.quarantine_store = QuarantineStore(allowed_drive=self.policy.system_drive)
        self._busy = False
        self._worker_events: queue.Queue[WorkerEvent] = queue.Queue()

        self.title("慎清 · C 盘清理审查器")
        fit_window(self, preferred=(1160, 760), minimum=(760, 500))
        self.configure(background=COLORS["background"])
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        configure_styles(self)
        self._build_layout()
        self.after(50, self._drain_worker_events)
        self.after(250, self.start_scan)

    def _build_layout(self) -> None:
        shell = ttk.Frame(self, style="App.TFrame", padding=12)
        shell.pack(fill="both", expand=True)
        shell.columnconfigure(0, weight=1)
        # 只有表格拿取/让出剩余高度，操作栏不参与争抢空间。
        shell.rowconfigure(5, weight=1)

        header = ttk.Frame(shell, style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="慎清 · C 盘清理审查器", style="Title.TLabel", width=1).grid(
            row=0, column=0, sticky="ew"
        )
        self.scan_button = ttk.Button(
            header, text="重新扫描", style="Accent.TButton", command=self.start_scan
        )
        self.scan_button.grid(row=0, column=1, sticky="e")

        self.safety_note = ttk.Label(
            shell,
            text="先审查再清理 · 默认不勾选 · 不扫描个人文档 · 执行前重新校验",
            style="Subtitle.TLabel",
        )
        self.safety_note.grid(row=1, column=0, sticky="w", pady=(0, 6))
        self.cards = ttk.Frame(shell, style="App.TFrame")
        self.cards.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        self.count_value = stat_card(self.cards, "候选项目", "—")
        self.size_value = stat_card(self.cards, "候选大小", "—")
        self.selected_value = stat_card(self.cards, "已勾选", "0 项")
        self.risk_value = stat_card(self.cards, "最高风险", "—")

        self.toolbar = FlowToolbar(shell, style="Surface.TFrame")
        self.toolbar.grid(row=3, column=0, sticky="ew", pady=(0, 6))
        self.selection_buttons = []
        for text, command in (
            ("勾选全部低风险", self.select_low_risk),
            ("全部取消", self.clear_selection),
        ):
            self.selection_buttons.append(
                ttk.Button(self.toolbar, text=text, style="Soft.TButton", command=command)
            )
        self.quarantine_button = ttk.Button(
            self.toolbar,
            text="查看/恢复隔离区",
            style="Soft.TButton",
            command=self.show_quarantine,
        )
        for text, command in (
            ("导出审查清单", self.export_review),
            ("查看跳过记录", self.show_warnings),
            ("打开所在位置", self.open_location),
        ):
            ttk.Button(self.toolbar, text=text, style="Soft.TButton", command=command)

        filters = ttk.Frame(shell, style="App.TFrame")
        filters.grid(row=4, column=0, sticky="ew", pady=(0, 6))
        filters.columnconfigure(3, weight=1)
        ttk.Label(filters, text="风险筛选").grid(row=0, column=0, padx=(0, 6))
        self.risk_filter = tk.StringVar(value="全部")
        risk_combo = ttk.Combobox(
            filters,
            textvariable=self.risk_filter,
            values=("全部", "低", "中", "高"),
            width=6,
            state="readonly",
        )
        risk_combo.grid(row=0, column=1)
        risk_combo.bind("<<ComboboxSelected>>", lambda _event: self.refresh_table())
        ttk.Label(filters, text="筛选路径").grid(row=0, column=2, padx=(12, 6))
        self.search_text = tk.StringVar()
        search = ttk.Entry(filters, textvariable=self.search_text, width=12)
        search.grid(row=0, column=3, sticky="ew")
        search.bind("<KeyRelease>", lambda _event: self.refresh_table())

        table_frame = ttk.Frame(shell, style="Surface.TFrame")
        table_frame.grid(row=5, column=0, sticky="nsew")
        self.tree = make_scrolled_tree(
            table_frame,
            columns=("pick", "risk", "category", "size", "modified", "path"),
            headings={
                "pick": "选择",
                "risk": "风险",
                "category": "类别",
                "size": "大小",
                "modified": "最后修改",
                "path": "完整路径",
            },
            widths={
                "pick": 56,
                "risk": 64,
                "category": 150,
                "size": 94,
                "modified": 145,
                "path": 500,
            },
            stretch_column="path",
        )
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<space>", self._on_tree_space)
        self.tree.bind("<<TreeviewSelect>>", self._show_candidate_details)

        detail = ttk.Frame(shell, style="Surface.TFrame")
        detail.grid(row=6, column=0, sticky="ew", pady=(6, 0))
        detail.columnconfigure(0, weight=1)
        self.detail_text = tk.Text(
            detail,
            height=2,
            width=1,
            wrap="word",
            relief="flat",
            font=("Microsoft YaHei UI", 9),
            background=COLORS["surface"],
            foreground=COLORS["ink"],
            padx=6,
            pady=4,
            state="disabled",
        )
        self.detail_text.grid(row=0, column=0, sticky="ew")
        detail_scroll = ttk.Scrollbar(detail, command=self.detail_text.yview)
        detail_scroll.grid(row=0, column=1, sticky="ns")
        self.detail_text.configure(yscrollcommand=detail_scroll.set)
        self._set_details("选择一项可查看风险理由；长内容可在此滚动查看。")

        self.status_var = tk.StringVar(value="准备扫描。")
        status = ttk.Frame(shell, style="App.TFrame")
        status.grid(row=7, column=0, sticky="ew", pady=4)
        status.columnconfigure(0, weight=1)
        ttk.Label(status, textvariable=self.status_var, style="Subtitle.TLabel", width=1).grid(
            row=0, column=0, sticky="ew"
        )
        self.selection_summary = tk.StringVar(value="已勾选 0 项")
        ttk.Label(status, textvariable=self.selection_summary).grid(
            row=0, column=1, sticky="e", padx=(8, 0)
        )

        footer = ttk.Frame(shell, style="App.TFrame")
        footer.grid(row=8, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)
        self.mode = tk.StringVar(value=CleanupMode.QUARANTINE.value)
        modes = FlowToolbar(footer, style="App.TFrame")
        modes.grid(row=0, column=0, sticky="ew")
        ttk.Radiobutton(
            modes,
            text="安全隔离（可恢复）",
            value=CleanupMode.QUARANTINE.value,
            variable=self.mode,
        )
        ttk.Radiobutton(
            modes,
            text="永久删除",
            value=CleanupMode.PERMANENT.value,
            variable=self.mode,
        )
        self.clean_button = ttk.Button(
            footer, text="清理已勾选项目", style="Accent.TButton", command=self.clean_selected
        )
        self.clean_button.grid(row=0, column=1, sticky="e", padx=(12, 0))
        shell.bind("<Configure>", self._adapt_layout)

    def _adapt_layout(self, event: tk.Event) -> None:
        # 小屏/高缩放优先保留审查列表和操作，收起非必需的装饰性统计。
        compact = event.height < 620
        self.detail_text.configure(height=1 if event.height < 520 else 2)
        for widget in (self.cards, self.safety_note):
            if compact:
                widget.grid_remove()
            else:
                widget.grid()

    def _set_details(self, text: str) -> None:
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")

    # ----- 扫描 -----

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
                self._worker_events.put(ScanFailedEvent(str(exc)))
                return
            self._worker_events.put(ScanCompletedEvent(report))

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

    # ----- 候选列表 -----

    def refresh_table(self) -> None:
        current = self.tree.selection()
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
                tags=(risk_tag(item.risk),),
            )
        if current and self.tree.exists(current[0]):
            self.tree.selection_set(current[0])
        self._update_stats()

    def _update_stats(self) -> None:
        items = list(self.candidates.values())
        selected = [
            self.candidates[item_id] for item_id in self.selected_ids if item_id in self.candidates
        ]
        self.count_value.configure(text=f"{len(items):,} 项")
        self.size_value.configure(text=format_size(sum(item.size_bytes for item in items)))
        self.selected_value.configure(
            text=f"{len(selected):,} 项 · {format_size(sum(item.size_bytes for item in selected))}"
        )
        self.selection_summary.set(
            f"已勾选 {len(selected):,} 项 · {format_size(sum(i.size_bytes for i in selected))}"
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
            self._set_details("选择一项可查看风险理由。")
            return
        item = self.candidates[selected[0]]
        self._set_details(f"风险 {item.risk.label} · {item.reason}    扫描范围：{item.source_root}")

    # ----- 工具栏动作 -----

    def select_low_risk(self) -> None:
        if self._busy:
            return
        self.selected_ids = {
            item.candidate_id for item in self.candidates.values() if item.risk is RiskLevel.LOW
        }
        self.refresh_table()
        self.status_var.set("仅勾选了低风险项；仍建议逐项查看路径和风险理由。")

    def clear_selection(self) -> None:
        if self._busy:
            return
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

    def show_quarantine(self) -> None:
        QuarantineWindow(self, self.quarantine_store)

    def open_location(self) -> None:
        selected = self.tree.selection()
        if not selected or selected[0] not in self.candidates:
            messagebox.showinfo("请选择项目", "请先在列表中选择一个项目。", parent=self)
            return
        path = self.candidates[selected[0]].path
        try:
            # The executable comes from GetWindowsDirectoryW and the candidate is
            # an absolute reviewed path. A list of args keeps shell parsing disabled.
            subprocess.Popen(  # noqa: S603
                [str(windows_explorer_path()), "/select,", str(path)], shell=False
            )
        except OSError as exc:
            messagebox.showerror("无法打开", str(exc), parent=self)

    # ----- 清理 -----

    def clean_selected(self) -> None:
        if self._busy:
            return
        selected = [
            self.candidates[item_id] for item_id in self.selected_ids if item_id in self.candidates
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

        if not self._confirm_cleanup(selected, mode, size, summary):
            return

        self._set_busy(True, f"正在处理 {len(selected)} 个已审查项目……")

        def worker() -> None:
            executor = CleanupExecutor(
                backend=WindowsRemovalBackend(self.quarantine_store),
                protected_roots=self.policy.protected_roots,
                allowed_drive=self.policy.system_drive,
            )
            try:
                result = executor.execute(selected, mode=mode)
            except Exception as exc:  # UI boundary: preserve selection for retry.
                self._worker_events.put(CleanupFailedEvent(str(exc)))
                return
            self._worker_events.put(CleanupCompletedEvent(result, mode))

        threading.Thread(target=worker, daemon=True, name="conservative-cleanup").start()

    def _confirm_cleanup(
        self,
        selected: list[Candidate],
        mode: CleanupMode,
        size: str,
        summary: str,
    ) -> bool:
        if mode is CleanupMode.PERMANENT:
            if any(item.risk is RiskLevel.HIGH for item in selected):
                messagebox.showerror(
                    "已阻止永久删除",
                    "高风险项目不能在本软件中永久删除。请取消这些项目，或改用安全隔离模式。",
                    parent=self,
                )
                return False
            confirmation = simpledialog.askstring(
                "确认永久删除",
                f"将永久删除 {len(selected)} 项（{size}，{summary}），无法恢复。\n\n"
                f"请输入“{CONFIRM_PERMANENT_PHRASE}”继续：",
                parent=self,
            )
            if confirmation != CONFIRM_PERMANENT_PHRASE:
                self.status_var.set("已取消永久删除。")
                return False
            return True

        if any(item.risk is RiskLevel.HIGH for item in selected):
            confirmation = simpledialog.askstring(
                "高风险项目复核",
                f"已选择高风险项目（共 {len(selected)} 项，{size}）。\n\n"
                f"请输入“{CONFIRM_HIGH_RISK_PHRASE}”后才可移到安全隔离区：",
                parent=self,
            )
            if confirmation != CONFIRM_HIGH_RISK_PHRASE:
                self.status_var.set("已取消高风险清理。")
                return False
        return messagebox.askyesno(
            "确认移到安全隔离区",
            f"将把 {len(selected)} 项（{size}，{summary}）移到安全隔离区。\n\n"
            "此操作可从“查看/恢复隔离区”逐项恢复，但不会立即释放 C 盘空间；"
            "软件也不会自动清空隔离区。\n\n"
            "确定继续吗？",
            parent=self,
        )

    def _cleanup_failed(self, message: str) -> None:
        self._set_busy(False, "清理未完成；所有未确认成功的项目均保持勾选。")
        messagebox.showerror("清理失败", message, parent=self)

    def _cleanup_completed(self, result: CleanupResult, mode: CleanupMode) -> None:
        succeeded = {item.candidate.candidate_id for item in result.items if item.success}
        for item_id in succeeded:
            self.candidates.pop(item_id, None)
            self.selected_ids.discard(item_id)
        self._set_busy(False, "")
        self.refresh_table()
        action = "移到安全隔离区" if mode is CleanupMode.QUARANTINE else "永久删除"
        self.status_var.set(
            f"完成：{result.success_count} 项已{action}，"
            f"{result.failure_count} 项未处理；处理大小 {format_size(result.processed_bytes)}。"
        )
        failures = [item for item in result.items if not item.success]
        detail = "\n".join(f"• {item.candidate.path}\n  {item.message}" for item in failures[:6])
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

    # ----- 后台事件与状态 -----

    def _drain_worker_events(self) -> None:
        try:
            while True:
                event = self._worker_events.get_nowait()
                if isinstance(event, ScanCompletedEvent):
                    self._scan_completed(event.report)
                elif isinstance(event, ScanFailedEvent):
                    self._scan_failed(event.message)
                elif isinstance(event, CleanupCompletedEvent):
                    self._cleanup_completed(event.result, event.mode)
                elif isinstance(event, CleanupFailedEvent):
                    self._cleanup_failed(event.message)
        except queue.Empty:
            pass
        if self.winfo_exists():
            self.after(50, self._drain_worker_events)

    def _set_busy(self, busy: bool, status: str) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        self.scan_button.configure(state=state)
        self.clean_button.configure(state=state)
        self.quarantine_button.configure(state=state)
        for button in self.selection_buttons:
            button.configure(state=state)
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
