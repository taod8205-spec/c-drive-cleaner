"""安全隔离区窗口：多选审查、批量恢复和永久删除。"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from ..models import RiskLevel
from ..quarantine import QuarantineEntry, QuarantineStore
from .theme import format_size, risk_tag
from .widgets import FlowToolbar, make_scrolled_tree
from .window_layout import fit_window

CONFIRM_DELETE_PHRASE = "永久删除隔离项"


class QuarantineWindow(tk.Toplevel):
    def __init__(self, master: tk.Misc, store: QuarantineStore) -> None:
        super().__init__(master)
        self._store = store
        self._entries: dict[str, QuarantineEntry] = {}
        self._busy = False
        self._batch: tuple[QuarantineEntry, ...] = ()
        self._results: list[tuple[QuarantineEntry, bool, str]] = []
        self._permanent = False
        self.title("安全隔离区 · 可恢复项目")
        self.transient(master)
        fit_window(self, preferred=(1000, 600), minimum=(640, 360))
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._build_layout()
        self.reload_entries()

    def _build_layout(self) -> None:
        shell = ttk.Frame(self, padding=12)
        shell.pack(fill="both", expand=True)
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(2, weight=1)
        note = ttk.Label(
            shell,
            text="隔离仍占用 C 盘空间；恢复不会覆盖原文件。Ctrl / Shift 可多选。",
            wraplength=600,
            justify="left",
        )
        note.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        shell.bind(
            "<Configure>", lambda event: note.configure(wraplength=max(100, event.width - 24))
        )

        selection = FlowToolbar(shell)
        self._selection_toolbar = selection
        selection.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        self._buttons = [
            ttk.Button(selection, text="全选", command=self._select_all),
            ttk.Button(selection, text="取消选择", command=self._clear_selection),
        ]
        self._selection_status = tk.StringVar(value="已选择 0 项")
        ttk.Label(selection, textvariable=self._selection_status, padding=(10, 4))

        table = ttk.Frame(shell)
        table.grid(row=2, column=0, sticky="nsew")
        self._tree = make_scrolled_tree(
            table,
            columns=("time", "risk", "size", "category", "original"),
            headings={
                "time": "隔离时间",
                "risk": "风险",
                "size": "大小",
                "category": "类别",
                "original": "原始路径",
            },
            widths={"time": 145, "risk": 60, "size": 95, "category": 150, "original": 500},
            stretch_column="original",
            selectmode="extended",
        )
        self._tree.bind("<<TreeviewSelect>>", self._update_selection)
        self._tree.bind("<Control-a>", self._select_all)
        self._tree.bind("<Control-A>", self._select_all)
        self._tree.bind("<Escape>", self._clear_selection)
        self._status = tk.StringVar()
        ttk.Label(shell, textvariable=self._status, width=1).grid(
            row=3, column=0, sticky="ew", pady=6
        )
        actions = FlowToolbar(shell)
        actions.grid(row=4, column=0, sticky="ew")
        for text, command in (
            ("恢复所选项", self._restore_selected),
            ("永久删除所选项", self._delete_selected),
            ("刷新", self.reload_entries),
            ("关闭", self._on_close),
        ):
            self._buttons.append(ttk.Button(actions, text=text, command=command))

    def _select_all(self, _event: tk.Event | None = None) -> str:
        if not self._busy:
            self._tree.selection_set(self._tree.get_children())
        return "break"

    def _clear_selection(self, _event: tk.Event | None = None) -> str:
        if not self._busy:
            self._tree.selection_remove(self._tree.selection())
        return "break"

    def _update_selection(self, _event: tk.Event | None = None) -> None:
        entries = [self._entries[i] for i in self._tree.selection() if i in self._entries]
        self._selection_status.set(
            f"已选择 {len(entries):,} 项 · {format_size(sum(e.size_bytes for e in entries))}"
        )
        self.after_idle(self._selection_toolbar._layout)

    def reload_entries(self, *, notify_warnings: bool = True) -> None:
        if self._busy:
            return
        selected = set(self._tree.selection())
        self._tree.delete(*self._tree.get_children())
        self._entries.clear()
        try:
            report = self._store.inspect_entries()
            listed = report.entries
        except (OSError, ValueError) as exc:
            messagebox.showerror("无法读取隔离区", str(exc), parent=self)
            listed = []
            report = None
        for entry in listed:
            self._entries[entry.entry_id] = entry
            self._tree.insert(
                "",
                "end",
                iid=entry.entry_id,
                values=(
                    entry.quarantined_at.astimezone().strftime("%Y-%m-%d %H:%M"),
                    entry.risk.label,
                    format_size(entry.size_bytes),
                    entry.category,
                    str(entry.original_path),
                ),
                tags=(risk_tag(entry.risk),),
            )
        self._tree.selection_set([i for i in selected if i in self._entries])
        self._update_selection()
        warnings = report.warnings if report else []
        warning_text = f"；{len(warnings)} 个异常项目已保留" if warnings else ""
        self._status.set(f"共 {len(listed)} 项{warning_text}；不会自动清空隔离区。")
        if notify_warnings and warnings:
            self._show_text_report(
                "部分隔离项目无法读取",
                "异常项目已原样保留，没有执行任何文件操作：\n\n" + "\n".join(warnings),
            )

    def _selected_entries(self) -> list[QuarantineEntry]:
        entries = [self._entries[i] for i in self._tree.selection() if i in self._entries]
        if not entries:
            messagebox.showinfo("请选择项目", "请先选择一个或多个隔离项目。", parent=self)
        return entries

    @staticmethod
    def _summary(entries: list[QuarantineEntry]) -> str:
        paths = "\n".join(f"• {e.original_path}（{e.risk.label}风险）" for e in entries[:8])
        if len(entries) > 8:
            paths += f"\n……另有 {len(entries) - 8} 项，请确认已在列表中审查。"
        return f"共 {len(entries)} 项，{format_size(sum(e.size_bytes for e in entries))}\n\n{paths}"

    def _can_start(self) -> bool:
        if self._busy:
            return False
        if getattr(self.master, "_busy", False):
            messagebox.showinfo("请稍候", "主窗口操作尚未完成，请完成后再操作隔离区。", parent=self)
            return False
        return True

    def _restore_selected(self) -> None:
        if not self._can_start():
            return
        entries = self._selected_entries()
        if not entries:
            return
        if not messagebox.askyesno(
            "确认批量恢复",
            self._summary(entries)
            + "\n\n恢复到各自原路径；遇到已有文件会保留该项并继续。确定恢复？",
            parent=self,
        ):
            return
        self._begin_batch(entries, permanent=False)

    def _delete_selected(self) -> None:
        if not self._can_start():
            return
        entries = self._selected_entries()
        if not entries:
            return
        if any(entry.risk is RiskLevel.HIGH for entry in entries):
            messagebox.showerror(
                "已阻止永久删除",
                "所选项目中包含高风险文件。本批次不会删除任何项目，请取消高风险项后重试。",
                parent=self,
            )
            return
        confirmation = simpledialog.askstring(
            "确认永久删除隔离项",
            self._summary(entries)
            + "\n\n将永久删除以上项目，无法恢复。\n"
            + f"请输入“{CONFIRM_DELETE_PHRASE}”继续：",
            parent=self,
        )
        if confirmation != CONFIRM_DELETE_PHRASE:
            return
        self._begin_batch(entries, permanent=True)

    def _begin_batch(self, entries: list[QuarantineEntry], *, permanent: bool) -> None:
        # 确认后的条目快照不受后续选择变化影响。
        self._batch = tuple(entries)
        self._results = []
        self._permanent = permanent
        self._busy = True
        for button in self._buttons:
            button.configure(state="disabled")
        if hasattr(self.master, "_set_busy"):
            self.master._set_busy(True, "正在处理隔离区项目……")
        self.configure(cursor="watch")
        self.after(1, self._process_next)

    def _process_next(self) -> None:
        if len(self._results) == len(self._batch):
            self._finish_batch()
            return
        entry = self._batch[len(self._results)]
        action = "永久删除" if self._permanent else "恢复"
        self._status.set(f"正在{action} {len(self._results) + 1}/{len(self._batch)}……")
        try:
            operation = self._store.permanently_delete if self._permanent else self._store.restore
            warning = operation(entry)
        except Exception as exc:  # UI boundary: record failure and continue other reviewed items.
            self._results.append((entry, False, str(exc)))
        else:
            self._results.append((entry, True, warning or ""))
        # 每个文件完成后把控制权交还界面，不在回调中递归或调用 update()。
        self.after(1, self._process_next)

    def _finish_batch(self) -> None:
        self._busy = False
        for button in self._buttons:
            button.configure(state="normal")
        if hasattr(self.master, "_set_busy"):
            self.master._set_busy(False, "隔离区操作完成；查看当前文件状态可重新扫描。")
        self.configure(cursor="")
        self.reload_entries(notify_warnings=False)
        succeeded = sum(success for _, success, _ in self._results)
        failed = len(self._results) - succeeded
        warnings = sum(success and bool(message) for _, success, message in self._results)
        action = "永久删除" if self._permanent else "恢复"
        summary = f"{action}完成：成功 {succeeded} 项，未完成 {failed} 项，清单警告 {warnings} 项。"
        self._status.set(summary)
        if failed or warnings:
            lines = [summary, ""]
            for entry, success, message in self._results:
                status = "已完成" if success else "未完成"
                lines.append(f"{status}：{entry.original_path}\n{message or '成功'}\n")
            self._show_text_report("批量操作结果", "\n".join(lines))
        else:
            messagebox.showinfo("批量操作完成", summary, parent=self)

    def _show_text_report(self, title: str, content: str) -> None:
        report = tk.Toplevel(self)
        report.title(title)
        report.transient(self)
        fit_window(report, preferred=(760, 460), minimum=(480, 280))
        report.columnconfigure(0, weight=1)
        report.rowconfigure(0, weight=1)
        text = tk.Text(report, wrap="word", width=1, height=4, padx=10, pady=10)
        text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(report, command=text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        text.configure(yscrollcommand=scrollbar.set)
        text.insert("1.0", content)
        text.configure(state="disabled")
        ttk.Button(report, text="关闭", command=report.destroy).grid(
            row=1, column=0, columnspan=2, pady=8
        )

    def _on_close(self) -> None:
        if self._busy:
            messagebox.showinfo("操作仍在进行", "请等待当前批次完成后关闭窗口。", parent=self)
            return
        self.destroy()
