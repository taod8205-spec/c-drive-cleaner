import os
import time
import tkinter as tk
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

from cleaner.models import DirectoryIdentity, FileFingerprint, RiskLevel
from cleaner.policy import CleanupPolicy
from cleaner.quarantine import QuarantineEntry, QuarantineReport
from cleaner.ui.main_window import CleanerApp
from cleaner.ui.quarantine_window import QuarantineWindow
from cleaner.ui.window_layout import fit_window


def entry(key: str, risk: RiskLevel = RiskLevel.LOW) -> QuarantineEntry:
    return QuarantineEntry(
        entry_id=key,
        original_path=Path(f"C:/Temp/{key}.tmp"),
        stored_path=Path(f"C:/Quarantine/{key}/payload"),
        manifest_path=Path(f"C:/Quarantine/{key}/manifest.json"),
        quarantined_at=datetime.now(UTC),
        size_bytes=10,
        category="测试缓存",
        risk=risk,
        reason="测试",
        fingerprint=FileFingerprint(10, 1, 1, 1),
        entry_dir_identity=DirectoryIdentity(1, 1),
    )


class UiTests(unittest.TestCase):
    def setUp(self) -> None:
        # Only the window and fake entries are used. Never scan the real machine.
        self.scan_patch = patch.object(CleanerApp, "start_scan")
        self.scan_patch.start()
        self.addCleanup(self.scan_patch.stop)
        original_init = tk.Tk.__init__
        scaling = float(os.environ.get("CLEANER_TEST_SCALING", "1.333"))

        def scaled_init(root, *args, **kwargs):
            original_init(root, *args, **kwargs)
            root.tk.call("tk", "scaling", scaling)

        try:
            with patch.object(tk.Tk, "__init__", scaled_init):
                self.app = CleanerApp(CleanupPolicy((), (), "C:"))
        except tk.TclError as exc:
            self.skipTest(f"Tk window unavailable: {exc}")
        self.addCleanup(self.close_app)
        self.store = Mock()
        self.entries = [entry("first"), entry("second")]
        self.store.inspect_entries.side_effect = lambda: QuarantineReport(list(self.entries), [])
        self.store.restore.return_value = None
        self.store.permanently_delete.return_value = None
        self.window = QuarantineWindow(self.app, self.store)
        self.report_patch = patch.object(self.window, "_show_text_report")
        self.report = self.report_patch.start()
        self.addCleanup(self.report_patch.stop)
        for name in ("showinfo", "showerror"):
            p = patch(f"cleaner.ui.quarantine_window.messagebox.{name}")
            p.start()
            self.addCleanup(p.stop)
        self.flush()

    def close_app(self) -> None:
        self.app.update_idletasks()
        for task in self.app.tk.call("after", "info"):
            self.app.after_cancel(task)
        self.app.destroy()

    def flush(self) -> None:
        for _ in range(4):
            self.app.update()

    def complete_batch(self) -> None:
        deadline = time.monotonic() + 3
        while self.window._busy and time.monotonic() < deadline:
            self.app.update()
            time.sleep(0.002)
        self.assertFalse(self.window._busy)
        self.assertFalse(self.app._busy)

    def assert_controls_visible(self, window) -> None:
        def walk(parent):
            for widget in parent.winfo_children():
                if isinstance(widget, tk.Toplevel):
                    continue
                if widget.winfo_class() in ("TButton", "TRadiobutton", "TCombobox", "TEntry"):
                    self.assertTrue(widget.winfo_ismapped(), str(widget))
                    left = widget.winfo_rootx() - window.winfo_rootx()
                    top = widget.winfo_rooty() - window.winfo_rooty()
                    self.assertGreaterEqual(left, 0)
                    self.assertGreaterEqual(top, 0)
                    self.assertLessEqual(left + widget.winfo_width(), window.winfo_width())
                    self.assertLessEqual(top + widget.winfo_height(), window.winfo_height())
                    # It must also fit inside each clipping parent, not just the root.
                    self.assertLessEqual(
                        widget.winfo_x() + widget.winfo_width(), parent.winfo_width()
                    )
                    self.assertLessEqual(
                        widget.winfo_y() + widget.winfo_height(), parent.winfo_height()
                    )
                walk(widget)

        walk(window)

    def test_small_windows_keep_all_actions_visible_and_tables_scroll(self) -> None:
        self.app.tree.insert(
            "", "end", iid="layout-probe", values=("", "低", "测试", "1 B", "", "C:/Temp/test")
        )
        for geometry in ("760x460", "800x500", "1024x600", "1280x720"):
            with self.subTest(main=geometry):
                self.app.geometry(geometry)
                self.flush()
                self.assert_controls_visible(self.app)
                self.assertGreater(self.app.tree.winfo_height(), 45)
                _, y, _, height = self.app.tree.bbox("layout-probe")
                self.assertLessEqual(y + height, self.app.tree.winfo_height())
        for geometry in ("640x360", "800x500", "1040x520"):
            with self.subTest(quarantine=geometry):
                self.window.geometry(geometry)
                self.flush()
                self.assert_controls_visible(self.window)
                self.assertGreater(self.window._tree.winfo_height(), 45)
        for tree in (self.app.tree, self.window._tree):
            self.assertTrue(tree.cget("xscrollcommand"))
            self.assertTrue(tree.cget("yscrollcommand"))

    def test_initial_size_respects_work_area_with_taskbar(self) -> None:
        with patch("cleaner.ui.window_layout.work_area", return_value=(0, 0, 1024, 600)):
            fit_window(self.app, preferred=(1240, 800), minimum=(760, 460))
            self.flush()
        # Both the client and a title-bar/border allowance stay above the taskbar.
        self.assertLessEqual(self.app.winfo_y() + self.app.winfo_height() + 40, 600)
        self.assertLessEqual(self.app.winfo_x() + self.app.winfo_width() + 16, 1024)
        self.assert_controls_visible(self.app)

    def test_select_all_and_clear_without_automatic_selection(self) -> None:
        self.assertEqual("extended", str(self.window._tree.cget("selectmode")))
        self.assertEqual((), self.window._tree.selection())
        self.window._select_all()
        self.assertEqual({"first", "second"}, set(self.window._tree.selection()))
        self.window._clear_selection()
        self.assertEqual((), self.window._tree.selection())
        self.store.restore.assert_not_called()
        self.store.permanently_delete.assert_not_called()

    def test_cancel_batch_restores_nothing(self) -> None:
        self.window._select_all()
        with patch("cleaner.ui.quarantine_window.messagebox.askyesno", return_value=False):
            self.window._restore_selected()
        self.store.restore.assert_not_called()
        self.assertFalse(self.window._busy)

    def test_partial_restore_preserves_failed_selection_and_continues(self) -> None:
        def restore(selected):
            if selected.entry_id == "first":
                raise FileExistsError("原路径已有文件，拒绝覆盖")
            self.entries.remove(selected)

        self.store.restore.side_effect = restore
        self.window._select_all()
        with patch("cleaner.ui.quarantine_window.messagebox.askyesno", return_value=True):
            self.window._restore_selected()
        self.assertTrue(self.app._busy)
        self.complete_batch()
        self.assertEqual(
            ["first", "second"],
            [call.args[0].entry_id for call in self.store.restore.call_args_list],
        )
        self.assertEqual(("first",), self.window._tree.selection())
        self.assertIn("未完成 1", self.window._status.get())
        self.report.assert_called_once()
        self.assertIn("原路径已有文件", self.report.call_args.args[1])

    def test_mixed_high_risk_blocks_entire_delete_batch(self) -> None:
        self.entries[1] = replace(self.entries[1], risk=RiskLevel.HIGH)
        self.window.reload_entries()
        self.window._select_all()
        with patch("cleaner.ui.quarantine_window.simpledialog.askstring") as confirm:
            self.window._delete_selected()
            confirm.assert_not_called()
        self.store.permanently_delete.assert_not_called()
        self.assertFalse(self.window._busy)

    def test_delete_requires_exact_phrase_and_uses_confirmed_snapshot(self) -> None:
        self.window._select_all()
        with patch("cleaner.ui.quarantine_window.simpledialog.askstring", return_value="确认"):
            self.window._delete_selected()
        self.store.permanently_delete.assert_not_called()
        with patch(
            "cleaner.ui.quarantine_window.simpledialog.askstring", return_value="永久删除隔离项"
        ):
            self.window._delete_selected()
        # A selection change after confirmation must not change the approved batch.
        self.window._tree.selection_remove(self.window._tree.selection())
        self.complete_batch()
        self.assertEqual(
            ["first", "second"],
            [c.args[0].entry_id for c in self.store.permanently_delete.call_args_list],
        )

    def test_metadata_warning_is_reported_as_completed_operation(self) -> None:
        self.store.restore.return_value = "文件操作已完成，但隔离清单未能移除"
        self.window._tree.selection_set("first")
        with patch("cleaner.ui.quarantine_window.messagebox.askyesno", return_value=True):
            self.window._restore_selected()
        self.complete_batch()
        self.assertIn("成功 1", self.window._status.get())
        self.assertIn("清单警告 1", self.window._status.get())
        self.report.assert_called_once()

    def test_scan_completion_keeps_candidates_unchecked(self) -> None:
        from cleaner.models import ScanReport

        self.app.selected_ids.add("stale")
        self.app._scan_completed(ScanReport())
        self.assertEqual(set(), self.app.selected_ids)


if __name__ == "__main__":
    unittest.main()
