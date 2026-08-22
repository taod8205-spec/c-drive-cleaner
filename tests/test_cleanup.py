import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

from cleaner.cleanup import CleanupExecutor, CleanupMode, WindowsRemovalBackend
from cleaner.models import Candidate, DirectoryIdentity, FileFingerprint, RiskLevel
from cleaner.quarantine import QuarantineStore


class RecordingRemovalBackend:
    def __init__(self) -> None:
        self.quarantined: list[Path] = []
        self.deleted: list[Path] = []

    def quarantine(self, candidate: Candidate) -> None:
        self.quarantined.append(candidate.path)

    def permanently_delete(self, candidate: Candidate) -> None:
        self.deleted.append(candidate.path)


def candidate_for(path: Path, source_root: Path) -> Candidate:
    stat = path.stat()
    return Candidate(
        candidate_id="candidate-id",
        path=path,
        source_root=source_root,
        source_root_identity=DirectoryIdentity.from_stat(source_root.stat()),
        rule_id="test-rule",
        category="测试缓存",
        size_bytes=stat.st_size,
        modified_at=datetime.fromtimestamp(stat.st_mtime, UTC),
        risk=RiskLevel.LOW,
        reason="测试候选项",
        fingerprint=FileFingerprint.from_stat(stat),
    )


class CleanupExecutorTests(unittest.TestCase):
    def test_execute_processes_only_explicitly_reviewed_candidates(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected.tmp"
            selected.write_bytes(b"selected")
            unselected = root / "unselected.tmp"
            unselected.write_bytes(b"unselected")
            backend = RecordingRemovalBackend()
            executor = CleanupExecutor(backend=backend, allowed_drive=root.drive)

            result = executor.execute(
                [candidate_for(selected, root)], mode=CleanupMode.QUARANTINE
            )

            self.assertEqual([selected], backend.quarantined)
            self.assertEqual([], backend.deleted)
            self.assertEqual(1, result.success_count)
            self.assertEqual(0, result.failure_count)
            self.assertTrue(unselected.exists())

    def test_execute_rejects_a_candidate_outside_its_approved_source(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            base = Path(temp_dir)
            approved_root = base / "approved"
            approved_root.mkdir()
            outside = base / "outside.tmp"
            outside.write_bytes(b"keep")
            backend = RecordingRemovalBackend()
            executor = CleanupExecutor(backend=backend, allowed_drive=base.drive)

            result = executor.execute(
                [candidate_for(outside, approved_root)], mode=CleanupMode.QUARANTINE
            )

            self.assertEqual([], backend.quarantined)
            self.assertEqual(1, result.failure_count)
            self.assertIn("不在允许的清理目录内", result.items[0].message)
            self.assertTrue(outside.exists())

    def test_execute_rejects_a_file_changed_since_scan(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            changed = root / "changed.tmp"
            changed.write_bytes(b"before")
            candidate = candidate_for(changed, root)
            changed.write_bytes(b"after scan, larger")
            changed.touch()
            # Ensure filesystems with coarse timestamps also expose a changed size.
            self.assertNotEqual(candidate.size_bytes, changed.stat().st_size)
            backend = RecordingRemovalBackend()
            executor = CleanupExecutor(backend=backend, allowed_drive=root.drive)

            result = executor.execute([candidate], mode=CleanupMode.PERMANENT)

            self.assertEqual([], backend.deleted)
            self.assertEqual(1, result.failure_count)
            self.assertIn("扫描后已发生变化", result.items[0].message)
            self.assertTrue(changed.exists())

    def test_execute_never_permanently_deletes_high_risk_candidates(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            sensitive = root / "diagnostic.dmp"
            sensitive.write_bytes(b"diagnostic evidence")
            low_risk_candidate = candidate_for(sensitive, root)
            high_risk_candidate = Candidate(
                candidate_id=low_risk_candidate.candidate_id,
                path=low_risk_candidate.path,
                source_root=low_risk_candidate.source_root,
                source_root_identity=low_risk_candidate.source_root_identity,
                rule_id=low_risk_candidate.rule_id,
                category=low_risk_candidate.category,
                size_bytes=low_risk_candidate.size_bytes,
                modified_at=low_risk_candidate.modified_at,
                risk=RiskLevel.HIGH,
                reason="诊断证据",
                fingerprint=low_risk_candidate.fingerprint,
            )
            backend = RecordingRemovalBackend()
            executor = CleanupExecutor(backend=backend)

            result = executor.execute(
                [high_risk_candidate], mode=CleanupMode.PERMANENT
            )

            self.assertEqual([], backend.deleted)
            self.assertEqual(1, result.failure_count)
            self.assertIn("高风险", result.items[0].message)
            self.assertTrue(sensitive.exists())

    def test_execute_rejects_a_replaced_source_root_even_if_file_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            base = Path(temp_dir)
            root = base / "approved"
            root.mkdir()
            original = root / "cache.tmp"
            original.write_bytes(b"same file identity")
            candidate = candidate_for(original, root)

            holding_link = base / "holding.tmp"
            os.link(original, holding_link)
            moved_root = base / "moved-approved"
            root.rename(moved_root)
            root.mkdir()
            replacement_path = root / "cache.tmp"
            os.link(holding_link, replacement_path)
            backend = RecordingRemovalBackend()

            result = CleanupExecutor(backend=backend, allowed_drive=base.drive).execute(
                [candidate], mode=CleanupMode.QUARANTINE
            )

            self.assertEqual([], backend.quarantined)
            self.assertEqual(1, result.failure_count)
            self.assertIn("清理目录", result.items[0].message)
            self.assertTrue(replacement_path.exists())

    def test_execute_rejects_non_c_drive_candidates_before_file_access(self) -> None:
        forged = Candidate(
            candidate_id="forged-d-drive",
            path=Path(r"D:\Temp\cache.tmp"),
            source_root=Path(r"D:\Temp"),
            source_root_identity=DirectoryIdentity(1, 1),
            rule_id="forged",
            category="伪造候选项",
            size_bytes=1,
            modified_at=datetime.now(UTC),
            risk=RiskLevel.LOW,
            reason="测试",
            fingerprint=FileFingerprint(1, 1, 1, 1),
        )
        backend = RecordingRemovalBackend()

        result = CleanupExecutor(backend=backend).execute(
            [forged], mode=CleanupMode.QUARANTINE
        )

        self.assertEqual([], backend.quarantined)
        self.assertEqual(1, result.failure_count)
        self.assertIn("C 盘", result.items[0].message)

    def test_execute_rejects_drive_relative_candidates(self) -> None:
        forged = Candidate(
            candidate_id="forged-drive-relative",
            path=Path(r"C:Temp\cache.tmp"),
            source_root=Path(r"C:Temp"),
            source_root_identity=DirectoryIdentity(1, 1),
            rule_id="forged",
            category="伪造候选项",
            size_bytes=1,
            modified_at=datetime.now(UTC),
            risk=RiskLevel.LOW,
            reason="测试",
            fingerprint=FileFingerprint(1, 1, 1, 1),
        )

        result = CleanupExecutor(backend=RecordingRemovalBackend()).execute(
            [forged], mode=CleanupMode.QUARANTINE
        )

        self.assertEqual(1, result.failure_count)
        self.assertIn("绝对路径", result.items[0].message)

    @unittest.skipUnless(os.name == "nt", "Windows 句柄接口测试")
    def test_windows_backend_rejects_leaf_replacement_after_review(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            reviewed = root / "reviewed.tmp"
            reviewed.write_bytes(b"reviewed bytes")
            candidate = candidate_for(reviewed, root)
            moved = root / "moved-original.tmp"
            reviewed.rename(moved)
            reviewed.write_bytes(b"replacement!!!")
            os.utime(
                reviewed,
                ns=(candidate.fingerprint.modified_ns, candidate.fingerprint.modified_ns),
            )

            with self.assertRaises(OSError):
                WindowsRemovalBackend().permanently_delete(candidate)

            self.assertTrue(reviewed.exists())
            self.assertTrue(moved.exists())

    @unittest.skipUnless(os.name == "nt", "Windows 句柄接口测试")
    def test_windows_backend_closes_handle_when_quarantine_prepare_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            reviewed = root / "reviewed.tmp"
            reviewed.write_bytes(b"reviewed bytes")
            candidate = candidate_for(reviewed, root)
            store = Mock(spec=QuarantineStore)
            store.prepare.side_effect = PermissionError("blocked")
            backend = WindowsRemovalBackend(store)

            with (
                patch.object(backend, "_open_verified_candidate", return_value=987),
                patch("cleaner.cleanup.close_windows_handle") as close_handle,
                self.assertRaises(PermissionError),
            ):
                backend.quarantine(candidate)

            close_handle.assert_called_once_with(987)
            store.discard_prepared.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows 隔离区测试")
    def test_windows_quarantine_can_restore_the_exact_reviewed_file(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            base = Path(temp_dir)
            source_root = base / "source"
            source_root.mkdir()
            reviewed = source_root / "reviewed.tmp"
            reviewed.write_bytes(b"reviewed bytes")
            app_data = base / "appdata"
            app_data.mkdir()
            store = QuarantineStore(
                app_data / "慎清" / "Quarantine", allowed_drive=base.drive
            )

            WindowsRemovalBackend(store).quarantine(candidate_for(reviewed, source_root))

            self.assertFalse(reviewed.exists())
            entries = store.list_entries()
            self.assertEqual(1, len(entries))
            self.assertEqual(b"reviewed bytes", entries[0].stored_path.read_bytes())

            store.restore(entries[0])

            self.assertEqual(b"reviewed bytes", reviewed.read_bytes())
            self.assertEqual([], store.list_entries())

    @unittest.skipUnless(os.name == "nt", "Windows 隔离区测试")
    def test_windows_quarantine_restore_never_overwrites_original_path(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            base = Path(temp_dir)
            source_root = base / "source"
            source_root.mkdir()
            reviewed = source_root / "reviewed.tmp"
            reviewed.write_bytes(b"reviewed bytes")
            app_data = base / "appdata"
            app_data.mkdir()
            store = QuarantineStore(
                app_data / "慎清" / "Quarantine", allowed_drive=base.drive
            )
            WindowsRemovalBackend(store).quarantine(candidate_for(reviewed, source_root))
            entry = store.list_entries()[0]
            reviewed.write_bytes(b"new occupant")

            with self.assertRaises(FileExistsError):
                store.restore(entry)

            self.assertEqual(b"new occupant", reviewed.read_bytes())
            self.assertEqual(b"reviewed bytes", entry.stored_path.read_bytes())

    @unittest.skipUnless(os.name == "nt", "Windows 隔离区测试")
    def test_windows_quarantine_permanent_delete_requires_a_non_high_risk_entry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            base = Path(temp_dir)
            source_root = base / "source"
            source_root.mkdir()
            reviewed = source_root / "reviewed.tmp"
            reviewed.write_bytes(b"reviewed bytes")
            app_data = base / "appdata"
            app_data.mkdir()
            store = QuarantineStore(
                app_data / "慎清" / "Quarantine", allowed_drive=base.drive
            )
            WindowsRemovalBackend(store).quarantine(candidate_for(reviewed, source_root))
            entry = store.list_entries()[0]

            store.permanently_delete(entry)

            self.assertFalse(entry.stored_path.exists())
            self.assertEqual([], store.list_entries())

    @unittest.skipUnless(os.name == "nt", "Windows 隔离区测试")
    def test_quarantine_store_never_permanently_deletes_high_risk(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            base = Path(temp_dir)
            source_root = base / "source"
            source_root.mkdir()
            reviewed = source_root / "reviewed.tmp"
            reviewed.write_bytes(b"reviewed bytes")
            app_data = base / "appdata"
            app_data.mkdir()
            store = QuarantineStore(
                app_data / "慎清" / "Quarantine", allowed_drive=base.drive
            )
            WindowsRemovalBackend(store).quarantine(candidate_for(reviewed, source_root))
            entry = replace(store.list_entries()[0], risk=RiskLevel.HIGH)

            with self.assertRaises(ValueError):
                store.permanently_delete(entry)

            self.assertTrue(entry.stored_path.exists())

    @unittest.skipUnless(os.name == "nt", "Windows 隔离区测试")
    def test_quarantine_inspection_reports_a_corrupt_manifest(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            base = Path(temp_dir)
            source_root = base / "source"
            source_root.mkdir()
            reviewed = source_root / "reviewed.tmp"
            reviewed.write_bytes(b"reviewed bytes")
            app_data = base / "appdata"
            app_data.mkdir()
            store = QuarantineStore(
                app_data / "慎清" / "Quarantine", allowed_drive=base.drive
            )
            WindowsRemovalBackend(store).quarantine(candidate_for(reviewed, source_root))
            entry = store.list_entries()[0]
            entry.manifest_path.write_text(
                '{"fingerprint": []}', encoding="utf-8"
            )

            report = store.inspect_entries()

            self.assertEqual([], report.entries)
            self.assertEqual(1, len(report.warnings))
            self.assertTrue(entry.stored_path.exists())

    @unittest.skipUnless(os.name == "nt", "Windows 隔离区测试")
    def test_quarantine_inspection_reports_deeply_nested_json(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            base = Path(temp_dir)
            source_root = base / "source"
            source_root.mkdir()
            reviewed = source_root / "reviewed.tmp"
            reviewed.write_bytes(b"reviewed bytes")
            app_data = base / "appdata"
            app_data.mkdir()
            store = QuarantineStore(
                app_data / "慎清" / "Quarantine", allowed_drive=base.drive
            )
            WindowsRemovalBackend(store).quarantine(candidate_for(reviewed, source_root))
            entry = store.list_entries()[0]
            entry.manifest_path.write_text(
                "[" * 2_000 + "0" + "]" * 2_000, encoding="utf-8"
            )

            report = store.inspect_entries()

            self.assertEqual([], report.entries)
            self.assertEqual(1, len(report.warnings))
            self.assertTrue(entry.stored_path.exists())

    @unittest.skipUnless(os.name == "nt", "Windows 隔离区测试")
    def test_quarantine_restore_rejects_a_replaced_entry_directory(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            base = Path(temp_dir)
            source_root = base / "source"
            source_root.mkdir()
            reviewed = source_root / "reviewed.tmp"
            reviewed.write_bytes(b"reviewed bytes")
            app_data = base / "appdata"
            app_data.mkdir()
            store = QuarantineStore(
                app_data / "慎清" / "Quarantine", allowed_drive=base.drive
            )
            WindowsRemovalBackend(store).quarantine(candidate_for(reviewed, source_root))
            entry = store.list_entries()[0]
            moved_entry_dir = entry.stored_path.parent.with_name("moved-entry")
            entry.stored_path.parent.rename(moved_entry_dir)
            entry.stored_path.parent.mkdir()

            with self.assertRaises(OSError):
                store.restore(entry)

            self.assertTrue((moved_entry_dir / "payload").exists())
            self.assertFalse(reviewed.exists())

    @unittest.skipUnless(os.name == "nt", "Windows 隔离区测试")
    def test_restore_reports_metadata_failure_after_the_file_is_restored(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            base = Path(temp_dir)
            source_root = base / "source"
            source_root.mkdir()
            reviewed = source_root / "reviewed.tmp"
            reviewed.write_bytes(b"reviewed bytes")
            app_data = base / "appdata"
            app_data.mkdir()
            store = QuarantineStore(
                app_data / "慎清" / "Quarantine", allowed_drive=base.drive
            )
            WindowsRemovalBackend(store).quarantine(candidate_for(reviewed, source_root))
            entry = store.list_entries()[0]

            with patch.object(
                Path, "unlink", side_effect=PermissionError("metadata blocked")
            ):
                warning = store.restore(entry)

            self.assertEqual(b"reviewed bytes", reviewed.read_bytes())
            self.assertIn("文件操作已完成", warning or "")
            report = store.inspect_entries()
            self.assertEqual([], report.entries)
            self.assertEqual(1, len(report.warnings))
            self.assertIn("payload 文件缺失", report.warnings[0])

    @unittest.skipUnless(os.name == "nt", "Windows 隔离区测试")
    def test_quarantine_inspection_rejects_unsafe_manifest_values(self) -> None:
        unsafe_values = (
            ("quarantined_at", "2026-08-22T12:00:00"),
            ("size_bytes", 10**400),
        )
        for field, value in unsafe_values:
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
                    base = Path(temp_dir)
                    source_root = base / "source"
                    source_root.mkdir()
                    reviewed = source_root / "reviewed.tmp"
                    reviewed.write_bytes(b"reviewed bytes")
                    app_data = base / "appdata"
                    app_data.mkdir()
                    store = QuarantineStore(
                        app_data / "慎清" / "Quarantine",
                        allowed_drive=base.drive,
                    )
                    WindowsRemovalBackend(store).quarantine(
                        candidate_for(reviewed, source_root)
                    )
                    entry = store.list_entries()[0]
                    payload = json.loads(entry.manifest_path.read_text(encoding="utf-8"))
                    payload[field] = value
                    entry.manifest_path.write_text(
                        json.dumps(payload, ensure_ascii=False), encoding="utf-8"
                    )

                    report = store.inspect_entries()

                    self.assertEqual([], report.entries)
                    self.assertEqual(1, len(report.warnings))
                    self.assertTrue(entry.stored_path.exists())


if __name__ == "__main__":
    unittest.main()
