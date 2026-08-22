import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cleaner.cleanup import CleanupExecutor, CleanupMode
from cleaner.models import Candidate, FileFingerprint, RiskLevel


class RecordingRemovalBackend:
    def __init__(self) -> None:
        self.recycled: list[Path] = []
        self.deleted: list[Path] = []

    def recycle(self, path: Path) -> None:
        self.recycled.append(path)

    def permanently_delete(self, path: Path) -> None:
        self.deleted.append(path)


def candidate_for(path: Path, source_root: Path) -> Candidate:
    stat = path.stat()
    return Candidate(
        candidate_id="candidate-id",
        path=path,
        source_root=source_root,
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
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected.tmp"
            selected.write_bytes(b"selected")
            unselected = root / "unselected.tmp"
            unselected.write_bytes(b"unselected")
            backend = RecordingRemovalBackend()
            executor = CleanupExecutor(backend=backend)

            result = executor.execute(
                [candidate_for(selected, root)], mode=CleanupMode.RECYCLE
            )

            self.assertEqual([selected], backend.recycled)
            self.assertEqual([], backend.deleted)
            self.assertEqual(1, result.success_count)
            self.assertEqual(0, result.failure_count)
            self.assertTrue(unselected.exists())

    def test_execute_rejects_a_candidate_outside_its_approved_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            approved_root = base / "approved"
            approved_root.mkdir()
            outside = base / "outside.tmp"
            outside.write_bytes(b"keep")
            backend = RecordingRemovalBackend()
            executor = CleanupExecutor(backend=backend)

            result = executor.execute(
                [candidate_for(outside, approved_root)], mode=CleanupMode.RECYCLE
            )

            self.assertEqual([], backend.recycled)
            self.assertEqual(1, result.failure_count)
            self.assertIn("不在允许的清理目录内", result.items[0].message)
            self.assertTrue(outside.exists())

    def test_execute_rejects_a_file_changed_since_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            changed = root / "changed.tmp"
            changed.write_bytes(b"before")
            candidate = candidate_for(changed, root)
            changed.write_bytes(b"after scan, larger")
            changed.touch()
            # Ensure filesystems with coarse timestamps also expose a changed size.
            self.assertNotEqual(candidate.size_bytes, changed.stat().st_size)
            backend = RecordingRemovalBackend()
            executor = CleanupExecutor(backend=backend)

            result = executor.execute([candidate], mode=CleanupMode.PERMANENT)

            self.assertEqual([], backend.deleted)
            self.assertEqual(1, result.failure_count)
            self.assertIn("扫描后已发生变化", result.items[0].message)
            self.assertTrue(changed.exists())

    def test_execute_never_permanently_deletes_high_risk_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sensitive = root / "diagnostic.dmp"
            sensitive.write_bytes(b"diagnostic evidence")
            low_risk_candidate = candidate_for(sensitive, root)
            high_risk_candidate = Candidate(
                candidate_id=low_risk_candidate.candidate_id,
                path=low_risk_candidate.path,
                source_root=low_risk_candidate.source_root,
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


if __name__ == "__main__":
    unittest.main()
