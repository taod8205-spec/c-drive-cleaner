import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cleaner.models import RiskLevel, ScanRule
from cleaner.scanner import CleanupScanner


class CleanupScannerTests(unittest.TestCase):
    def test_mixed_case_patterns_preserve_matching_and_age_gate(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            now = datetime.now(UTC)
            old = (now - timedelta(days=20)).timestamp()
            for name in ("OLD.TmP", "thumbCACHE-1.DB", "keep.txt", "fresh.tmp"):
                path = root / name
                path.write_bytes(b"test")
                if name != "fresh.tmp":
                    os.utime(path, (old, old))
            rule = ScanRule(
                rule_id="mixed-patterns",
                category="测试缓存",
                root=root,
                min_age_days=7,
                risk=RiskLevel.LOW,
                reason="测试",
                patterns=("*.TMP", "ThumbCache*.dB"),
            )
            report = CleanupScanner([rule], now=lambda: now, allowed_drive=root.drive).scan()
            self.assertEqual(
                {"OLD.TmP", "thumbCACHE-1.DB"},
                {candidate.path.name for candidate in report.candidates},
            )

    def test_scan_lists_only_old_files_with_risk_context(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            old_file = root / "old-cache.tmp"
            old_file.write_bytes(b"old cache")
            fresh_file = root / "fresh-cache.tmp"
            fresh_file.write_bytes(b"fresh cache")

            now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
            old_timestamp = (now - timedelta(days=10)).timestamp()
            fresh_timestamp = (now - timedelta(hours=2)).timestamp()
            os.utime(old_file, (old_timestamp, old_timestamp))
            os.utime(fresh_file, (fresh_timestamp, fresh_timestamp))

            rule = ScanRule(
                rule_id="test-cache",
                category="测试缓存",
                root=root,
                min_age_days=7,
                risk=RiskLevel.LOW,
                reason="超过 7 天的可重建测试缓存",
            )

            report = CleanupScanner([rule], now=lambda: now, allowed_drive=root.drive).scan()

            self.assertEqual([old_file], [item.path for item in report.candidates])
            self.assertEqual("低", report.candidates[0].risk.label)
            self.assertEqual(rule.reason, report.candidates[0].reason)
            self.assertEqual(old_file.stat().st_size, report.total_bytes)
            self.assertNotEqual(0, report.candidates[0].fingerprint.inode)
            self.assertEqual([], report.warnings)

    def test_scan_never_follows_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            root.mkdir()
            outside = base / "outside"
            outside.mkdir()
            secret = outside / "keep.txt"
            secret.write_text("do not list", encoding="utf-8")
            link = root / "linked-folder"

            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("当前 Windows 配置不允许创建符号链接")

            now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
            old_timestamp = (now - timedelta(days=10)).timestamp()
            os.utime(secret, (old_timestamp, old_timestamp))
            rule = ScanRule(
                rule_id="test-link",
                category="链接测试",
                root=root,
                min_age_days=1,
                risk=RiskLevel.LOW,
                reason="测试",
            )

            report = CleanupScanner([rule], now=lambda: now, allowed_drive=root.drive).scan()

            self.assertEqual([], report.candidates)
            self.assertTrue(any("链接" in warning for warning in report.warnings))


if __name__ == "__main__":
    unittest.main()
