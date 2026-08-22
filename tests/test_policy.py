import unittest
from pathlib import Path

from cleaner.models import RiskLevel
from cleaner.policy import build_default_policy


class DefaultPolicyTests(unittest.TestCase):
    def test_default_policy_is_age_gated_and_avoids_personal_folders(self) -> None:
        environment = {
            "SystemDrive": "C:",
            "WINDIR": r"C:\Windows",
            "LOCALAPPDATA": r"C:\Users\Reviewer\AppData\Local",
            "ProgramData": r"C:\ProgramData",
            "USERPROFILE": r"C:\Users\Reviewer",
            "ProgramFiles": r"C:\Program Files",
            "ProgramFiles(x86)": r"C:\Program Files (x86)",
        }

        policy = build_default_policy(environment, discover_browser_profiles=False)

        self.assertGreaterEqual(len(policy.rules), 6)
        self.assertTrue(all(rule.min_age_days >= 7 for rule in policy.rules))
        scanned_roots = {str(rule.root).casefold() for rule in policy.rules}
        for personal_name in (
            "desktop",
            "documents",
            "downloads",
            "pictures",
            "music",
            "videos",
            "onedrive",
        ):
            self.assertFalse(
                any(f"\\{personal_name}" in root for root in scanned_roots),
                personal_name,
            )

    def test_sensitive_system_caches_are_marked_high_risk(self) -> None:
        environment = {
            "SystemDrive": "C:",
            "WINDIR": r"C:\Windows",
            "LOCALAPPDATA": r"C:\Users\Reviewer\AppData\Local",
            "ProgramData": r"C:\ProgramData",
            "USERPROFILE": r"C:\Users\Reviewer",
        }

        policy = build_default_policy(environment, discover_browser_profiles=False)
        rules_by_id = {rule.rule_id: rule for rule in policy.rules}

        self.assertEqual(
            RiskLevel.HIGH, rules_by_id["windows-update-downloads"].risk
        )
        self.assertEqual(RiskLevel.HIGH, rules_by_id["windows-minidumps"].risk)
        self.assertIn("不要清理", rules_by_id["windows-minidumps"].reason)

    def test_protected_roots_include_personal_and_critical_system_locations(self) -> None:
        environment = {
            "SystemDrive": "C:",
            "WINDIR": r"C:\Windows",
            "LOCALAPPDATA": r"C:\Users\Reviewer\AppData\Local",
            "ProgramData": r"C:\ProgramData",
            "USERPROFILE": r"C:\Users\Reviewer",
            "ProgramFiles": r"C:\Program Files",
        }

        policy = build_default_policy(environment, discover_browser_profiles=False)
        protected = {str(path).casefold() for path in policy.protected_roots}

        self.assertIn(str(Path(r"C:\Windows\System32")).casefold(), protected)
        self.assertIn(
            str(Path(r"C:\Users\Reviewer\Documents")).casefold(), protected
        )
        self.assertIn(str(Path(r"C:\Program Files")).casefold(), protected)


if __name__ == "__main__":
    unittest.main()
