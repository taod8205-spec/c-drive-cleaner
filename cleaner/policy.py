from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .models import RiskLevel, ScanRule
from .safety import DirectoryChainLock, DirectoryLockError, is_reparse_point


@dataclass(frozen=True, slots=True)
class CleanupPolicy:
    rules: tuple[ScanRule, ...]
    protected_roots: tuple[Path, ...]
    system_drive: str


def _path(environment: Mapping[str, str], name: str, fallback: str) -> Path:
    return Path(environment.get(name) or fallback)


def _on_drive(path: Path, drive: str) -> bool:
    return (
        path.is_absolute()
        and bool(path.anchor)
        and path.drive.rstrip("\\/").casefold() == drive.casefold()
    )


def _browser_rules(
    *,
    product_id: str,
    product_name: str,
    user_data_root: Path,
    system_drive: str,
    discover_profiles: bool,
) -> list[ScanRule]:
    profiles: dict[str, Path] = {"default": user_data_root / "Default"}
    if discover_profiles:
        try:
            with DirectoryChainLock(user_data_root):
                with os.scandir(user_data_root) as entries:
                    for entry in entries:
                        entry_stat = entry.stat(follow_symlinks=False)
                        if (
                            stat.S_ISDIR(entry_stat.st_mode)
                            and not entry.is_symlink()
                            and not is_reparse_point(entry_stat)
                            and entry.name.casefold().startswith("profile ")
                        ):
                            profiles[entry.name.casefold()] = Path(entry.path)
        except (DirectoryLockError, OSError):
            pass

    rules: list[ScanRule] = []
    for profile_key, profile_root in profiles.items():
        if not _on_drive(profile_root, system_drive):
            continue
        safe_profile_id = profile_key.replace(" ", "-")
        for cache_id, relative_path, label in (
            ("http-cache", Path("Cache") / "Cache_Data", "网页缓存"),
            ("code-cache", Path("Code Cache"), "代码缓存"),
            ("gpu-cache", Path("GPUCache"), "图形缓存"),
        ):
            rules.append(
                ScanRule(
                    rule_id=f"{product_id}-{safe_profile_id}-{cache_id}",
                    category=f"{product_name}{label}",
                    root=profile_root / relative_path,
                    min_age_days=14,
                    risk=RiskLevel.MEDIUM,
                    reason=(
                        f"{product_name}可重建此缓存，但浏览器运行时不应清理；"
                        "可能导致首次打开页面变慢。"
                    ),
                )
            )
    return rules


def build_default_policy(
    environment: Mapping[str, str] | None = None,
    *,
    discover_browser_profiles: bool = True,
) -> CleanupPolicy:
    """构建只覆盖明确缓存位置的保守策略，不枚举个人资料目录。"""

    env = environment if environment is not None else os.environ
    system_drive = "C:"
    windir = _path(env, "WINDIR", f"{system_drive}\\Windows")
    local_app_data = _path(
        env, "LOCALAPPDATA", f"{system_drive}\\Users\\Default\\AppData\\Local"
    )
    program_data = _path(env, "ProgramData", f"{system_drive}\\ProgramData")
    user_profile = _path(env, "USERPROFILE", f"{system_drive}\\Users\\Default")

    rules = [
        ScanRule(
            rule_id="user-temp",
            category="用户临时文件",
            root=local_app_data / "Temp",
            min_age_days=7,
            risk=RiskLevel.LOW,
            reason="超过 7 天的用户临时文件；应用通常不再需要，但仍请核对文件名。",
        ),
        ScanRule(
            rule_id="crash-dumps",
            category="应用崩溃转储",
            root=local_app_data / "CrashDumps",
            min_age_days=30,
            risk=RiskLevel.MEDIUM,
            reason="超过 30 天的应用崩溃诊断文件；近期仍在排查崩溃时请保留。",
            patterns=("*.dmp",),
        ),
        ScanRule(
            rule_id="thumbnail-cache",
            category="缩略图缓存",
            root=local_app_data / "Microsoft" / "Windows" / "Explorer",
            min_age_days=14,
            risk=RiskLevel.MEDIUM,
            reason="Windows 会重建缩略图，清理后首次浏览图片文件夹可能较慢。",
            patterns=("thumbcache*.db",),
            recursive=False,
        ),
        ScanRule(
            rule_id="windows-temp",
            category="Windows 临时文件",
            root=windir / "Temp",
            min_age_days=14,
            risk=RiskLevel.MEDIUM,
            reason="超过 14 天的系统临时文件；可能需要管理员权限，正在使用的文件会失败。",
        ),
        ScanRule(
            rule_id="wer-archive",
            category="Windows 错误报告归档",
            root=program_data / "Microsoft" / "Windows" / "WER" / "ReportArchive",
            min_age_days=30,
            risk=RiskLevel.MEDIUM,
            reason="超过 30 天的错误诊断归档；正在排查系统问题时应保留。",
        ),
        ScanRule(
            rule_id="wer-queue",
            category="Windows 错误报告队列",
            root=program_data / "Microsoft" / "Windows" / "WER" / "ReportQueue",
            min_age_days=30,
            risk=RiskLevel.MEDIUM,
            reason="超过 30 天的待上报诊断数据；可能仍对故障分析有用。",
        ),
        ScanRule(
            rule_id="windows-update-downloads",
            category="Windows 更新下载缓存",
            root=windir / "SoftwareDistribution" / "Download",
            min_age_days=30,
            risk=RiskLevel.HIGH,
            reason=(
                "可能影响待安装或回滚中的更新；除非确认 Windows 更新已完成且运行正常，"
                "否则不要清理。"
            ),
        ),
        ScanRule(
            rule_id="windows-minidumps",
            category="Windows 小型内存转储",
            root=windir / "Minidump",
            min_age_days=30,
            risk=RiskLevel.HIGH,
            reason="蓝屏诊断的重要证据；仍在排查系统故障时不要清理。",
            patterns=("*.dmp",),
        ),
    ]

    if _on_drive(local_app_data, system_drive):
        rules.extend(
            _browser_rules(
                product_id="edge",
                product_name="Microsoft Edge",
                user_data_root=local_app_data
                / "Microsoft"
                / "Edge"
                / "User Data",
                system_drive=system_drive,
                discover_profiles=discover_browser_profiles,
            )
        )
        rules.extend(
            _browser_rules(
                product_id="chrome",
                product_name="Google Chrome",
                user_data_root=local_app_data
                / "Google"
                / "Chrome"
                / "User Data",
                system_drive=system_drive,
                discover_profiles=discover_browser_profiles,
            )
        )

    rules = [rule for rule in rules if _on_drive(rule.root, system_drive)]

    protected_roots = [
        windir / "System32",
        windir / "SysWOW64",
        windir / "WinSxS",
        windir / "Installer",
        windir / "servicing",
        Path(f"{system_drive}\\$Recycle.Bin"),
        Path(f"{system_drive}\\System Volume Information"),
        _path(env, "ProgramFiles", f"{system_drive}\\Program Files"),
        _path(env, "ProgramFiles(x86)", f"{system_drive}\\Program Files (x86)"),
        program_data / "Package Cache",
        user_profile / "Desktop",
        user_profile / "Documents",
        user_profile / "Downloads",
        user_profile / "Pictures",
        user_profile / "Music",
        user_profile / "Videos",
        user_profile / "OneDrive",
        user_profile / "AppData" / "Roaming",
    ]
    protected_roots = [
        path for path in protected_roots if _on_drive(path, system_drive)
    ]
    return CleanupPolicy(
        rules=tuple(rules),
        protected_roots=tuple(protected_roots),
        system_drive=system_drive,
    )
