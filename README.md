**English** | [简体中文](README.zh-CN.md)

# Shenqing · C Drive Cleanup Auditor

A conservative disk cleanup tool for Windows. Its primary goal is not to delete as much as possible, but to let you review every candidate's full path, size, timestamps, category, risk level, and risk rationale before any file operation takes place.

## Safety Design

- Scanning is read-only. Starting a scan never automatically selects or deletes any file.
- Only explicitly listed cache, temporary-file, and diagnostic directories are scanned; the tool never sweeps the entire C drive.
- Every candidate must be at least 7 days old. System-related items usually have retention thresholds of 14–30 days.
- Desktop, Documents, Downloads, Pictures, Music, Videos, OneDrive, and `AppData\Roaming` are excluded.
- Symbolic links, directory junctions, and other reparse points are not followed.
- During scanning and cleanup, the directory chain from the drive root to each candidate is locked. Any path with a link or reparse-point ancestor is rejected to prevent replacement after inspection.
- Before acting on a file, the tool revalidates its absolute path, target drive, scan-root identity, type, size, modification time, and file identity. Files replaced or modified after scanning are preserved.
- The default action is **Move to Safety Quarantine**. Quarantined items retain their original paths and can be reviewed and restored individually in the application. The quarantine is never emptied automatically.
- Quarantine and permanent deletion both operate through revalidated file handles. If a file or directory changes after review, the operation is rejected.
- Permanent deletion requires entering a confirmation phrase. High-risk items are blocked from permanent deletion in both the interface and the executor.
- If permissions are insufficient, a file is in use, or a path is abnormal, the result is **Skipped/Preserved**. The tool does not attempt privilege escalation or forcefully take ownership.

## Risk Levels

| Level | Typical candidates | Policy |
| --- | --- | --- |
| Low | Current-user temporary files older than 7 days | Still unselected by default; users may select them manually with “Select All Low-Risk” |
| Medium | Browser caches, thumbnail caches, crash dumps, Windows temporary files, error reports | Review individually and close the related applications first |
| High | Windows Update download cache, small memory dumps from system crashes | Highlighted in red; requires a review phrase; permanent deletion is prohibited |

“Low risk” does not mean “zero risk.” Installers or application sessions that have not yet ended may still use older temporary files, so the application always requires human review.

## Explicitly Excluded

- `WinSxS`, `System32`, `SysWOW64`, Windows Installer, and servicing components
- Program Files, the ProgramData Package Cache, the registry, drivers, startup items, and restore points
- Personal files, browser history/bookmarks/passwords/cookies, application settings, and roaming data
- The Windows Recycle Bin and this application's safety quarantine; neither is scanned or emptied automatically
- Directories themselves; the tool acts only on regular files identified during scanning

## Usage

The easiest way to start the application is to double-click `启动C盘清理器.cmd`. Python 3.11 or later is required. The interface uses only Python's built-in Tkinter library and has no third-party runtime dependencies.

You can also run the following command from the project directory:

```powershell
py -3 app.py
```

Recommended workflow:

1. Wait for the read-only scan to finish.
2. Filter by risk level, review each full path and its risk rationale, and use **Open File Location** to verify items when necessary.
3. Optionally export the review list as CSV.
4. Select only items you have confirmed are no longer needed.
5. Prefer **Move to Safety Quarantine**. To undo an action, open **View/Restore Quarantine** and restore items individually.
6. After confirming that the system and applications work normally, permanently delete low- or medium-risk files from quarantine individually to reclaim space. A confirmation phrase is still required, and high-risk items remain protected from permanent deletion.

## Building a Standalone EXE

Install PyInstaller in the development environment, then run:

```powershell
py -m pip install pyinstaller
.\build_exe.ps1
```

The output is written to `dist\慎清-C盘清理审查器.exe`. The application uses `asInvoker` behavior and does not request administrator privileges. Locations it cannot access are safely skipped.

## Testing

```powershell
py -3 -m unittest discover -s tests -v
```

Tests cover age thresholds, risk labeling, link skipping, explicit-selection enforcement, rejection of non-C-drive and relative paths, scan-root replacement rejection, post-scan change rejection, quarantine and restoration, preservation of the quarantine manifest after failures, and the permanent-deletion ban for high-risk items.

## Important Limitations

- Safety quarantine is reversible, but quarantined files remain on the C drive and therefore do not free disk space. Space is reclaimed only after explicit permanent deletion.
- Windows or application processes may prevent files in use from being handled. This is the expected conservative failure mode.
- High-risk items may contain update data or diagnostic evidence. Leave them unselected unless you have a clear reason to remove them.
- Keep backups of important data and an available system recovery option before use.

## Contributing and Security Reports

Read the [Contributing Guide](CONTRIBUTING.md) before submitting code. Report security vulnerabilities privately according to the [Security Policy](SECURITY.md); do not disclose exploit details or sensitive data in a public issue.

## License

This project is open source under the [MIT License](LICENSE).

## Maintainer

[@taod8205-spec](https://github.com/taod8205-spec)
