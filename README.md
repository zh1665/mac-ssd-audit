# mac-ssd-audit

Evidence-first Mac SSD write auditing for Codex users.

This project provides a Codex skill plus a deterministic Python script that:

- reads SMART Host Writes and SSD health with `smartctl`;
- collects macOS hardware, uptime, disk, APFS, memory, and swap baselines;
- snapshots selected application/system directories and reports TOP growth versus the previous run;
- checks Codex `logs*.sqlite` databases, WAL/SHM files, level counts, max ids, and the `block_nonerror_logs_insert` guard trigger;
- optionally searches public GitHub issues for Codex logging, SQLite, or SSD-write problems;
- writes a daily Markdown report and compact JSONL history;
- includes an explicit Codex log guard command for users who want to block non-ERROR SQLite log rows.

The daily audit is designed to be read-only except for its own bounded output files. It does not delete files, clear caches, close services, or change system settings.

## Quick start

```bash
python3 scripts/mac_ssd_audit.py audit \
  --output-dir ~/Documents/SSD_Audit_Reports \
  --state-dir ~/.local/state/mac-ssd-audit \
  --install-missing-tools \
  --online-check
```

If `smartctl` is missing, `--install-missing-tools` installs `smartmontools` through Homebrew. Without that flag, the audit reports that SMART collection is unavailable.

## Codex log guard

Audit only:

```bash
python3 scripts/mac_ssd_audit.py guard-codex-logs --codex-home ~/.codex
```

Apply the SQLite trigger and remove existing non-ERROR rows:

```bash
python3 scripts/mac_ssd_audit.py guard-codex-logs \
  --codex-home ~/.codex \
  --apply \
  --delete-nonessential \
  --vacuum \
  --watch-seconds 30
```

## Scheduling

Use the LaunchAgent template in `templates/com.zhari.mac-ssd-audit.plist` for a once-daily run after login/boot. The default design is one run per day; high-frequency auditing should be temporary and explicit.

## Evidence limits

SMART Host Writes proves total device writes, but not the responsible process. Directory growth can support attribution only when files remain on disk at scan time. Transient writes that are later deleted may remain `无法确定`.
