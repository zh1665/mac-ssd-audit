---
name: mac-ssd-audit
description: Audit Mac SSD Host Writes, daily write growth, SMART health, high-growth directories, Codex SQLite log/WAL recurrence, and evidence-backed disk-write risks. Use when the user asks about SSD wear, excessive writes, SMART Host Writes, daily disk audit reports, Codex TRACE/log database growth, or preventing Codex log regressions after updates.
---

# Mac SSD Audit

## Core Rules

- Use Asia/Singapore (UTC+8) for dates, filenames, reports, and schedules unless the user explicitly asks otherwise.
- Evidence first: if a source cannot be proven from SMART deltas, directory growth, WAL/log deltas, or explicit system evidence, write `暂无直接证据` or `无法确定`.
- The daily audit is read-only except for its own bounded report/history output.
- Do not delete files, clean caches, close services, or change system settings from the audit path.
- `smartmontools` may be installed with Homebrew only when the user has allowed the tool-install exception or passes the install flag.
- Codex log guarding is a separate explicit action. Do not apply SQLite triggers, delete rows, or vacuum unless the user explicitly asks for guard/cleanup.

## Scripts

The deterministic entrypoint is `scripts/mac_ssd_audit.py`.

Run a normal daily audit:

```bash
python3 scripts/mac_ssd_audit.py audit \
  --output-dir ~/Documents/SSD_Audit_Reports \
  --state-dir ~/.local/state/mac-ssd-audit \
  --install-missing-tools \
  --online-check
```

Audit Codex log status without changing it:

```bash
python3 scripts/mac_ssd_audit.py guard-codex-logs --codex-home ~/.codex
```

Explicitly restore the Codex SQLite guard and remove existing non-essential rows:

```bash
python3 scripts/mac_ssd_audit.py guard-codex-logs \
  --codex-home ~/.codex \
  --apply \
  --delete-nonessential \
  --vacuum \
  --watch-seconds 30
```

## Report Contents

Each audit writes `SSD_Daily_Report_YYYY-MM-DD.md` plus compact JSONL history. The report includes:

- hardware, macOS, uptime, APFS/disk, memory, swap, and SMART baseline;
- Host Writes total, daily delta, per-hour average, and 7/30 day rolling averages;
- monitored sizes for Codex, R/temp, Git-related paths where supplied, browsers, system caches/logs, swap, and VM;
- growth TOP20 versus yesterday when a prior snapshot exists;
- Codex `logs*.sqlite`, WAL/SHM size, max ids, level counts, and `block_nonerror_logs_insert` trigger presence;
- anomaly detection for high daily writes, Codex log/WAL recurrence, large directory growth, swap risk, and SMART risk;
- public GitHub issue search for Codex logging/SQLite/SSD-write issues when online checking is enabled;
- self-audit bytes written by the audit itself.

## Scheduling Guidance

Default schedule: once daily after login/boot, delayed a few minutes. Do not run as a high-frequency daemon by default.

Recommended modes:

- Daily baseline: 1 run/day.
- Short investigation: 2 runs/day for a few days.
- Burst mode: hourly for 1-3 days only when the user explicitly asks.

The audit should stay small: one Markdown report and compact JSONL records, normally KB-scale per day.

## Interpreting Results

- SMART Host Writes proves device-level writes, but not the process source.
- Directory growth can support attribution only for retained files; it cannot prove transient writes that were deleted before the scan.
- WAL growth and SQLite row deltas support Codex log-write recurrence.
- If evidence is incomplete, state the uncertainty rather than guessing.
