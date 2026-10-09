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

SMART Host Writes measures total host writes reported by the device, not physical NAND writes or the responsible process. Directory growth can support attribution only when files remain on disk at scan time. Transient writes that are later deleted may remain `无法确定`.

## Optional short Codex diagnosis

```bash
python3 scripts/mac_ssd_audit.py diagnose-codex --seconds 30 --interval 0.25
```

This command prints JSON to stdout. It monitors both
`~/.codex/.codex-global-state.json` and its `.bak`, independently. It never
calls the log guard, deletes logs, clears caches, modifies Codex state or installs tools.
Use `--codex-home /path/to/.codex` for another profile. Duration is bounded at
600 seconds and the minimum interval is 0.05 seconds. Start with 30 seconds;
JSON parsing and hashing add observer CPU/read overhead. Unchanged inode,
mtime, ctime and size skip full reads; changed metadata still triggers content
comparison, including same-size and identical replacements.

Additional sources are explicit and optional:

```bash
python3 scripts/mac_ssd_audit.py diagnose-codex \
  --seconds 180 --interval 0.25 \
  --pid 12345 \
  --log-file /absolute/path/to/desktop-main.log \
  --smart-device /dev/disk0
```

Replace the PID with the actual desktop main process (the executable may be
named `ChatGPT`); do not select a renderer or CLI by name alone. Select the
actual desktop text log after checking its location locally. On current macOS
builds, main-process logs may be under `~/Library/Logs/com.openai.codex/` in
date subdirectories; select the newest log for the chosen main PID. Paths differ by
version; SQLite logs are a separate source and need not contain desktop events.
`--log-file` is repeatable. Missing files, unsupported counters and permission
failures are reported as unavailable, never as zero write activity.

For Apple SSDs, first run `smartctl --scan` and pass the complete discovered
`IOService:...` path as a quoted `--smart-device` argument. Do not assume
`/dev/disk0` works on every Mac. Diagnostics use `-i -A -j -d nvme`, requesting
only device identity and NVMe health counters. This avoids requesting an
unsupported Error Information Log with `-a`, which can cause a command-error
status even when Host Writes was returned. Existing daily auditing is unchanged.
An existing Homebrew `smartctl` is also found when it is absent from PATH;
nothing is installed.

`--sqlite` additionally samples existing `logs*.sqlite` files beneath Codex home.
It copies a bounded main database/WAL pair into a temporary directory and checks
source metadata before and after copying. Unstable snapshots are rejected.
SQLite opens only the disposable copy, so source DB/WAL/SHM files are never
opened with SQLite or checkpointed. Each snapshot is capped at 64 MiB and each
SQL query has a 0.5-second progress deadline. Temporary copies generate **observer
writes**, potentially substantial at a short interval; they are removed on normal
exit, and can remain if the diagnostic is forcibly terminated. For this option,
prefer a longer interval such as 2 seconds. Databases exceeding the cap are
unavailable rather than silently sampled. New databases created after startup
are not discovered until the next run.

### Interpret the metrics separately

| Metric | Meaning | What it cannot prove |
| --- | --- | --- |
| `observed_updates`, update rate | Changes in inode, mtime, ctime or size between samples | Number of all writes; a metadata-only touch also counts |
| `same_size_updates` | Observed updates even when size stays unchanged | Full file rewrite by a particular process |
| `identical_bytes_updates`, `identical_json_updates` | Observed metadata updates with equal bytes / parsed JSON | Why persistence occurred |
| `sampled_updated_file_bytes` | Sum of current sizes at observed updates | Actual bytes written; partial writes and touches may overstate it, missed updates may understate it |
| `net_size_delta_bytes` | Last valid size minus first valid size | Cumulative write volume |
| `process_disk_write.delta_bytes` | macOS `proc_pid_rusage` V2 disk-write counter for the chosen PID | Writes by all helpers, attribution to a file, or physical NAND writes |
| `device_host_writes.delta_bytes` | Whole-device NVMe Host Writes from optional `smartctl -i -A -j -d nvme`, in 512,000-byte units | Codex attribution or physical NAND writes |
| Text log line / target event rate | New complete newline-terminated lines; target match counted once per line | Unlogged upstream events; lines are not guaranteed to equal events |
| SQLite row rate | Count of retained rows with integer ID above the previous maximum, divided by covered time | Events blocked by a guard or deleted before sampling; max-ID difference is not a row count |

Backup and primary rates are separate. `repeated_update_detected` means at least
two observed metadata updates, **not** a verdict of abnormal SSD wear. Polling
can coalesce rapid changes; no finite poll interval guarantees every rewrite
will be observed. State errors break comparison continuity. File rotation,
truncation, counter reset and PID reuse invalidate or rebaseline affected
measurements. Text-log baseline starts at EOF; rotation starts a new baseline at
EOF and can miss its initial lines. Same-inode truncate-and-regrow between polls
can also be missed. SQLite ID reuse without an observable reset can undercount.
Errors and covered durations are retained so zero rates are not confused with
missing evidence. Rates use monotonic elapsed time and are interval averages,
not event-timestamp rates.

Process and SMART endpoint windows include sampling overhead and are slightly
longer than the file observation window; they should not be equated exactly.
Whole-device counters can include temporary SQLite snapshot writes and other
applications. Counter identity changes or negative deltas produce unavailable
results. Without `--smart-device`, daily SMART auditing still works unchanged.
No elevated command or installation is attempted by diagnostics.

Reports omit raw state, content hashes, log lines, thread IDs and message values;
explicit log/database paths and the selected PID do appear, so review those
before sharing the JSON. stdout redirection writes the report you choose:

```bash
python3 scripts/mac_ssd_audit.py diagnose-codex --seconds 30 > codex-diagnostic.json
```

### Evidence and validation

The pre-upgrade daily detector compares retained directory sizes and SQLite
stocks, with SMART daily deltas and WAL size thresholds. Its two existing tests
covered SMART parsing and directory growth, not equal-size rewrites or log rates.
These are confirmed detection gaps: daily device totals may still flag a large
increase, but cannot reliably identify these short bursts or their source.

Test scenarios are motivated by [openai/codex#51288](https://github.com/openai/codex/issues/51288)
(repeated primary/backup persistence including unchanged JSON) and
[openai/codex#52091](https://github.com/openai/codex/issues/52091)
(130,055 target messages in 16.651 seconds). They are issue reports, not proof
that your Mac is affected. Co-occurring file updates, writes, log storms and
crashes establish neither write attribution nor crash causation. The non-ERROR
guard can reduce retained SQLite rows while upstream repeated events continue;
a zero SQLite rate with a guard does not establish a fix.

Run the standard-library simulation suite and original regression checks:

```bash
python3 -m unittest discover -s tests -v
python3 tests/test_mac_ssd_audit.py
```

Simulations cover nine equal-size identical replacements, JSON reordering,
metadata-only touches, partial lines, a 130,055-line burst, rotation/truncation,
WAL snapshot safety, guarded rows, ID gaps/reset, unavailable/unstable sources,
counter reset/PID reuse, and both script distributions. These tests run without
macOS or additional Python dependencies. Additional regressions verify the Apple
NVMe command, Homebrew lookup, and skipping full state reads when metadata is
unchanged. On 2026-10-09, both `proc_pid_rusage` and NVMe Host Writes were read
successfully on an Apple Silicon Mac with smartmontools 7.5; this does not
guarantee availability on every Mac or confirm that a Codex bug is fixed.
