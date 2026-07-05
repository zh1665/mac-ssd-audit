#!/usr/bin/env python3
"""Evidence-first Mac SSD write audit and Codex log guard."""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo


TZ = ZoneInfo("Asia/Singapore")
TRIGGER_NAME = "block_nonerror_logs_insert"
TRIGGER_SQL = f"""
CREATE TRIGGER IF NOT EXISTS {TRIGGER_NAME}
BEFORE INSERT ON logs
WHEN NEW.level != 'ERROR'
BEGIN
  SELECT RAISE(IGNORE);
END;
"""


def now_sgt() -> dt.datetime:
    return dt.datetime.now(TZ)


def run(cmd: list[str], timeout: int = 30) -> dict[str, Any]:
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "elapsed_seconds": round(time.time() - started, 3),
        }
    except Exception as exc:
        return {"cmd": cmd, "error": str(exc), "elapsed_seconds": round(time.time() - started, 3)}


def bytes_human(num: int | float | None) -> str:
    if num is None:
        return "unknown"
    n = float(num)
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if abs(n) < 1024 or unit == "PB":
            return f"{n:.2f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.2f} PB"


def find_smartctl() -> str | None:
    for candidate in [
        shutil.which("smartctl"),
        "/opt/homebrew/bin/smartctl",
        "/usr/local/bin/smartctl",
    ]:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def install_smartmontools_if_missing(allow_install: bool) -> dict[str, Any]:
    smartctl = find_smartctl()
    if smartctl:
        return {"installed": True, "path": smartctl, "action": "already_present"}
    if not allow_install:
        return {"installed": False, "action": "missing_not_installed"}
    brew = shutil.which("brew") or "/opt/homebrew/bin/brew"
    if not Path(brew).exists():
        return {"installed": False, "action": "homebrew_missing", "brew": brew}
    result = run([brew, "install", "smartmontools"], timeout=600)
    smartctl = find_smartctl()
    return {
        "installed": bool(smartctl),
        "path": smartctl,
        "action": "install_attempted",
        "install_result": result,
    }


def parse_smartctl(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"raw_available": bool(text)}
    patterns = {
        "model": r"Model Number:\s+(.+)",
        "serial": r"Serial Number:\s+(.+)",
        "health": r"SMART overall-health self-assessment test result:\s+(.+)",
        "temperature_c": r"Temperature:\s+([0-9]+)\s+Celsius",
        "power_on_hours": r"Power On Hours:\s+([0-9,]+)",
        "available_spare_percent": r"Available Spare:\s+([0-9]+)%",
        "percentage_used": r"Percentage Used:\s+([0-9]+)%",
        "media_errors": r"Media and Data Integrity Errors:\s+([0-9,]+)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        if not match:
            continue
        value = match.group(1).strip()
        if key in {"temperature_c", "power_on_hours", "available_spare_percent", "percentage_used", "media_errors"}:
            value = int(value.replace(",", ""))
        out[key] = value
    m = re.search(r"Data Units Written:\s+([0-9,]+)\s+\[([0-9.]+)\s+([A-Z]+)\]", text)
    if m:
        units = int(m.group(1).replace(",", ""))
        value = float(m.group(2))
        suffix = m.group(3)
        out["data_units_written"] = units
        # NVMe SMART data units are 512,000 bytes each. Use the exact unit
        # count for deltas; the bracketed TB/GB value is rounded for humans.
        out["host_writes_bytes"] = units * 512000
        out["host_writes_display"] = f"{value:g} {suffix}"
    return out


def collect_smart(allow_install: bool) -> dict[str, Any]:
    install_state = install_smartmontools_if_missing(allow_install)
    smartctl = install_state.get("path")
    if not smartctl:
        return {"tool": install_state, "smart": {}, "evidence": "smartctl unavailable"}
    candidates = []
    scan = run([smartctl, "--scan"], timeout=30)
    for line in (scan.get("stdout") or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        before_comment = line.split("#", 1)[0].strip()
        parts = before_comment.split()
        if parts:
            candidates.append(["-a", *parts])
    candidates.extend([["-a", "disk0"], ["-a", "/dev/disk0"]])
    attempts = []
    for args in candidates:
        result = run([smartctl, *args], timeout=45)
        attempts.append(result)
        text = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
        parsed = parse_smartctl(text)
        if parsed.get("host_writes_bytes") or parsed.get("health") or parsed.get("model"):
            return {"tool": install_state, "smart": parsed, "scan": scan, "attempt": result}
    return {"tool": install_state, "smart": {}, "scan": scan, "attempts": attempts, "evidence": "SMART data not parsed"}


def parse_key_value_lines(text: str, sep: str = ":") -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if sep not in line:
            continue
        left, right = line.split(sep, 1)
        key = left.strip().lower().replace(" ", "_")
        data[key] = right.strip()
    return data


def collect_system() -> dict[str, Any]:
    hardware = run(["system_profiler", "SPHardwareDataType"], timeout=45)
    diskutil = run(["diskutil", "info", "/"], timeout=30)
    df = run(["df", "-k", "/"], timeout=30)
    apfs = run(["diskutil", "apfs", "list"], timeout=60)
    vm_stat = run(["vm_stat"], timeout=30)
    swap = run(["sysctl", "vm.swapusage"], timeout=30)
    uptime = run(["uptime"], timeout=30)
    sw_vers = run(["sw_vers"], timeout=30)
    return {
        "host_time_sgt": now_sgt().isoformat(timespec="seconds"),
        "platform": platform.platform(),
        "hardware": parse_key_value_lines(hardware.get("stdout", "")),
        "macos": parse_key_value_lines(sw_vers.get("stdout", ""), sep=":"),
        "diskutil_root": parse_key_value_lines(diskutil.get("stdout", "")),
        "df_root": df.get("stdout", "").strip(),
        "apfs_summary": apfs.get("stdout", "")[:12000],
        "vm_stat": vm_stat.get("stdout", "").strip(),
        "swap": swap.get("stdout", "").strip(),
        "uptime": uptime.get("stdout", "").strip(),
    }


def du_bytes(path: Path, timeout: int = 45) -> tuple[int | None, str | None]:
    if not path.exists():
        return None, "missing"
    result = run(["du", "-sk", str(path)], timeout=timeout)
    if result.get("returncode") == 0 and result.get("stdout"):
        first = result["stdout"].splitlines()[0].split()[0]
        try:
            return int(first) * 1024, None
        except ValueError:
            pass
    return None, (result.get("stderr") or result.get("error") or "du failed").strip()


def mtime_iso(path: Path) -> str | None:
    if not path.exists():
        return None
    return dt.datetime.fromtimestamp(path.stat().st_mtime, TZ).isoformat(timespec="seconds")


def monitored_paths(home: Path, extra_paths: list[str]) -> list[dict[str, str]]:
    paths = [
        ("Codex home", home / ".codex"),
        ("Codex sqlite", home / ".codex" / "sqlite"),
        ("Codex sessions", home / ".codex" / "sessions"),
        ("Codex cache", home / ".codex" / "cache"),
        ("User caches", home / "Library" / "Caches"),
        ("User logs", home / "Library" / "Logs"),
        ("Application Support", home / "Library" / "Application Support"),
        ("Containers", home / "Library" / "Containers"),
        ("Group Containers", home / "Library" / "Group Containers"),
        ("Safari caches", home / "Library" / "Containers" / "com.apple.Safari" / "Data" / "Library" / "Caches"),
        ("Chrome cache", home / "Library" / "Caches" / "Google" / "Chrome"),
        ("Edge cache", home / "Library" / "Caches" / "Microsoft Edge"),
        ("Edge updater", home / "Library" / "Application Support" / "Microsoft" / "EdgeUpdater"),
        ("Firefox cache", home / "Library" / "Caches" / "Firefox"),
        ("Douyin container", home / "Library" / "Containers" / "com.bytedance.douyin.desktop"),
        ("Douyin cache", home / "Library" / "Containers" / "com.bytedance.douyin.desktop" / "Data" / "Library" / "Application Support" / "抖音" / "Cache"),
        ("draw.io updater", home / "Library" / "Caches" / "draw.io-updater"),
        ("R temp root", Path("/private/tmp")),
        ("System logs", Path("/private/var/log")),
        ("System temp folders", Path("/private/var/folders")),
        ("VM swap", Path("/private/var/vm")),
        ("Homebrew cache", home / "Library" / "Caches" / "Homebrew"),
    ]
    for raw in extra_paths:
        paths.append((f"Extra {raw}", Path(raw).expanduser()))
    return [{"label": label, "path": str(path)} for label, path in paths]


def collect_path_sizes(paths: list[dict[str, str]]) -> list[dict[str, Any]]:
    rows = []
    for item in paths:
        path = Path(item["path"]).expanduser()
        size, error = du_bytes(path)
        rows.append(
            {
                "label": item["label"],
                "path": str(path),
                "exists": path.exists(),
                "size_bytes": size,
                "modified_sgt": mtime_iso(path),
                "error": error,
            }
        )
    return rows


def collect_top_growth_candidates(home: Path, limit: int = 120) -> list[dict[str, Any]]:
    roots = [
        home,
        home / "Library",
        home / "Library" / "Caches",
        home / "Library" / "Application Support",
        home / "Library" / "Containers",
        home / "Library" / "Group Containers",
        Path("/private/var"),
    ]
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for root in roots:
        if not root.exists():
            continue
        try:
            entries = [root, *[entry.path for entry in os.scandir(root)]]
        except OSError:
            entries = [root]
        for raw in entries:
            path = Path(raw)
            spath = str(path)
            if spath in seen:
                continue
            seen.add(spath)
            size, error = du_bytes(path, timeout=30)
            rows.append({"path": spath, "size_bytes": size, "modified_sgt": mtime_iso(path), "error": error})
    return sorted(rows, key=lambda r: r.get("size_bytes") or 0, reverse=True)[:limit]


@dataclass
class CodexDbStats:
    path: str
    exists: bool
    has_logs: bool = False
    total_rows: int | None = None
    level_counts: dict[str, int] | None = None
    max_id: int | None = None
    max_trace_id: int | None = None
    nonerror_rows: int | None = None
    db_size: int | None = None
    wal_size: int | None = None
    shm_size: int | None = None
    wal_modified_sgt: str | None = None
    trigger_present: bool = False
    error: str | None = None


def sqlite_scalar(conn: sqlite3.Connection, sql: str) -> Any:
    return conn.execute(sql).fetchone()[0]


def inspect_codex_db(path: Path) -> CodexDbStats:
    stats = CodexDbStats(path=str(path), exists=path.exists())
    if not stats.exists:
        return stats
    stats.db_size = path.stat().st_size
    wal = Path(str(path) + "-wal")
    shm = Path(str(path) + "-shm")
    if wal.exists():
        stats.wal_size = wal.stat().st_size
        stats.wal_modified_sgt = mtime_iso(wal)
    if shm.exists():
        stats.shm_size = shm.stat().st_size
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        try:
            stats.has_logs = bool(sqlite_scalar(conn, "select count(*) from sqlite_master where type='table' and name='logs'"))
            if not stats.has_logs:
                return stats
            rows = conn.execute("select level, count(*) from logs group by level order by count(*) desc").fetchall()
            stats.level_counts = {str(level): int(count) for level, count in rows}
            row = conn.execute(
                """
                select
                  count(*),
                  max(id),
                  max(case when level='TRACE' then id end),
                  coalesce(sum(level != 'ERROR'), 0)
                from logs
                """
            ).fetchone()
            stats.total_rows, stats.max_id, stats.max_trace_id, stats.nonerror_rows = row
            stats.trigger_present = bool(sqlite_scalar(conn, f"select count(*) from sqlite_master where type='trigger' and name='{TRIGGER_NAME}'"))
        finally:
            conn.close()
    except Exception as exc:
        stats.error = str(exc)
    return stats


def find_codex_log_dbs(codex_home: Path) -> list[Path]:
    return sorted(Path(p) for p in glob.glob(str(codex_home / "**" / "logs*.sqlite"), recursive=True))


def collect_codex(codex_home: Path) -> dict[str, Any]:
    dbs = [asdict(inspect_codex_db(path)) for path in find_codex_log_dbs(codex_home)]
    return {
        "codex_home": str(codex_home),
        "databases": dbs,
        "summary": {
            "db_count": len(dbs),
            "trace_or_nonerror_present": any((db.get("nonerror_rows") or 0) > 0 for db in dbs),
            "guard_missing": any(db.get("has_logs") and not db.get("trigger_present") for db in dbs),
            "total_wal_bytes": sum(db.get("wal_size") or 0 for db in dbs),
        },
    }


def apply_codex_log_guard(codex_home: Path, delete_nonessential: bool, vacuum: bool, watch_seconds: int) -> dict[str, Any]:
    paths = find_codex_log_dbs(codex_home)
    before = [asdict(inspect_codex_db(path)) for path in paths]
    for path in paths:
        conn = sqlite3.connect(str(path), timeout=10)
        try:
            conn.execute("pragma busy_timeout=10000")
            has_logs = bool(sqlite_scalar(conn, "select count(*) from sqlite_master where type='table' and name='logs'"))
            if not has_logs:
                continue
            conn.execute("drop trigger if exists block_trace_logs_insert")
            conn.execute("drop trigger if exists block_nonessential_logs_insert")
            conn.executescript(TRIGGER_SQL)
            if delete_nonessential:
                conn.execute("delete from logs where level != 'ERROR'")
            conn.commit()
            conn.execute("pragma wal_checkpoint(truncate)")
            if vacuum:
                conn.execute("vacuum")
                conn.execute("pragma wal_checkpoint(truncate)")
        finally:
            conn.close()
    after_apply = [asdict(inspect_codex_db(path)) for path in paths]
    after_watch = None
    if watch_seconds > 0:
        time.sleep(watch_seconds)
        after_watch = [asdict(inspect_codex_db(path)) for path in paths]
    return {"before": before, "after_apply": after_apply, "after_watch": after_watch}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def append_jsonl(path: Path, row: dict[str, Any]) -> int:
    before = path.stat().st_size if path.exists() else 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return path.stat().st_size - before


def previous_record(records: list[dict[str, Any]], today: str) -> dict[str, Any] | None:
    for row in reversed(records):
        if row.get("date_sgt") != today:
            return row
    return None


def rolling_average(records: list[dict[str, Any]], days: int) -> float | None:
    values = []
    for row in reversed(records):
        delta = row.get("derived", {}).get("host_writes_delta_bytes")
        if isinstance(delta, (int, float)) and delta >= 0:
            values.append(delta)
        if len(values) >= days:
            break
    if not values:
        return None
    return sum(values) / len(values)


def compare_path_growth(current: list[dict[str, Any]], previous: dict[str, Any] | None) -> list[dict[str, Any]]:
    prev_map = {}
    if previous:
        for row in previous.get("top_candidates", []):
            if row.get("size_bytes") is not None:
                prev_map[row.get("path")] = row.get("size_bytes")
        for row in previous.get("path_sizes", []):
            if row.get("size_bytes") is not None:
                prev_map[row.get("path")] = row.get("size_bytes")
    growth_by_path: dict[str, dict[str, Any]] = {}
    for row in current:
        path = row.get("path")
        size = row.get("size_bytes")
        prev = prev_map.get(path)
        if not path or size is None or prev is None:
            continue
        delta = size - prev
        item = {
            "path": path,
            "previous_bytes": prev,
            "current_bytes": size,
            "delta_bytes": delta,
            "growth_percent": round(delta / prev * 100, 2) if prev else None,
        }
        if path not in growth_by_path or delta > growth_by_path[path]["delta_bytes"]:
            growth_by_path[path] = item
    growth = list(growth_by_path.values())
    return sorted(growth, key=lambda r: r["delta_bytes"], reverse=True)[:20]


def online_codex_check() -> dict[str, Any]:
    queries = [
        "repo:openai/codex log sqlite ssd",
        "repo:openai/codex TRACE logs sqlite",
        "repo:openai/codex disk write",
    ]
    findings = []
    errors = []
    for query in queries:
        url = "https://api.github.com/search/issues?" + urllib.parse.urlencode({"q": query, "per_page": 5})
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "mac-ssd-audit"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            for item in payload.get("items", []):
                findings.append(
                    {
                        "title": item.get("title"),
                        "number": item.get("number"),
                        "state": item.get("state"),
                        "url": item.get("html_url"),
                        "created_at": item.get("created_at"),
                        "updated_at": item.get("updated_at"),
                    }
                )
        except Exception as exc:
            errors.append({"query": query, "error": str(exc)})
    unique = []
    seen = set()
    for item in findings:
        key = item.get("url")
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return {
        "status": "ok" if unique else ("unavailable" if errors else "no_findings"),
        "findings": unique,
        "errors": errors,
        "evidence": "GitHub issue search via public API",
    }


def detect_anomalies(record: dict[str, Any], avg7: float | None, growth_top20: list[dict[str, Any]]) -> list[dict[str, str]]:
    anomalies = []
    delta = record.get("derived", {}).get("host_writes_delta_bytes")
    if isinstance(delta, (int, float)) and avg7 and delta > avg7 * 2:
        anomalies.append({"risk": "中", "item": "单日写入异常高", "evidence": f"{bytes_human(delta)} > 2x 7-day average {bytes_human(avg7)}"})
    smart = record.get("smart", {}).get("smart", {})
    if smart.get("media_errors") not in (None, 0):
        anomalies.append({"risk": "高", "item": "SMART media errors", "evidence": str(smart.get("media_errors"))})
    if smart.get("available_spare_percent") is not None and smart.get("available_spare_percent") < 90:
        anomalies.append({"risk": "中", "item": "Available Spare lower than expected", "evidence": f"{smart.get('available_spare_percent')}%"})
    codex_summary = record.get("codex", {}).get("summary", {})
    if codex_summary.get("trace_or_nonerror_present"):
        anomalies.append({"risk": "中", "item": "Codex 非 ERROR 日志仍存在", "evidence": "logs table contains non-ERROR rows"})
    if codex_summary.get("guard_missing"):
        anomalies.append({"risk": "中", "item": "Codex SQLite guard missing", "evidence": "one or more logs tables lack block_nonerror_logs_insert"})
    if codex_summary.get("total_wal_bytes", 0) > 16 * 1024 * 1024:
        anomalies.append({"risk": "中", "item": "Codex WAL 较大", "evidence": bytes_human(codex_summary.get("total_wal_bytes"))})
    for row in growth_top20[:5]:
        if row.get("delta_bytes", 0) > 5 * 1024**3:
            anomalies.append({"risk": "中", "item": "目录增长较快", "evidence": f"{row.get('path')} grew {bytes_human(row.get('delta_bytes'))}"})
    return anomalies


def compact_record(record: dict[str, Any]) -> dict[str, Any]:
    codex_dbs = []
    for db in record.get("codex", {}).get("databases", []):
        codex_dbs.append(
            {
                "path": db.get("path"),
                "db_size": db.get("db_size"),
                "wal_size": db.get("wal_size"),
                "total_rows": db.get("total_rows"),
                "nonerror_rows": db.get("nonerror_rows"),
                "max_id": db.get("max_id"),
                "max_trace_id": db.get("max_trace_id"),
                "trigger_present": db.get("trigger_present"),
                "level_counts": db.get("level_counts"),
            }
        )
    return {
        "timestamp_sgt": record.get("timestamp_sgt"),
        "date_sgt": record.get("date_sgt"),
        "smart": {"smart": record.get("smart", {}).get("smart", {}), "tool": record.get("smart", {}).get("tool", {})},
        "derived": record.get("derived", {}),
        "path_sizes": [
            {
                "label": row.get("label"),
                "path": row.get("path"),
                "size_bytes": row.get("size_bytes"),
                "modified_sgt": row.get("modified_sgt"),
            }
            for row in record.get("path_sizes", [])
        ],
        "top_candidates": [
            {
                "path": row.get("path"),
                "size_bytes": row.get("size_bytes"),
                "modified_sgt": row.get("modified_sgt"),
            }
            for row in record.get("top_candidates", [])
        ],
        "codex": {"summary": record.get("codex", {}).get("summary", {}), "databases": codex_dbs},
        "growth_top20": record.get("growth_top20", []),
        "anomalies": record.get("anomalies", []),
        "online_codex_check": {
            "status": record.get("online_codex_check", {}).get("status"),
            "finding_count": len(record.get("online_codex_check", {}).get("findings", [])),
            "error_count": len(record.get("online_codex_check", {}).get("errors", [])),
        },
        "self_audit": record.get("self_audit", {}),
    }


def render_report(record: dict[str, Any], previous: dict[str, Any] | None, avg7: float | None, avg30: float | None, growth_top20: list[dict[str, Any]], anomalies: list[dict[str, str]]) -> str:
    smart = record.get("smart", {}).get("smart", {})
    derived = record.get("derived", {})
    codex = record.get("codex", {})
    online = record.get("online_codex_check", {})
    delta = derived.get("host_writes_delta_bytes")
    summary = "今天 SSD 暂未发现明确异常。" if not anomalies else f"今天发现 {len(anomalies)} 项需要关注的 SSD/写入风险。"
    lines = [
        f"# SSD Daily Report {record['date_sgt']}",
        "",
        "## 一、执行摘要",
        summary,
        "",
        "## 二、SSD 写入",
        f"- 累计 Host Writes：{smart.get('host_writes_display') or bytes_human(smart.get('host_writes_bytes'))}",
        f"- 今日新增：{bytes_human(delta) if delta is not None else '暂无昨日基线，无法计算'}",
        f"- 过去7天平均：{bytes_human(avg7)}",
        f"- 过去30天平均：{bytes_human(avg30)}",
        f"- Power On Hours：{smart.get('power_on_hours', 'unknown')}",
        f"- Temperature：{smart.get('temperature_c', 'unknown')} C",
        f"- Available Spare：{smart.get('available_spare_percent', 'unknown')}%",
        f"- Media Errors：{smart.get('media_errors', 'unknown')}",
        f"- Health：{smart.get('health', 'unknown')}",
        "",
        "## 三、今日主要写入来源",
        "- 暂无直接证据能把 Host Writes 精确归因到单个程序；本报告仅使用目录增长、WAL/日志变化、SMART 增量作为证据。",
    ]
    if growth_top20:
        for row in growth_top20[:10]:
            lines.append(f"- {row['path']}：增长 {bytes_human(row['delta_bytes'])}")
    else:
        lines.append("- 暂无昨日目录快照，无法计算目录增长来源。")
    lines.extend(["", "## 四、磁盘增长最快目录", "| 目录 | 昨日大小 | 今日大小 | 增长量 | 增长百分比 |", "| --- | ---: | ---: | ---: | ---: |"])
    for row in growth_top20:
        pct = "unknown" if row.get("growth_percent") is None else f"{row['growth_percent']}%"
        lines.append(f"| `{row['path']}` | {bytes_human(row['previous_bytes'])} | {bytes_human(row['current_bytes'])} | {bytes_human(row['delta_bytes'])} | {pct} |")
    if not growth_top20:
        lines.append("| 暂无可比数据 |  |  |  |  |")
    lines.extend(["", "## 五、Codex 状态"])
    lines.append(f"- 日志数据库数量：{codex.get('summary', {}).get('db_count', 0)}")
    lines.append(f"- SQLite guard 缺失：{codex.get('summary', {}).get('guard_missing')}")
    lines.append(f"- 非 ERROR 日志存在：{codex.get('summary', {}).get('trace_or_nonerror_present')}")
    lines.append(f"- WAL 总大小：{bytes_human(codex.get('summary', {}).get('total_wal_bytes'))}")
    for db in codex.get("databases", []):
        lines.append(f"- `{db.get('path')}`：size={bytes_human(db.get('db_size'))}, wal={bytes_human(db.get('wal_size'))}, trigger={db.get('trigger_present')}, levels={db.get('level_counts')}")
    lines.extend(["", "## 六、风险评估"])
    if anomalies:
        for item in anomalies:
            lines.append(f"- 风险等级 {item['risk']}：{item['item']}。证据：{item['evidence']}")
    else:
        lines.append("- 风险等级：低。依据：本次采样未发现 SMART 错误、Codex WAL 异常或可证实的异常目录增长。")
    lines.extend(["", "## 七、在线核查"])
    if online.get("findings"):
        for item in online["findings"]:
            lines.append(f"- #{item.get('number')} {item.get('title')} ({item.get('state')}): {item.get('url')}")
    elif online.get("status") == "unavailable":
        lines.append("- 在线核查失败或网络不可用；无法确认今日是否有新的官方 SSD/日志相关更新。")
    else:
        lines.append("- 今日未发现新的官方 SSD/日志相关更新。")
    lines.extend(["", "## 八、建议"])
    if anomalies:
        lines.append("- 建议处理：优先检查上述风险项对应目录或 Codex 日志状态。依据：异常检测已列出证据。")
    elif previous is None:
        lines.append("- 观察即可：今天是首个基线日，先积累明日对比数据。依据：无昨日 Host Writes 和目录快照。")
    else:
        lines.append("- 无需处理：继续每日自动审计。依据：未发现明确异常。")
    lines.extend(["", "## 九、自身写入审计"])
    lines.append(f"- 本次历史记录新增：{bytes_human(record.get('self_audit', {}).get('history_bytes_written'))}")
    lines.append(f"- 本次报告大小：{bytes_human(record.get('self_audit', {}).get('report_bytes_written'))}")
    lines.append(f"- 输出目录：`{record.get('self_audit', {}).get('report_dir')}`")
    return "\n".join(lines) + "\n"


def run_audit(args: argparse.Namespace) -> int:
    start = now_sgt()
    home = Path(args.home).expanduser()
    output_dir = Path(args.output_dir).expanduser()
    state_dir = Path(args.state_dir).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    history_path = state_dir / "metrics.jsonl"
    records = load_jsonl(history_path)
    today = start.strftime("%Y-%m-%d")
    report_name = f"SSD_Daily_Report_{today}.md"
    report_path = output_dir / report_name
    if args.skip_if_report_exists and report_path.exists():
        print(json.dumps({"skipped": True, "reason": "report_exists", "report": str(report_path)}, ensure_ascii=False, indent=2))
        return 0
    prev = previous_record(records, today)
    smart = collect_smart(args.install_missing_tools)
    path_specs = monitored_paths(home, args.extra_path)
    path_sizes = collect_path_sizes(path_specs)
    top_candidates = collect_top_growth_candidates(home, args.candidate_limit)
    codex = collect_codex(Path(args.codex_home).expanduser())
    host_writes = smart.get("smart", {}).get("host_writes_bytes")
    previous_host_writes = None
    if prev:
        previous_host_writes = prev.get("smart", {}).get("smart", {}).get("host_writes_bytes")
    delta = host_writes - previous_host_writes if isinstance(host_writes, int) and isinstance(previous_host_writes, int) else None
    elapsed_hours = None
    if prev and prev.get("timestamp_sgt"):
        try:
            prev_ts = dt.datetime.fromisoformat(prev["timestamp_sgt"])
            elapsed_hours = (start - prev_ts).total_seconds() / 3600
        except Exception:
            elapsed_hours = None
    record = {
        "timestamp_sgt": start.isoformat(timespec="seconds"),
        "date_sgt": today,
        "system": collect_system(),
        "smart": smart,
        "path_sizes": path_sizes,
        "top_candidates": top_candidates,
        "codex": codex,
        "online_codex_check": online_codex_check() if args.online_check else {"status": "skipped"},
        "derived": {
            "host_writes_delta_bytes": delta,
            "elapsed_hours_since_previous": elapsed_hours,
            "average_bytes_per_hour": delta / elapsed_hours if delta is not None and elapsed_hours else None,
        },
    }
    growth_top20 = compare_path_growth(path_sizes + top_candidates, prev)
    avg7 = rolling_average(records, 7)
    avg30 = rolling_average(records, 30)
    anomalies = detect_anomalies(record, avg7, growth_top20)
    record["growth_top20"] = growth_top20
    record["anomalies"] = anomalies
    before_report = report_path.stat().st_size if report_path.exists() else 0
    record["self_audit"] = {"history_bytes_written": None, "report_bytes_written": None, "report_dir": str(output_dir)}
    draft_report = render_report(record, prev, avg7, avg30, growth_top20, anomalies)
    report_delta = len(draft_report.encode("utf-8")) - before_report
    record["self_audit"]["report_bytes_written"] = report_delta
    history_bytes = append_jsonl(history_path, compact_record(record))
    record["self_audit"]["history_bytes_written"] = history_bytes
    report_text = render_report(record, prev, avg7, avg30, growth_top20, anomalies)
    report_path.write_text(report_text, encoding="utf-8")
    report_delta = report_path.stat().st_size - before_report
    print(json.dumps({"report": str(report_path), "history": str(history_path), "self_written_bytes": history_bytes + max(report_delta, 0), "anomalies": anomalies}, ensure_ascii=False, indent=2))
    return 0


def run_codex_guard(args: argparse.Namespace) -> int:
    codex_home = Path(args.codex_home).expanduser()
    if args.apply:
        result = apply_codex_log_guard(codex_home, args.delete_nonessential, args.vacuum, args.watch_seconds)
    else:
        result = collect_codex(codex_home)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mac SSD write audit and Codex SQLite log guard.")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="Run a read-only SSD and write-source audit.")
    audit.add_argument("--home", default=str(Path.home()))
    audit.add_argument("--codex-home", default=str(Path.home() / ".codex"))
    audit.add_argument("--output-dir", default=str(Path.home() / "Documents" / "SSD_Audit_Reports"))
    audit.add_argument("--state-dir", default=str(Path.home() / ".local" / "state" / "mac-ssd-audit"))
    audit.add_argument("--extra-path", action="append", default=[])
    audit.add_argument("--candidate-limit", type=int, default=120, help="Keep only the largest growth-candidate directories in history.")
    audit.add_argument("--skip-if-report-exists", action="store_true", help="Exit without scanning if today's report already exists.")
    audit.add_argument("--install-missing-tools", action="store_true", help="Install smartmontools with Homebrew if smartctl is missing.")
    audit.add_argument("--online-check", action="store_true", help="Check public GitHub issues for Codex logging/SSD problems.")
    audit.set_defaults(func=run_audit)
    guard = sub.add_parser("guard-codex-logs", help="Audit or explicitly guard Codex SQLite logs.")
    guard.add_argument("--codex-home", default=str(Path.home() / ".codex"))
    guard.add_argument("--apply", action="store_true", help="Install/restore trigger blocking non-ERROR rows.")
    guard.add_argument("--delete-nonessential", action="store_true", help="Delete existing non-ERROR rows. Requires --apply.")
    guard.add_argument("--vacuum", action="store_true", help="Vacuum after deletion. Requires --apply.")
    guard.add_argument("--watch-seconds", type=int, default=0)
    guard.set_defaults(func=run_codex_guard)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, "command", None) == "guard-codex-logs" and (args.delete_nonessential or args.vacuum) and not args.apply:
        parser.error("--delete-nonessential and --vacuum require --apply")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
