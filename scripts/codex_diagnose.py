"""Bounded, source-read-only Codex diagnostics. No state contents are exported."""
from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
import platform
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

LIMIT = 64 * 1024 * 1024
EVENT = b'maybe_resume_skipped_inactive_hotkey_window'


def signature(path):
    s = path.stat()
    return (s.st_dev, s.st_ino, s.st_mtime_ns, s.st_ctime_ns, s.st_size)


def state_sample(path):
    try:
        before = signature(path)
        if before[-1] > LIMIT:
            return {'error': 'file exceeds 64 MiB read limit'}
        with path.open('rb') as f:
            data = f.read(LIMIT + 1)
        if signature(path) != before or len(data) != before[-1]:
            return {'error': 'file changed during read'}
        result = {'signature': before, 'size_bytes': len(data),
                  'digest': hashlib.sha256(data).hexdigest(), 'semantic': None}
        try:
            canonical = json.dumps(json.loads(data), sort_keys=True, separators=(',', ':'), ensure_ascii=True)
            result['semantic'] = hashlib.sha256(canonical.encode()).hexdigest()
        except (ValueError, UnicodeError, RecursionError):
            pass
        return result
    except OSError as e:
        return {'error': type(e).__name__}


class StateTracker:
    def __init__(self, path):
        self.path = path
        self.previous = None
        self.first_size = None
        self.last_size = None
        self.stats = dict(observed_updates=0, same_size_updates=0,
                          identical_bytes_updates=0, identical_json_updates=0,
                          sampled_updated_file_bytes=0, unavailable_samples=0)

    def poll(self):
        s = state_sample(self.path)
        if 'error' in s:
            self.stats['unavailable_samples'] += 1
            self.previous = None
            return
        if self.first_size is None:
            self.first_size = s['size_bytes']
        self.last_size = s['size_bytes']
        p = self.previous
        if p and s['signature'] != p['signature']:
            self.stats['observed_updates'] += 1
            self.stats['sampled_updated_file_bytes'] += s['size_bytes']
            self.stats['same_size_updates'] += s['size_bytes'] == p['size_bytes']
            self.stats['identical_bytes_updates'] += s['digest'] == p['digest']
            self.stats['identical_json_updates'] += s['semantic'] is not None and s['semantic'] == p['semantic']
        self.previous = s

    def report(self, seconds):
        return {**self.stats, 'observed_updates_per_second': self.stats['observed_updates'] / seconds,
                'net_size_delta_bytes': None if self.first_size is None else self.last_size - self.first_size,
                'repeated_update_detected': self.stats['observed_updates'] >= 2}


def db_sample(path, after=None):
    """Copy a stable main/WAL pair; SQLite may write only inside TemporaryDirectory.

    Never open the live database with SQLite (even mode=ro can touch SHM).
    Concurrently changing copies are rejected, not interpreted as zero events.
    """
    files = [path, Path(str(path) + '-wal')]
    try:
        before = {p: signature(p) for p in files if p.exists()}
        if path not in before:
            return {'error': 'database missing'}
        if sum(s[-1] for s in before.values()) > LIMIT:
            return {'error': 'database plus WAL exceeds 64 MiB snapshot limit'}
        with tempfile.TemporaryDirectory(prefix='mac-ssd-diagnostic-') as d:
            target = Path(d) / 'logs.sqlite'
            for source in before:
                dest = target if source == path else Path(str(target) + '-wal')
                with source.open('rb') as src, dest.open('wb') as out:
                    remaining = before[source][-1]
                    while remaining:
                        chunk = src.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise OSError('short snapshot read')
                        out.write(chunk)
                        remaining -= len(chunk)
            if before != {p: signature(p) for p in files if p.exists()}:
                return {'error': 'database changed during snapshot'}
            with sqlite3.connect(target, timeout=0.1) as conn:
                conn.execute('PRAGMA query_only=ON')
                deadline = time.monotonic() + 0.5
                conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                columns = {r[1] for r in conn.execute('PRAGMA table_info(logs)')}
                if 'id' not in columns:
                    return {'error': 'logs.id unavailable'}
                maximum = conn.execute('SELECT max(id) FROM logs').fetchone()[0]
                if maximum is not None and not isinstance(maximum, int):
                    return {'error': 'logs.id is not integer'}
                count = (None if after is None else
                         conn.execute('SELECT count(*) FROM logs').fetchone()[0] if after == 'empty' else
                         conn.execute('SELECT count(*) FROM logs WHERE id > ?', (after,)).fetchone()[0])
                guard = bool(conn.execute("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name='block_nonerror_logs_insert'").fetchone()[0])
                return {'identity': before[path][:2], 'max_id': maximum, 'new_rows': count, 'guard_present': guard}
    except (OSError, sqlite3.Error) as e:
        return {'error': type(e).__name__}


class DbTracker:
    def __init__(self, path):
        self.path = path
        self.previous = None
        self.started = None
        self.rows = 0
        self.seconds = 0
        self.peak = None
        self.errors = 0
        self.resets = 0
        self.guard = False

    def poll(self, now):
        after = (self.previous['max_id'] if self.previous['max_id'] is not None else 'empty') if self.previous else None
        s = db_sample(self.path, after)
        if 'error' in s:
            self.errors += 1
            self.previous = None
            return
        self.guard |= s['guard_present']
        if self.previous:
            p = self.previous
            if s['identity'] != p['identity'] or (p['max_id'] is not None and (s['max_id'] is None or s['max_id'] < p['max_id'])):
                self.resets += 1
            elif s['new_rows'] is not None and now > self.started:
                elapsed = now - self.started
                self.rows += s['new_rows']
                self.seconds += elapsed
                rate = s['new_rows'] / elapsed
                self.peak = max(self.peak or 0, rate)
        self.previous, self.started = s, now

    def report(self):
        return {'observed_new_rows': self.rows, 'covered_seconds': self.seconds,
                'rows_per_second': self.rows / self.seconds if self.seconds else None,
                'peak_interval_rows_per_second': self.peak, 'unavailable_samples': self.errors,
                'resets': self.resets, 'guard_present': self.guard,
                'scope': 'retained SQLite rows; not upstream events'}


class TextTracker:
    def __init__(self, path):
        self.path = path
        self.identity = None
        self.offset = None
        self.pending = b''
        self.lines = self.matches = self.errors = self.resets = 0
        self.covered = 0.0
        self.last = None
        self.peak = None

    def poll(self, now):
        try:
            with self.path.open('rb') as f:
                # fstat binds the cursor to the opened inode across rotation.
                st = os.fstat(f.fileno())
                identity = (st.st_dev, st.st_ino)
                if self.offset is None or self.identity != identity or st.st_size < self.offset:
                    if self.offset is not None:
                        self.resets += 1
                    self.identity, self.offset = identity, st.st_size
                    self.pending = b''
                    self.last = now
                    return
                if st.st_size - self.offset > LIMIT:
                    self.errors += 1
                    self.offset = st.st_size
                    self.pending = b''
                    self.last = now
                    return
                f.seek(self.offset)
                data = f.read(min(LIMIT, st.st_size - self.offset))
                self.offset += len(data)
            parts = (self.pending + data).split(b'\n')
            self.pending = parts.pop()
            if len(self.pending) > 1024 * 1024:
                self.pending = b''
                self.errors += 1
            matches = sum(EVENT in line for line in parts)
            self.lines += len(parts)
            self.matches += matches
            elapsed = now - self.last
            if elapsed > 0:
                self.covered += elapsed
                self.peak = max(self.peak or 0, matches / elapsed)
            self.last = now
        except OSError:
            self.errors += 1
            self.offset = None

    def report(self):
        return {'observed_complete_lines': self.lines, 'target_event_lines': self.matches,
                'covered_seconds': self.covered,
                'lines_per_second': self.lines / self.covered if self.covered else None,
                'target_event_lines_per_second': self.matches / self.covered if self.covered else None,
                'peak_target_interval_rate': self.peak, 'unavailable_samples': self.errors,
                'rotations_or_truncations': self.resets,
                'scope': 'new complete lines in explicitly selected text log; one match per line'}


def process_sample(pid):
    if platform.system() != 'Darwin':
        return {'error': 'proc_pid_rusage only available on macOS'}
    class Usage(ctypes.Structure):
        _fields_ = [('uuid', ctypes.c_uint8 * 16)] + [(n, ctypes.c_uint64) for n in (
            'user', 'system', 'idle', 'interrupt', 'pageins', 'wired', 'resident', 'footprint',
            'start', 'exit', 'child_user', 'child_system', 'child_idle', 'child_interrupt',
            'child_pageins', 'child_elapsed', 'disk_read', 'disk_written')]
    try:
        lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        lib.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        lib.proc_pid_rusage.restype = ctypes.c_int
        usage = Usage()
        if lib.proc_pid_rusage(pid, 2, ctypes.byref(usage)) != 0:
            return {'error': 'process unavailable or permission denied'}
        return {'identity': usage.start, 'bytes': usage.disk_written}
    except OSError:
        return {'error': 'libproc unavailable'}


def counter_delta(before, after):
    if 'error' in before or 'error' in after:
        return {'delta_bytes': None, 'error': before.get('error') or after.get('error')}
    if before['identity'] != after['identity'] or after['bytes'] < before['bytes']:
        return {'delta_bytes': None, 'error': 'counter reset or identity changed'}
    return {'delta_bytes': after['bytes'] - before['bytes']}


def smart_sample(device):
    executable = shutil.which('smartctl')
    if not executable:
        return {'error': 'smartctl unavailable; nothing installed'}
    try:
        p = subprocess.run([executable, '-a', '-j', device], capture_output=True, timeout=5, check=False)
        if p.returncode & 7:
            return {'error': 'SMART command failed'}
        data = json.loads(p.stdout)
        units = data['nvme_smart_health_information_log']['data_units_written']
        return {'identity': (device, data['serial_number']), 'bytes': int(units) * 512000}
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        return {'error': 'NVMe SMART Host Writes unavailable'}


def run_diagnose(args):
    if not math.isfinite(args.seconds) or not 0 < args.seconds <= 600:
        raise ValueError('--seconds must be finite and in (0, 600]')
    if not math.isfinite(args.interval) or not 0.05 <= args.interval <= args.seconds:
        raise ValueError('--interval must be in [0.05, seconds]')
    if args.pid is not None and args.pid <= 0:
        raise ValueError('--pid must be positive')
    home = Path(args.codex_home).expanduser()
    states = {name: StateTracker(home / name) for name in ('.codex-global-state.json', '.codex-global-state.json.bak')}
    logs = {str(Path(p).expanduser()): TextTracker(Path(p).expanduser()) for p in args.log_file}
    dbs = {str(p): DbTracker(p) for p in sorted(home.glob('**/logs*.sqlite'))} if args.sqlite else {}
    proc_before = process_sample(args.pid) if args.pid else {'error': 'no PID selected'}
    smart_before = smart_sample(args.smart_device) if args.smart_device else {'error': 'no device selected'}
    started = time.monotonic()
    def poll():
        for tracker in states.values():
            tracker.poll()
        for tracker in logs.values():
            tracker.poll(time.monotonic())
        for tracker in dbs.values():
            tracker.poll(time.monotonic())
    poll()
    deadline = started + args.seconds
    while time.monotonic() < deadline:
        time.sleep(min(args.interval, max(0, deadline - time.monotonic())))
        poll()
    finished = time.monotonic()
    proc_after = process_sample(args.pid) if args.pid else {'error': 'no PID selected'}
    smart_after = smart_sample(args.smart_device) if args.smart_device else {'error': 'no device selected'}
    elapsed = finished - started
    result = {'duration_seconds': elapsed, 'interval_seconds': args.interval,
              'state_files': {n: t.report(elapsed) for n, t in states.items()},
              'text_logs': {n: t.report() for n, t in logs.items()},
              'sqlite_logs': {n: t.report() for n, t in dbs.items()},
              'process_disk_write': {**counter_delta(proc_before, proc_after), 'pid': args.pid,
                                     'scope': 'selected process only; endpoint window includes counter-read overhead'},
              'device_host_writes': {**counter_delta(smart_before, smart_after),
                                     'scope': 'whole NVMe device Host Writes, 512000-byte resolution; not physical NAND writes'},
              'limits': ['Polling can miss intervening updates; metadata changes alone do not prove full rewrites.',
                         'sampled_updated_file_bytes is a sum of observed file sizes, not measured I/O.',
                         'No write attribution or crash causation is established by co-occurrence.',
                         'SQLite snapshots write bounded temporary copies, never the source DB/WAL/SHM.',
                         'Retained logs can undercount upstream events due to guards, rotation or deletion.',
                         'No raw state, log lines or content hashes are exported.']}
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0
