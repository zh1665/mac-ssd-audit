import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('codex_diagnose', ROOT / 'scripts/codex_diagnose.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def replace(path, data):
    temp = path.with_suffix('.tmp')
    temp.write_bytes(data)
    temp.replace(path)


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.tmp_path = Path(temp.name)

    def setattr(self, obj, name, value):
        replacement = patch.object(obj, name, value)
        replacement.start()
        self.addCleanup(replacement.stop)

    def test_same_size_identical_rewrites(self):
        tmp_path = self.tmp_path
        monkeypatch = self
        path = tmp_path / 'state'
        path.write_bytes(b'{"a":1}')
        tracker = m.StateTracker(path)
        tracker.poll()
        for _ in range(9):
            replace(path, b'{"a":1}')
            tracker.poll()
        report = tracker.report(180)
        assert report['net_size_delta_bytes'] == 0
        assert report['observed_updates'] == 9
        assert report['identical_json_updates'] == 9
        assert report['identical_bytes_updates'] == 9
        assert report['same_size_updates'] == 9
        assert report['repeated_update_detected']
        assert report['sampled_updated_file_bytes'] == 63


    def test_semantic_equality_and_changed_content(self):
        tmp_path = self.tmp_path
        monkeypatch = self
        path = tmp_path / 'state'
        path.write_bytes(b'{"a":1,"b":2}')
        tracker = m.StateTracker(path)
        tracker.poll()
        replace(path, b'{"b":2,"a":1}')
        tracker.poll()
        replace(path, b'{"b":3,"a":1}')
        tracker.poll()
        r = tracker.report(1)
        assert r['same_size_updates'] == 2
        assert r['identical_json_updates'] == 1
        assert r['identical_bytes_updates'] == 0


    def test_touch_is_evidence_not_proof(self):
        tmp_path = self.tmp_path
        monkeypatch = self
        path = tmp_path / 'state'
        path.write_text('{}')
        t = m.StateTracker(path)
        t.poll()
        st = path.stat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1000000))
        t.poll()
        assert t.report(1)['observed_updates'] == 1
        assert not t.report(1)['repeated_update_detected']


    def test_missing_invalid_and_oversized_state(self):
        tmp_path = self.tmp_path
        monkeypatch = self
        p = tmp_path / 'state'
        assert 'error' in m.state_sample(p)
        p.write_bytes(b'invalid')
        assert m.state_sample(p)['semantic'] is None
        monkeypatch.setattr(m, 'LIMIT', 2)
        assert 'error' in m.state_sample(p)


    def test_no_change_does_not_report_update(self):
        tmp_path = self.tmp_path
        monkeypatch = self
        p = tmp_path / 'state'
        p.write_text('{}')
        t = m.StateTracker(p)
        t.poll()
        t.poll()
        assert t.report(1)['observed_updates'] == 0

    def test_unchanged_metadata_skips_full_state_read(self):
        p = self.tmp_path / 'state'
        p.write_text('{}')
        t = m.StateTracker(p)
        with patch.object(m, 'state_sample', wraps=m.state_sample) as sample:
            t.poll()
            for _ in range(20):
                t.poll()
            assert sample.call_count == 1
            replace(p, b'{}')
            t.poll()
            assert sample.call_count == 2
        assert t.report(1)['identical_bytes_updates'] == 1
        p.rename(self.tmp_path / 'gone')
        t.poll()
        assert t.previous is None
        assert t.report(1)['unavailable_samples'] == 1

    def test_apple_nvme_smart_device_and_homebrew_fallback(self):
        device = 'IOService:/AppleARMPE/arm-io/AppleANS3/NS_01@1'
        data = {'serial_number': 'simulation',
                'nvme_smart_health_information_log': {'data_units_written': 123}}
        response = subprocess.CompletedProcess([], 0, json.dumps(data).encode(), b'')
        with patch.object(m.shutil, 'which', return_value=None), \
             patch.object(m.Path, 'is_file', side_effect=lambda: True), \
             patch.object(m.subprocess, 'run', return_value=response) as run:
            s = m.smart_sample(device)
        assert s['bytes'] == 123 * 512000
        assert run.call_args.args[0] == ['/opt/homebrew/bin/smartctl', '-i', '-A', '-j', '-d', 'nvme', device]
        response.returncode = 2
        with patch.object(m.shutil, 'which', return_value='/usr/bin/smartctl'), \
             patch.object(m.subprocess, 'run', return_value=response):
            assert 'error' in m.smart_sample(device)
        with patch.object(m.shutil, 'which', return_value=None), \
             patch.object(m.Path, 'is_file', return_value=False), \
             patch.object(m.subprocess, 'run') as run:
            assert 'error' in m.smart_sample(device)
            run.assert_not_called()


    def test_log_storm_partial_lines_and_rotation(self):
        tmp_path = self.tmp_path
        monkeypatch = self
        p = tmp_path / 'desktop.log'
        p.write_bytes(b'historical\n')
        t = m.TextTracker(p)
        t.poll(0)
        with p.open('ab') as f:
            f.write((m.EVENT + b'\n') * 130055)
            f.write(m.EVENT[:10])
        t.poll(16.651)
        r = t.report()
        assert r['target_event_lines'] == 130055
        assert abs(r['target_event_lines_per_second'] - 7810.6414) < 0.01
        with p.open('ab') as f:
            f.write(m.EVENT[10:] + b'\n')
        t.poll(17)
        assert t.report()['target_event_lines'] == 130056
        replace(p, b'new generation\n')
        t.poll(18)
        assert t.report()['rotations_or_truncations'] == 1
        assert t.report()['target_event_lines'] == 130056
        p.write_bytes(b'')
        t.poll(19)
        assert t.report()['rotations_or_truncations'] == 2


    def test_sqlite_wal_source_unchanged_guard_and_real_counts(self):
        tmp_path = self.tmp_path
        monkeypatch = self
        p = tmp_path / 'logs.sqlite'
        conn = sqlite3.connect(p)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('CREATE TABLE logs(id INTEGER PRIMARY KEY, level TEXT)')
        conn.execute("INSERT INTO logs VALUES(10, 'ERROR')")
        conn.execute("CREATE TRIGGER block_nonerror_logs_insert BEFORE INSERT ON logs WHEN NEW.level != 'ERROR' BEGIN SELECT RAISE(IGNORE); END")
        conn.commit()
        files = list(tmp_path.iterdir())
        before = {f.name: (f.read_bytes(), m.signature(f)) for f in files}
        s = m.db_sample(p, 0)
        after = {f.name: (f.read_bytes(), m.signature(f)) for f in tmp_path.iterdir()}
        assert before == after
        assert s['new_rows'] == 1  # max id is 10, not 10 inserted rows
        assert s['guard_present']
        tracker = m.DbTracker(p)
        tracker.poll(0)
        conn.execute("INSERT INTO logs VALUES(100, 'ERROR')")
        conn.execute("INSERT INTO logs VALUES(200, 'INFO')")
        conn.commit()
        tracker.poll(2)
        r = tracker.report()
        assert r['observed_new_rows'] == 1
        assert r['rows_per_second'] == 0.5
        assert r['guard_present']
        conn.execute('DELETE FROM logs')
        conn.commit()
        tracker.poll(3)
        assert tracker.report()['resets'] == 1
        conn.close()


    def test_empty_database_first_insert(self):
        p = self.tmp_path / 'logs.sqlite'
        with sqlite3.connect(p) as conn:
            conn.execute('CREATE TABLE logs(id INTEGER PRIMARY KEY)')
        tracker = m.DbTracker(p)
        tracker.poll(0)
        with sqlite3.connect(p) as conn:
            conn.execute('INSERT INTO logs VALUES(100)')
        tracker.poll(1)
        assert tracker.report()['observed_new_rows'] == 1

    def test_db_busy_snapshot_is_unavailable(self):
        tmp_path = self.tmp_path
        monkeypatch = self
        p = tmp_path / 'logs.sqlite'
        with sqlite3.connect(p) as conn:
            conn.execute('CREATE TABLE logs(id INTEGER)')
        real = m.signature
        calls = 0
        def changed(path):
            nonlocal calls
            calls += 1
            value = real(path)
            return (*value[:-1], value[-1] + (1 if calls > 1 else 0))
        monkeypatch.setattr(m, 'signature', changed)
        assert m.db_sample(p)['error'] == 'database changed during snapshot'


    def test_counter_unavailable_reset_and_pid_reuse(self):
        tmp_path = self.tmp_path
        monkeypatch = self
        assert m.counter_delta({'bytes': 10, 'identity': 1}, {'bytes': 20, 'identity': 1})['delta_bytes'] == 10
        assert m.counter_delta({'bytes': 20, 'identity': 1}, {'bytes': 10, 'identity': 1})['delta_bytes'] is None
        assert m.counter_delta({'bytes': 10, 'identity': 1}, {'bytes': 20, 'identity': 2})['delta_bytes'] is None
        assert m.counter_delta({'error': 'unavailable'}, {'bytes': 20, 'identity': 1})['delta_bytes'] is None


    def test_cli_and_mirror(self):
        tmp_path = self.tmp_path
        monkeypatch = self
        for name in ('mac_ssd_audit.py', 'codex_diagnose.py'):
            assert (ROOT / 'scripts' / name).read_bytes() == (ROOT / 'skills/mac-ssd-audit/scripts' / name).read_bytes()
        for folder in ('scripts', 'skills/mac-ssd-audit/scripts'):
            proc = subprocess.run([sys.executable, str(ROOT / folder / 'mac_ssd_audit.py'), 'diagnose-codex',
                                   '--codex-home', str(tmp_path), '--seconds', '0.05', '--interval', '0.05'],
                                  capture_output=True, text=True, check=True)
            r = json.loads(proc.stdout)
            assert r['process_disk_write']['delta_bytes'] is None
            assert r['device_host_writes']['delta_bytes'] is None
            assert not list(tmp_path.iterdir())
            assert any('causation' in limit for limit in r['limits'])
        help_run = subprocess.run([sys.executable, str(ROOT / 'scripts/mac_ssd_audit.py'), 'audit', '--help'], capture_output=True, text=True)
        assert help_run.returncode == 0
        assert '--online-check' in help_run.stdout

if __name__ == "__main__":
    unittest.main()
