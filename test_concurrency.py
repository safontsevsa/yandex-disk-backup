"""Isolated worker configuration and cancellation tests; no live cloud or backup IO."""
import concurrent.futures
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
import urllib.error
from unittest.mock import patch

import download as d


class WorkerConfiguration(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.folder = Path(self.temporary.name).resolve()
        self.path = self.folder / "workers.json"

    def tearDown(self):
        self.temporary.cleanup()

    def config(self, value):
        self.path.write_text(json.dumps(value), encoding="utf-8")
        self.path.chmod(0o600)

    def test_missing_default_and_private_boundaries(self):
        self.assertEqual(d.selected_workers(path=self.path), 8)
        for workers in (1, 8, 16, 32, 48, 64, 65, 128, 256):
            self.config({"workers": workers})
            self.assertEqual(d.selected_workers(path=self.path), workers)

    def test_strict_schema_and_type(self):
        for value in (0, True, False, 257, -1, None, "16", 16.0):
            with self.subTest(value=value):
                self.config({"workers": value})
                with self.assertRaises(d.FatalBackupError):
                    d.selected_workers(path=self.path)
        for value in ({}, [], {"workers": 16, "extra": True}):
            self.config(value)
            with self.assertRaises(d.FatalBackupError):
                d.selected_workers(path=self.path)
        self.path.write_text("invalid JSON", encoding="utf-8")
        with self.assertRaises(d.FatalBackupError):
            d.selected_workers(path=self.path)

    def test_private_owner_regular_size_and_nofollow(self):
        self.config({"workers": 16})
        for permissions in (0o644, 0o666, 0o400):
            self.path.chmod(permissions)
            with self.assertRaises(d.FatalBackupError):
                d.selected_workers(path=self.path)
        self.path.chmod(0o600)
        self.path.write_text(" " * 4097, encoding="utf-8")
        with self.assertRaises(d.FatalBackupError):
            d.selected_workers(path=self.path)
        self.path.unlink()
        target = self.folder / "target"
        target.write_text('{"workers": 16}', encoding="utf-8")
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(d.FatalBackupError):
            d.selected_workers(path=self.path)
        self.path.unlink()
        self.path.mkdir()
        with self.assertRaises(d.FatalBackupError):
            d.selected_workers(path=self.path)
        self.path.rmdir()
        self.config({"workers": 16})
        real = d.os.fstat
        def foreign_owner(fd):
            info = real(fd)
            changed = list(info)
            changed[4] = os.getuid() + 1
            return os.stat_result(changed)
        with patch.object(d.os, "fstat", side_effect=foreign_owner):
            with self.assertRaises(d.FatalBackupError):
                d.selected_workers(path=self.path)

    def test_explicit_override_does_not_read_config(self):
        self.path.symlink_to(self.folder / "missing")
        for workers in (1, 65, 128, 256):
            with patch.object(d.os, "open", side_effect=AssertionError("Explicit override must not read config")):
                self.assertEqual(d.selected_workers(workers, path=self.path), workers)
        for invalid in (True, 0, 257, "16", 16.0):
            with self.assertRaises(d.FatalBackupError):
                d.selected_workers(invalid, path=self.path)

    def test_cli_accepts_256_and_rejects_257_without_live_state_or_api(self):
        with patch.object(d, "PROGRESS", self.folder / "synthetic-progress.json"), patch.object(d.sys, "argv", ["download.py", "--status", "--workers", "256"]), patch.object(d, "DiskAPI", side_effect=AssertionError("No live API permitted")), patch("builtins.print") as output:
            d.main()
        output.assert_called_once_with('{"phase":"not_started"}')
        with patch.object(d.sys, "argv", ["download.py", "--status", "--workers", "257"]), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                d.main()
        self.assertEqual(error.exception.code, 2)


class PoolSafety(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.folder = Path(self.temporary.name).resolve()
        self.backup = d.Backup(None, self.folder, self.folder / "fake-destination")
        self.backup.progress = lambda **values: self.backup.state.update(values)
        self.persisted = []
        self.backup.persist_failures = lambda force=False: self.persisted.append(force)
        def mount():
            if self.backup.stop.is_set():
                raise d.FatalBackupError("Synthetic stop")
        self.backup.check_mount = mount
        self.files = [{"path": f"disk:/fake-{index}", "size": index + 1} for index in range(12)]

    def tearDown(self):
        self.temporary.cleanup()

    def test_actual_pool_caps_simultaneous_downloads(self):
        lock, full, release = threading.Lock(), threading.Event(), threading.Event()
        counts = {"active": 0, "peak": 0, "finished": 0}
        def download(item):
            with lock:
                counts["active"] += 1
                counts["peak"] = max(counts["peak"], counts["active"])
                if counts["active"] == 3:
                    full.set()
            if not release.wait(3):
                raise AssertionError("Synthetic workers failed to start")
            with lock:
                counts["active"] -= 1
                counts["finished"] += 1
            return True
        self.backup.download = download
        def unblock():
            full.wait(3)
            release.set()
        coordinator = threading.Thread(target=unblock)
        coordinator.start()
        try:
            self.backup.download_batch(self.files, 3)
        finally:
            release.set()
            coordinator.join(3)
        self.assertEqual(counts["peak"], 3)
        self.assertEqual(counts["finished"], len(self.files))
        self.assertEqual(self.backup.state["files_verified"], len(self.files))
        self.assertEqual(self.backup.state["bytes_verified"], sum(item["size"] for item in self.files))
        self.assertEqual(self.backup.state["files_pending_count"], 0)

    def test_fatal_failure_stops_running_and_cancels_queued(self):
        started, lock = [], threading.Lock()
        first = max(self.files, key=lambda item: item["size"])["path"]
        def download(item):
            with lock:
                started.append(item["path"])
            if item["path"] == first:
                raise d.FatalBackupError("Synthetic fatal failure")
            if not self.backup.stop.wait(3):
                raise AssertionError("Running download was not stopped")
            raise d.FatalBackupError("Synthetic stop")
        self.backup.download = download
        with self.assertRaises(d.FatalBackupError):
            self.backup.download_batch(self.files, 2)
        self.assertTrue(self.backup.stop.is_set())
        self.assertLess(len(started), len(self.files))
        self.assertIn(True, self.persisted)


    def test_interrupt_during_submission_stops_already_started_work(self):
        real_pool = concurrent.futures.ThreadPoolExecutor
        entered = threading.Event()
        def download(item):
            entered.set()
            if not self.backup.stop.wait(3):
                raise AssertionError("Submission interruption did not stop running work")
            raise d.FatalBackupError("Synthetic stop")
        self.backup.download = download
        class InterruptingPool:
            def __init__(self, **kwargs):
                self.pool, self.calls = real_pool(**kwargs), 0
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.pool.shutdown(wait=True)
            def submit(self, *args):
                self.calls += 1
                if self.calls == 2:
                    self.assert_entered()
                    raise KeyboardInterrupt()
                return self.pool.submit(*args)
            def assert_entered(self):
                if not entered.wait(3):
                    raise AssertionError("Synthetic first worker did not start")
        with patch.object(d.concurrent.futures, "ThreadPoolExecutor", InterruptingPool):
            with self.assertRaises(KeyboardInterrupt):
                self.backup.download_batch(self.files, 2)
        self.assertTrue(self.backup.stop.is_set())
        self.assertIn(True, self.persisted)


class APIPacing(unittest.TestCase):
    class Clock:
        def __init__(self):
            self.now, self.delays = 100.0, []
        def monotonic(self):
            return self.now
        def sleep(self, delay):
            self.delays.append(delay)
            self.now += delay

    def test_shared_pacing_has_no_idle_burst_and_safe_snapshot(self):
        clock = self.Clock()
        api = d.DiskAPI("FAKE_ONLY_MEMORY_TOKEN")
        started = []
        def open_request(*args, **kwargs):
            started.append(clock.now)
            # Counter lock must be released before the request/callback can run.
            self.assertTrue(api.counter_lock.acquire(blocking=False))
            api.counter_lock.release()
            return io.BytesIO(b'{"ok": true}')
        api.opener = type("Opener", (), {"open": staticmethod(open_request)})()
        with patch.object(d.time, "monotonic", clock.monotonic), patch.object(d.time, "sleep", clock.sleep):
            for _ in range(3):
                self.assertEqual(api.get("/fake", _attempts=1), {"ok": True})
            clock.now += 20
            api.get("/fake", _attempts=1)
            api.get("/fake", _attempts=1)
        for first, second in zip(started, started[1:]):
            self.assertGreaterEqual(second - first, 0.05 - 10**-9)
        self.assertEqual(api.request_snapshot(), {"api_requests_total": 5, "api_http_error_counts": {},
            "api_http_429_count": 0, "api_rate_limit_rps": 20})

    def test_http429_is_counted_even_when_single_attempt_is_exhausted(self):
        clock = self.Clock()
        api = d.DiskAPI("FAKE_ONLY_MEMORY_TOKEN")
        def denied(*args, **kwargs):
            raise urllib.error.HTTPError("https://example.invalid/private", 429, "omitted", {}, io.BytesIO(b""))
        api.opener = type("Opener", (), {"open": staticmethod(denied)})()
        with patch.object(d.time, "monotonic", clock.monotonic), patch.object(d.time, "sleep", clock.sleep):
            with self.assertRaises(d.BackupError):
                api.get("/fake", _attempts=1)
            with self.assertRaises(d.BackupError):
                api.get("/fake", _attempts=5)
        snapshot = api.request_snapshot()
        self.assertEqual(snapshot["api_http_429_count"], 6)
        self.assertEqual(snapshot["api_requests_total"], 6)
        self.assertEqual(snapshot["api_http_error_counts"], {"429": 6})
        self.assertNotIn("FAKE_ONLY_MEMORY_TOKEN", json.dumps(snapshot))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve()
            backup = d.Backup(api, path, path / "fake")
            with patch.object(d, "atomic_json") as save, patch("builtins.print"):
                backup.progress(phase="synthetic")
            self.assertEqual(backup.state["api_http_429_count"], 6)
            self.assertEqual(save.call_args.args[1]["api_rate_limit_rps"], 20)



if __name__ == "__main__":
    unittest.main()
