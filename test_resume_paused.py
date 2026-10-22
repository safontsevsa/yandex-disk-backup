"""Paused retry CLI tests using only temporary state and mocked processes."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location('retry_coordinator', Path(__file__).with_name('start-retry-remaining.py'))
retry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retry)


class PausedRetryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.base = Path(self.folder.name).resolve()
        self.dest = self.base / 'backup'
        self.dest.mkdir()
        self.items = [dict(path='disk:/' + name, size=size, md5='a' * 32)
                      for name, size in zip('abcde', (100, 200, 300, 400, 500))]
        self.progress = dict(phase='paused', updated_at='2026-10-14T20:00:00+0300', retry_only_failed=True,
                             files_total=4, bytes_total=1400, files_verified=1, bytes_verified=200,
                             files_failed_count=3, bytes_failed=1200, workers=128)
        self.broker = dict(status='failed_waiting_retry', return_code=130, broker_pid=12345)
        self.previous = dict(files_verified=1, bytes_verified=100, files_total=5, bytes_total=1500)
        self.save(self.base / 'progress.json', self.progress)
        self.save(self.base / 'broker.json', self.broker)
        self.save(self.base / 'retry-remaining.json', dict(status='paused', previous_verified=self.previous))
        self.save(self.dest / 'manifest.json', dict(files=self.items, directories=[]))
        self.save(self.dest / 'summary.json', dict(phase='complete_with_errors', inventory_verified=True,
                  source_changed=False, files_verified=1, bytes_verified=100, files_failed_count=4, bytes_failed=1400))
        self.save_failures(self.items[2:])
        for name in ('retry-remaining.lock', 'download.lock'):
            path = self.base / name
            path.touch(mode=0o600)
        volume = SimpleNamespace(is_mount=lambda: True,
                                 stat=lambda: SimpleNamespace(st_dev=Path('/').stat().st_dev + 1))
        patches = (mock.patch.object(retry, 'BASE', self.base), mock.patch.object(retry, 'DEST', self.dest),
                   mock.patch.object(retry, 'STATUS', self.base / 'retry-remaining.json'),
                   mock.patch.object(retry, 'VOLUME', volume),
                   mock.patch.object(retry, 'owned_broker', return_value=True),
                   mock.patch.object(retry, 'selected_workers', return_value=128),
                   mock.patch.object(retry.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**10)))
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for patch in patches:
            self.stack.enter_context(patch)

    @staticmethod
    def save(path, value):
        path.write_text(json.dumps(value), encoding='utf-8')
        path.chmod(0o600)

    def save_failures(self, items):
        self.save(self.dest / 'failed-files.json', dict(files=items, directories=[],
                  files_failed_count=len(items), bytes_failed=sum(item['size'] for item in items)))

    def snapshot(self):
        return {str(path.relative_to(self.base)): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in self.base.rglob('*') if path.is_file()}

    def test_paused_plan_rebases_previous_successes_without_requiring_old_failure_totals(self):
        previous, queue = retry.validate_plan(self.progress, resume_paused=True)
        self.assertEqual(previous, dict(files_verified=2, bytes_verified=300, files_total=5, bytes_total=1500))
        self.assertEqual(queue, dict(files_total=3, bytes_total=1200))

    def test_check_only_does_not_publish_create_markers_wait_or_change_files(self):
        before = self.snapshot()
        output = io.StringIO()
        with mock.patch.object(retry, 'publish', side_effect=AssertionError('write')), \
                mock.patch.object(retry, 'marker', side_effect=AssertionError('marker')), \
                mock.patch.object(retry.time, 'sleep', side_effect=AssertionError('wait')), \
                contextlib.redirect_stdout(output):
            retry.main(['--resume-paused', '--check'])
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'paused_retry_ready')
        self.assertEqual(result['previous_verified']['files_verified'], 2)
        self.assertEqual(self.snapshot(), before)

    def test_check_missing_guard_does_not_create_it(self):
        (self.base / 'retry-remaining.lock').unlink()
        before = self.snapshot()
        with self.assertRaises(FileNotFoundError):
            retry.main(['--resume-paused', '--check'])
        self.assertEqual(self.snapshot(), before)

    def test_check_failure_reporting_preserves_pause_metadata(self):
        before = self.snapshot()
        with mock.patch.object(retry, 'publish', side_effect=AssertionError('write')), \
                contextlib.redirect_stdout(io.StringIO()):
            retry.report_failure(RuntimeError('safe_reason'), check=True)
            retry.report_failure(RuntimeError('safe_reason'), resume_paused=True)
        self.assertEqual(self.snapshot(), before)

    def test_paused_refuses_active_broker_other_exit_code_or_reported_child(self):
        for changes in (dict(status='running'), dict(return_code=2), dict(child_pid=9876)):
            with self.subTest(changes=changes):
                self.save(self.base / 'broker.json', {**self.broker, **changes})
                with self.assertRaisesRegex(RuntimeError, 'not_a_paused'):
                    retry.main(['--resume-paused', '--check'])
                self.assertFalse((self.base / 'retry-only-failed').exists())

    def test_paused_refuses_inconsistent_queue_or_baseline(self):
        for changes in (dict(bytes_failed=1201), dict(files_verified=2), dict(bytes_total=1401)):
            with self.subTest(changes=changes):
                p = {**self.progress, **changes}
                with self.assertRaisesRegex(RuntimeError, 'baseline_not_consistent'):
                    retry.validate_plan(p, resume_paused=True)
        changed = [dict(item) for item in self.items[2:]]
        changed[0]['md5'] = 'b' * 32
        self.save_failures(changed)
        with self.assertRaisesRegex(RuntimeError, 'queue_not_consistent'):
            retry.validate_plan(self.progress, resume_paused=True)

    def test_after_completion_plan_retains_old_consistency_requirement(self):
        with self.assertRaisesRegex(RuntimeError, 'failure_totals_not_consistent'):
            retry.validate_plan(self.progress)
        self.save_failures(self.items[1:])
        self.assertEqual(retry.validate_plan(self.progress),
                         (self.previous, dict(files_total=4, bytes_total=1400)))

    def test_pending_broken_symlink_is_refused(self):
        (self.base / 'retry-download').symlink_to(self.base / 'absent')
        with self.assertRaisesRegex(RuntimeError, 'pending_marker_changed'):
            retry.main(['--resume-paused', '--check'])

    def test_paused_resume_publishes_new_baseline_and_confirms_new_scope(self):
        original_marker = retry.marker

        def simulated_marker(name):
            value = original_marker(name)
            if name == 'retry-download':
                self.save(self.base / 'broker.json', dict(status='running', broker_pid=12345, child_pid=34567))
                self.save(self.base / 'progress.json', dict(phase='downloading', updated_at='2026-10-14T20:00:01+0300',
                          retry_only_failed=True, files_total=3, bytes_total=1200, workers=128, download_attempts_max=3,
                          files_verified=0, bytes_verified=0, files_failed_count=3))
                value[0].unlink()  # The mock broker consumes its trigger.
            return value

        with mock.patch.object(retry, 'marker', side_effect=simulated_marker), contextlib.redirect_stdout(io.StringIO()):
            retry.main(['--resume-paused'])
        state = json.loads((self.base / 'retry-remaining.json').read_text())
        self.assertEqual(state['status'], 'downloading_saved_failures')
        self.assertEqual(state['previous_verified']['files_verified'], 2)
        self.assertEqual(state['previous_verified']['bytes_verified'], 300)
        self.assertEqual(state['retry_queue'], dict(files_total=3, bytes_total=1200))
        self.assertFalse((self.base / 'retry-only-failed').exists())


class StartupAcknowledgementTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        patch = mock.patch.object(retry, 'BASE', Path(folder.name).resolve())
        patch.start()
        self.addCleanup(patch.stop)

    def test_consumed_trigger_with_original_pause_state_is_not_a_startup_failure(self):
        original = dict(status='failed_waiting_retry', return_code=130, broker_pid=12345)
        p = dict(phase='paused', updated_at='old')
        self.assertFalse(retry.startup_failed(p, dict(original), original, 'old', False, False))
        self.assertFalse(retry.startup_failed({**p, 'updated_at': 'new'}, original, original, 'old', False, False))
        self.assertTrue(retry.startup_failed(p, {**original, 'return_code': 1}, original, 'old', False, False))
        self.assertTrue(retry.startup_failed(p, original, original, 'old', True, False))

    def test_requires_changed_progress_and_queue_scope_before_consuming_mode(self):
        broker = dict(status='running', broker_pid=12345, child_pid=34567)
        queue = dict(files_total=3, bytes_total=1200)
        p = dict(phase='downloading', updated_at='new', retry_only_failed=True, download_attempts_max=3, **queue)
        self.assertTrue(retry.startup_acknowledged(p, broker, 12345, None, 'old', queue))
        for changes in (dict(updated_at='old'), dict(phase='paused'), dict(files_total=4),
                        dict(bytes_total=1400), dict(retry_only_failed=False),
                        dict(download_attempts_max=6), dict(download_attempts_max=None),
                        dict(phase='authenticating', files_total=None, bytes_total=None)):
            with self.subTest(changes=changes):
                self.assertFalse(retry.startup_acknowledged({**p, **changes}, broker, 12345, None, 'old', queue))
        self.assertFalse(retry.startup_acknowledged(p, broker, 12345, 34567, 'old', queue))

    def test_broker_ownership_requires_exact_python_script_argument(self):
        uid = os.getuid()
        valid = f'{uid} /usr/bin/python3 {retry.BASE / "authorize.py"} --port 55588'
        invalid = (f'{uid} /usr/bin/python3 /tmp/other.py {retry.BASE / "authorize.py"}',
                   f'{uid} /bin/sh -c "python3 {retry.BASE / "authorize.py"}"',
                   f'{uid} /usr/bin/python3 -c "{retry.BASE / "authorize.py"}"',
                   f'{uid + 1} /usr/bin/python3 {retry.BASE / "authorize.py"}')
        with mock.patch.object(retry.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=valid)):
            self.assertTrue(retry.owned_broker(12345))
        for command in invalid:
            with self.subTest(command=command), mock.patch.object(retry.subprocess, 'run',
                      return_value=SimpleNamespace(returncode=0, stdout=command)):
                self.assertFalse(retry.owned_broker(12345))


if __name__ == '__main__':
    unittest.main()
