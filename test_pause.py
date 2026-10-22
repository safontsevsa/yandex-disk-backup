"""Safe pause tests: all signals/processes mocked, all state in temporary folders."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import test_resume_paused as fixtures

retry = fixtures.retry


SPEC = importlib.util.spec_from_file_location('live_pause', Path(__file__).with_name('pause.py'))
pause = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pause)


class PauseTests(unittest.TestCase):
    save = staticmethod(fixtures.PausedRetryTests.save)
    save_failures = fixtures.PausedRetryTests.save_failures
    snapshot = fixtures.PausedRetryTests.snapshot

    def setUp(self):
        fixtures.PausedRetryTests.setUp(self)
        self.stack.enter_context(mock.patch.object(pause, 'retry', retry))
        self.stack.enter_context(mock.patch.object(pause, 'BASE', self.base))
        self.kill = self.stack.enter_context(mock.patch.object(pause.os, 'kill'))
        self.stack.enter_context(mock.patch.object(pause.time, 'sleep'))
        self.identity = (os.getuid(), self.broker['broker_pid'], ('/usr/bin/python3', str(self.base / 'download.py')))
        self.stack.enter_context(mock.patch.object(pause, 'owned_downloader', return_value=(45678, self.identity)))
        self.stack.enter_context(mock.patch.object(pause, 'process_identity', return_value=self.identity))

    def running(self):
        self.broker = dict(status='running', broker_pid=12345, child_pid=45678)
        self.progress.update(phase='downloading', active_transfers={'pending': dict(stage='reading', bytes_written=17)},
                             current_file='disk:/c', current_directory='disk:/')
        self.save(self.base / 'broker.json', self.broker)
        self.save(self.base / 'progress.json', self.progress)
        self.save(self.base / 'retry-remaining.json', dict(status='downloading_saved_failures', previous_verified=self.previous))

    def drained(self, target, sig):
        self.assertEqual((target, sig), (45678, signal.SIGTERM))
        self.save(self.base / 'broker.json', dict(status='failed_waiting_retry', return_code=130, broker_pid=12345))
        self.progress.update(files_verified=2, bytes_verified=500, files_failed_count=2, bytes_failed=900)
        self.save(self.base / 'progress.json', self.progress)
        self.save_failures(self.items[3:])

    def test_pause_signals_only_owned_child_and_preserves_final_drain_counts(self):
        self.running()
        self.kill.side_effect = self.drained
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pause.main(['--timeout', '1'])
        self.kill.assert_called_once_with(45678, signal.SIGTERM)
        p = json.loads((self.base / 'progress.json').read_text())
        r = json.loads((self.base / 'retry-remaining.json').read_text())
        self.assertEqual(p['phase'], 'paused')
        self.assertEqual(p['files_verified'], 2)
        self.assertEqual(p['bytes_verified'], 500)
        self.assertEqual(p['active_transfers'], {})
        self.assertIsNone(p['current_file'])
        self.assertEqual(r['previous_verified'], self.previous)
        self.assertEqual(r['resume_policy'], 'manual')
        result = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(result['files_verified'], 3)
        self.assertEqual(result['bytes_verified'], 600)
        self.assertEqual(result['files_remaining'], 2)

    def test_already_paused_does_not_signal_or_rewrite_any_state(self):
        before = self.snapshot()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pause.main([])
        self.kill.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(json.loads(output.getvalue())['status'], 'already_paused')

    def test_delayed_stop_can_finalize_checkpoint_without_another_signal(self):
        self.progress['phase'] = 'downloading'
        self.save(self.base / 'progress.json', self.progress)
        with contextlib.redirect_stdout(io.StringIO()):
            pause.main([])
        self.kill.assert_not_called()
        self.assertEqual(json.loads((self.base / 'progress.json').read_text())['phase'], 'paused')

    def test_check_delayed_stop_does_not_finalize_or_change_checkpoint(self):
        self.progress['phase'] = 'downloading'
        self.save(self.base / 'progress.json', self.progress)
        before = self.snapshot()
        with contextlib.redirect_stdout(io.StringIO()):
            pause.main(['--check'])
        self.kill.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_active_retry_coordinator_refuses_pause_without_a_signal(self):
        self.running()
        with retry.private_lock(self.base / 'retry-remaining.lock', readonly=True):
            with self.assertRaises(BlockingIOError):
                pause.main([])
        self.kill.assert_not_called()

    def test_pending_retry_marker_refuses_pause_without_removing_it(self):
        marker = self.base / 'retry-only-failed'
        marker.touch(mode=0o600)
        with self.assertRaisesRegex(pause.PauseError, 'retry_request_pending'):
            pause.main([])
        self.assertTrue(marker.exists())
        self.kill.assert_not_called()

    def test_lock_replacement_after_drain_is_not_marked_as_paused(self):
        self.running()
        # Simulate a different lock identity without relying on filesystem inode reuse.
        actual = pause.lock_identity()
        with mock.patch.object(pause, 'lock_identity', side_effect=[(actual[0], actual[1] + 1)] * 2), \
                contextlib.redirect_stdout(io.StringIO()):
            self.kill.side_effect = self.drained
            with self.assertRaisesRegex(pause.PauseError, 'download_lock_changed'):
                pause.main(['--timeout', '1'])
        self.assertEqual(json.loads((self.base / 'progress.json').read_text())['phase'], 'downloading')
        self.assertEqual(json.loads((self.base / 'retry-remaining.json').read_text())['status'], 'downloading_saved_failures')

    def test_timeout_does_not_claim_pause_or_erase_transfer_state(self):
        self.running()
        before = self.snapshot()
        with mock.patch.object(pause.time, 'monotonic', side_effect=[0, 0.1, 2]), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(pause.PauseError, 'pause_timeout'):
            pause.main(['--timeout', '1'])
        self.kill.assert_called_once_with(45678, signal.SIGTERM)
        self.assertEqual(self.snapshot(), before)

    def test_changed_child_identity_is_not_signalled(self):
        self.running()
        with mock.patch.object(pause, 'process_identity', return_value=(os.getuid(), 99, self.identity[2])):
            with self.assertRaisesRegex(pause.PauseError, 'ownership_changed'):
                pause.main([])
        self.kill.assert_not_called()

    def test_check_running_target_does_not_signal_or_rewrite_state(self):
        self.running()
        before = self.snapshot()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pause.main(['--check'])
        self.kill.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(json.loads(output.getvalue())['status'], 'pause_ready')

    def test_stopped_broker_with_inconsistent_failure_totals_is_not_published_as_paused(self):
        self.running()

        def bad_drain(target, sig):
            self.drained(target, sig)
            self.progress['bytes_failed'] = 901
            self.save(self.base / 'progress.json', self.progress)

        self.kill.side_effect = bad_drain
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(pause.PauseError, 'totals_not_consistent'):
            pause.main(['--timeout', '1'])
        self.assertEqual(json.loads((self.base / 'progress.json').read_text())['phase'], 'downloading')


class DownloaderOwnershipTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        patch = mock.patch.object(pause, 'BASE', Path(folder.name).resolve())
        patch.start()
        self.addCleanup(patch.stop)

    def test_direct_child_requires_exact_script_uid_and_broker_parent(self):
        good = (os.getuid(), 12345, ('/usr/bin/python3', str(pause.BASE / 'download.py')))
        with mock.patch.object(pause, 'process_identity', return_value=good):
            self.assertEqual(pause.owned_downloader(45678, 12345), (45678, good))
        for identity in ((os.getuid() + 1, good[1], good[2]), (good[0], 99, good[2]),
                         (good[0], good[1], ('/usr/bin/python3', '/tmp/other.py', str(pause.BASE / 'download.py')))):
            with self.subTest(identity=identity), mock.patch.object(pause, 'process_identity', return_value=identity):
                with self.assertRaises(pause.PauseError):
                    pause.owned_downloader(45678, 12345)

    def test_caffeinate_wrapper_resolves_python_child_instead_of_signalling_wrapper(self):
        script = str(pause.BASE / 'download.py')
        wrapper = (os.getuid(), 12345, ('/usr/bin/caffeinate', '-im', '/usr/bin/python3', script))
        python = (os.getuid(), 45678, ('/usr/bin/python3', script))
        with mock.patch.object(pause, 'process_identity', side_effect=[wrapper, python]), \
                mock.patch.object(pause.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='56789\n')):
            self.assertEqual(pause.owned_downloader(45678, 12345), (56789, python))

    def test_process_identity_reads_only_command_uid_parent_not_environment(self):
        result = SimpleNamespace(returncode=0, stdout=f'{os.getuid()} 12345 /usr/bin/python3 "{pause.BASE / "download.py"}"\n')
        with mock.patch.object(pause.subprocess, 'run', return_value=result) as command:
            self.assertEqual(pause.process_identity(45678)[:2], (os.getuid(), 12345))
        arguments = command.call_args.args[0]
        self.assertNotIn('-e', arguments)
        self.assertIn('ppid=', arguments)


if __name__ == '__main__':
    unittest.main()
