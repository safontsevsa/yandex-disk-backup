"""New-broker launch tests use temporary state and mock every process operation."""
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


SPEC = importlib.util.spec_from_file_location('saved_launch', Path(__file__).with_name('launch-saved-retry.py'))
launch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launch)


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name).resolve()
        self.base = self.root / 'scripts'
        self.base.mkdir(mode=0o700)
        self.volume = self.root / 'KINGSTON'
        self.volume.mkdir()
        self.dest = self.volume / 'YandexDisk-backup'
        self.dest.mkdir()
        self.journal = self.base / 'journals' / 'KINGSTON' / 'verified.sqlite3'
        self.items = [dict(path='disk:/' + name, size=size, md5='a' * 32)
                      for name, size in zip('abcde', (100, 200, 300, 400, 500))]
        self.save(self.dest / 'manifest.json', dict(files=self.items, directories=[]), 0o700)
        self.save(self.dest / 'summary.json', dict(phase='complete_with_errors', inventory_verified=True,
                  source_changed=False, files_verified=1, bytes_verified=100, files_failed_count=4, bytes_failed=1400), 0o700)
        self.save(self.dest / 'failed-files.json', dict(files=self.items[2:], directories=[],
                  files_failed_count=3, bytes_failed=1200), 0o700)
        self.progress = dict(phase='paused', destination='/Volumes/ADATA/YandexDisk-backup', updated_at='old',
                             retry_only_failed=True, files_total=4, bytes_total=1400, files_verified=1,
                             bytes_verified=200, files_failed_count=3, bytes_failed=1200, workers=128)
        self.save(self.base / 'progress.json', self.progress)
        self.save(self.base / 'broker.json', dict(status='failed_waiting_retry', broker_pid=12345, return_code=130))
        self.save(self.base / 'retry-remaining.json', dict(status='paused', previous_verified=dict(
                  files_verified=1, bytes_verified=100, files_total=5, bytes_total=1500)))
        for name in ('retry-remaining.lock', 'download.lock'):
            (self.base / name).touch(mode=0o600)
        self.target = dict(volume=self.volume, journal_path=self.journal)
        self.args = ['--volume', str(self.volume), '--journal-path', str(self.journal), '--client-id', 'a' * 32]
        self.output = io.StringIO()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(self.output))
        self.stack.enter_context(mock.patch.object(launch, 'BASE', self.base))
        self.stack.enter_context(mock.patch.object(launch.retry, 'BASE', self.base))
        self.stack.enter_context(mock.patch.object(launch.retry, 'VOLUME', self.volume))
        self.stack.enter_context(mock.patch.object(launch.retry, 'DEST', self.dest))
        self.raw_owner = self.stack.enter_context(mock.patch.object(launch, 'raw_owned_authorizer', return_value=False))
        self.stack.enter_context(mock.patch.object(launch.retry, 'owned_broker', return_value=True))
        self.stack.enter_context(mock.patch.object(launch, 'owned_child', side_effect=lambda pid, parent: type(pid) is int and pid > 1))
        self.stack.enter_context(mock.patch.object(launch.target_config, 'validate_target', side_effect=lambda value, base:
                                  dict(volume=Path(value['volume']), journal_path=Path(value['journal_path']))))
        self.stack.enter_context(mock.patch.object(launch.retry.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**10)))
        self.popen = self.stack.enter_context(mock.patch.object(launch.subprocess, 'Popen'))
        self.stack.enter_context(mock.patch.object(launch.time, 'sleep'))
        real_stat = Path.stat

        def volume_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if path == self.volume:
                values = list(result)
                values[2] += 1
                return os.stat_result(values)
            return result

        self.stack.enter_context(mock.patch.object(Path, 'stat', volume_stat))
        self.stack.enter_context(mock.patch.object(Path, 'is_mount', lambda path: path == self.volume))

    @staticmethod
    def save(path, data, mode=0o600):
        path.write_text(json.dumps(data), encoding='utf-8')
        path.chmod(mode)

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in self.root.rglob('*') if path.is_file()}

    def activate(self):
        self.save(self.base / 'progress.json', dict(phase='downloading', updated_at='new', retry_only_failed=True,
                  destination=str(self.dest), workers=128, download_attempts_max=3, files_total=3, bytes_total=1200,
                  files_verified=0, bytes_verified=0, files_failed_count=3))
        self.save(self.base / 'broker.json', dict(status='running', broker_pid=87654, child_pid=98765))

    def test_check_is_readonly_accepts_relocated_checkpoint_and_rebases_saved_totals(self):
        before = self.snapshot()
        launch.main([*self.args, '--check'])
        self.assertEqual(self.snapshot(), before)
        self.popen.assert_not_called()
        self.assertFalse((self.base / 'journals').exists())
        result = json.loads(self.output.getvalue())
        self.assertEqual(result['status'], 'saved_retry_ready')
        self.assertEqual(result['previous_verified']['files_verified'], 2)
        self.assertEqual(result['previous_verified']['bytes_verified'], 300)
        self.assertEqual(result['retry_queue'], dict(files_total=3, bytes_total=1200))

    def test_live_old_authorizer_is_refused_even_with_a_different_old_destination(self):
        self.raw_owner.return_value = True
        before = self.snapshot()
        with self.assertRaisesRegex(launch.LaunchError, 'existing_authorizer_is_still_alive'):
            launch.main([*self.args, '--check'])
        self.popen.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_success_releases_download_lock_before_auth_and_removes_only_acknowledged_mode(self):
        process = SimpleNamespace(pid=87654, poll=mock.Mock(return_value=None))

        def start(command, cwd, **kwargs):
            self.assertIn('--journal-path', command)
            self.assertIn(str(self.journal), command)
            self.assertTrue((self.base / 'retry-only-failed').exists())
            self.assertIs(kwargs['start_new_session'], True)
            self.assertEqual(kwargs['stdin'], launch.subprocess.DEVNULL)
            self.assertEqual(kwargs['stderr'], launch.subprocess.STDOUT)
            self.assertIs(kwargs['close_fds'], True)
            status = kwargs['stdout']
            self.assertEqual(os.fstat(status.fileno()).st_mode & 0o777, 0o600)
            status.write(b'SECRET raw log must not be relayed\nLOCAL_AUTH_URL=http://127.0.0.1:65432/\n')
            with launch.retry.private_lock(self.base / 'download.lock', readonly=True):
                pass
            return process

        self.popen.side_effect = start
        started = False

        def tick():
            nonlocal started
            if not started:
                self.activate()
                started = True
                return 0
            return 0.1

        with mock.patch.object(launch.time, 'monotonic', side_effect=tick):
            launch.main(self.args)
        self.assertFalse((self.base / 'retry-only-failed').exists())
        state = json.loads((self.base / 'retry-remaining.json').read_text())
        self.assertEqual(state['status'], 'downloading_saved_failures')
        self.assertEqual(state['previous_verified']['files_verified'], 2)
        self.assertEqual(state['retry_queue']['files_total'], 3)
        self.assertEqual(self.journal.parent.stat().st_mode & 0o777, 0o700)
        self.assertFalse(self.journal.exists())
        self.assertEqual((self.base / 'target.json').stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.popen.call_args.kwargs['stdout'].closed)
        self.assertEqual(self.output.getvalue().count('LOCAL_AUTH_URL='), 1)
        self.assertNotIn('SECRET', self.output.getvalue())

    def test_timeout_keeps_mode_while_authorizer_can_still_start(self):
        self.popen.return_value = SimpleNamespace(pid=87654, poll=mock.Mock(return_value=None))
        with mock.patch.object(launch.time, 'monotonic', side_effect=[0, 1201]), \
                self.assertRaisesRegex(launch.LaunchError, 'start_timeout'):
            launch.main(self.args)
        self.assertTrue((self.base / 'retry-only-failed').exists())
        state = json.loads((self.base / 'retry-remaining.json').read_text())
        self.assertEqual(state['previous_verified']['files_verified'], 2)

    def test_authorizer_death_keeps_mode_in_case_of_an_unannounced_child(self):
        self.popen.return_value = SimpleNamespace(pid=87654, poll=mock.Mock(return_value=1))
        with self.assertRaisesRegex(launch.LaunchError, 'authorizer_exited'):
            launch.main(self.args)
        self.assertTrue((self.base / 'retry-only-failed').exists())
        state = json.loads((self.base / 'retry-remaining.json').read_text())
        self.assertEqual(state['previous_verified']['files_verified'], 2)

    def test_stale_or_wrong_new_progress_is_not_an_acknowledgement(self):
        broker = dict(status='running', broker_pid=87654, child_pid=98765)
        progress = dict(phase='downloading', updated_at='new', retry_only_failed=True, destination=str(self.dest),
                        workers=128, download_attempts_max=3, files_total=3, bytes_total=1200)
        queue = dict(files_total=3, bytes_total=1200)
        self.assertTrue(launch.acknowledged(progress, broker, 87654, 'old', queue, self.target))
        for changes in (dict(updated_at='old'), dict(phase='checking_local_files'), dict(files_total=4),
                        dict(destination='/Volumes/ADATA/YandexDisk-backup'), dict(download_attempts_max=1),
                        dict(download_attempts_max=6), dict(download_attempts_max=None)):
            self.assertFalse(launch.acknowledged({**progress, **changes}, broker, 87654, 'old', queue, self.target))

    def test_unsafe_journal_path_or_parent_is_refused_without_authorization(self):
        with self.assertRaisesRegex(launch.LaunchError, 'private_local_directory'):
            launch.journal_ready(self.root / 'outside.sqlite3')
        (self.base / 'journals').mkdir(mode=0o755)
        (self.base / 'journals').chmod(0o755)
        with self.assertRaisesRegex(launch.LaunchError, 'unsafe_journal_directory'):
            launch.main([*self.args, '--check'])
        self.popen.assert_not_called()

    def test_source_metadata_change_during_plan_is_refused_before_any_launch_writes(self):
        original = launch.retry.validate_plan

        def changing(*args, **kwargs):
            value = original(*args, **kwargs)
            (self.dest / 'summary.json').write_text('{}')
            return value

        with mock.patch.object(launch.retry, 'validate_plan', side_effect=changing), \
                self.assertRaisesRegex(launch.LaunchError, 'changed_during_validation'):
            launch.main([*self.args, '--check'])
        self.popen.assert_not_called()
        self.assertFalse((self.base / 'target.json').exists())

    def test_unsafe_authorization_log_is_refused_before_target_or_marker_writes(self):
        path = self.base / 'authorization-status.log'
        path.write_bytes(b'untouched synthetic content')
        path.chmod(0o644)
        before = self.snapshot()
        with self.assertRaisesRegex(launch.LaunchError, 'unsafe_authorization_status_log'):
            launch.main(self.args)
        self.assertEqual(self.snapshot(), before)
        self.popen.assert_not_called()
        self.assertFalse((self.base / 'target.json').exists())

    def test_status_parser_accepts_only_exact_loopback_root_url(self):
        status, identity = launch.open_auth_status()
        with status:
            status.write(b'raw SECRET\nLOCAL_AUTH_URL=https://example.invalid/?token=SECRET\n'
                         b'LOCAL_AUTH_URL=http://127.0.0.1:65536/\n'
                         b'LOCAL_AUTH_URL=http://127.0.0.1:60000/token?secret=SECRET\n')
        self.assertIsNone(launch.authorization_url(identity))
        with (self.base / 'authorization-status.log').open('ab') as output:
            output.write(b'LOCAL_AUTH_URL=http://127.0.0.1:60000/\n')
        self.assertEqual(launch.authorization_url(identity), 'http://127.0.0.1:60000/')

    def test_auth_status_symlink_is_rejected_without_overwriting_target(self):
        target = self.root / 'untouched'
        target.write_bytes(b'not an auth log')
        (self.base / 'authorization-status.log').symlink_to(target)
        with self.assertRaisesRegex(launch.LaunchError, 'unsafe_authorization_status_log'):
            launch.main([*self.args, '--check'])
        self.assertEqual(target.read_bytes(), b'not an auth log')


class RawOwnershipTests(unittest.TestCase):
    def test_raw_old_broker_check_ignores_destination_but_requires_owned_exact_script(self):
        command = f'{os.getuid()} /usr/bin/python3 {launch.BASE / "authorize.py"} --volume /Volumes/OLD'
        with mock.patch.object(launch.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=command)):
            self.assertTrue(launch.raw_owned_authorizer(12345))
        for command in (f'{os.getuid()} /usr/bin/python3 /tmp/other.py {launch.BASE / "authorize.py"}',
                        f'{os.getuid()+1} /usr/bin/python3 {launch.BASE / "authorize.py"}'):
            with mock.patch.object(launch.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=command)):
                self.assertFalse(launch.raw_owned_authorizer(12345))


if __name__ == '__main__':
    unittest.main()
