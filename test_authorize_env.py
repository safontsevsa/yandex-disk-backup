"""Synthetic environment authorization tests: no credential, server, or API."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location('env_auth_under_test', Path(__file__).with_name('authorize.py'))
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)


class AuthorizeEnvironmentTests(unittest.TestCase):
    def test_environment_bypasses_form_and_passes_token_only_in_child_environment(self):
        token = 'synthetic_env_credential-1.2'
        environment = {'YANDEX_DISK_TOKEN': token, 'SYNTHETIC_OTHER': 'retained'}
        captured = {}
        extra = ['--volume', '/Volumes/KINGSTON', '--workers', '128',
                 '--journal-path', '/private/tmp/synthetic.sqlite3']
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)

            class Process:
                pid = 12346
                def wait(self): return 0

            def api_get(path):
                self.assertEqual(path, '/')
                self.assertNotIn('YANDEX_DISK_TOKEN', environment)
                return {'used_space': 0}

            def spawn(command, **kwargs):
                self.assertNotIn('YANDEX_DISK_TOKEN', environment)
                captured.update(command=command, child_env=kwargs['env'].copy())
                return Process()

            with mock.patch.object(auth, '__file__', str(root / 'authorize.py')), \
                    mock.patch.object(auth.sys, 'argv', ['authorize.py', '--client-id', 'a' * 32, *extra]), \
                    mock.patch.object(auth.os, 'environ', environment), \
                    mock.patch.object(auth, 'HTTPServer', side_effect=AssertionError('No form allowed')), \
                    mock.patch.object(auth.threading, 'Thread', side_effect=AssertionError('No thread allowed')), \
                    mock.patch('download.DiskAPI') as api, \
                    mock.patch.object(auth.subprocess, 'Popen', side_effect=spawn), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                api.return_value.get.side_effect = api_get
                with self.assertRaises(SystemExit) as ended:
                    auth.main()
                self.assertEqual(ended.exception.code, 0)
                api.assert_called_once_with(token)
            self.assertEqual(captured['command'][-6:], extra)
            self.assertTrue(any(value.endswith('/download.py') for value in captured['command']))
            self.assertEqual(captured['child_env'], {'SYNTHETIC_OTHER': 'retained', 'YANDEX_DISK_TOKEN': token})
            self.assertNotIn(token, ' '.join(captured['command']))
            self.assertNotIn(token, stdout.getvalue())
            self.assertNotIn('LOCAL_AUTH_URL', stdout.getvalue())
            self.assertNotIn('YANDEX_DISK_TOKEN', environment)
            self.assertEqual(json.loads((root / 'broker.json').read_text())['status'], 'complete')
            for path in root.iterdir():
                self.assertNotIn(token.encode(), path.read_bytes())

    def test_invalid_nonempty_environment_is_rejected_without_bind_api_or_files(self):
        for token in ('contains a space', 'newline\n', 'юникод', 'x' * 2049, '\t'):
            with self.subTest(token_kind=repr(token[:10])):
                environment = {'YANDEX_DISK_TOKEN': token}
                with tempfile.TemporaryDirectory() as folder, \
                        mock.patch.object(auth, '__file__', str(Path(folder) / 'authorize.py')), \
                        mock.patch.object(auth.sys, 'argv', ['authorize.py', '--client-id', 'a' * 32]), \
                        mock.patch.object(auth.os, 'environ', environment), \
                        mock.patch.object(auth, 'HTTPServer') as server, \
                        mock.patch('download.DiskAPI') as api, \
                        contextlib.redirect_stdout(io.StringIO()) as stdout:
                    with self.assertRaisesRegex(ValueError, '^Invalid environment token$'):
                        auth.main()
                    server.assert_not_called()
                    api.assert_not_called()
                    self.assertEqual(list(Path(folder).iterdir()), [])
                    self.assertEqual(stdout.getvalue(), '')
                    self.assertNotIn('YANDEX_DISK_TOKEN', environment)

    def test_missing_or_empty_environment_keeps_form_fallback(self):
        class FormReached(Exception):
            pass

        for environment in ({}, {'YANDEX_DISK_TOKEN': ''}):
            with self.subTest(environment_present=bool(environment)), \
                    mock.patch.object(auth.sys, 'argv', ['authorize.py', '--client-id', 'a' * 32]), \
                    mock.patch.object(auth.os, 'environ', environment), \
                    mock.patch.object(auth, 'HTTPServer', side_effect=FormReached) as server, \
                    mock.patch('download.DiskAPI') as api:
                with self.assertRaises(FormReached):
                    auth.main()
                server.assert_called_once()
                api.assert_not_called()
                self.assertNotIn('YANDEX_DISK_TOKEN', environment)


if __name__ == '__main__':
    unittest.main()
