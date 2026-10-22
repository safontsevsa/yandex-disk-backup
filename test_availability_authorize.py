"""Synthetic authorization dispatch tests: no real token, socket, or API."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse
from unittest import mock


SPEC = importlib.util.spec_from_file_location('availability_auth_under_test', Path(__file__).with_name('authorize.py'))
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)


class AuthorizeAvailabilityTests(unittest.TestCase):
    def exercise(self, availability, child_code=0, extra=()):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            original = b'{"status":"paused","do_not_change":true}\n'
            (root / 'broker.json').write_bytes(original)
            (root / 'retry-download').write_text('leave the migration trigger alone')
            captured = {}
            fake_token = 'synthetic_test_credential'

            class Thread:
                def __init__(self, target, **kwargs): self.target = target
                def start(self): self.target()
                def join(self): pass

            class Server:
                server_port = 12345

                def __init__(self, address, handler): self.handler = handler
                def shutdown(self): pass
                def server_close(self): pass

                def serve_forever(self):
                    handler = object.__new__(self.handler)
                    handler.server = self
                    handler.path = '/'
                    handler.headers = {'Host': '127.0.0.1:12345'}
                    handler.reply = lambda status, body: captured.update(page=body)
                    handler.do_GET()
                    body = urllib.parse.urlencode({'csrf': 'test_nonce', 'token': fake_token}).encode()
                    handler.path = '/token'
                    handler.headers = {'Host': '127.0.0.1:12345', 'Origin': 'http://127.0.0.1:12345',
                                       'Content-Length': str(len(body))}
                    handler.rfile = io.BytesIO(body)
                    handler.reply = lambda status, body: captured.update(post_status=status, post_reply=body)
                    handler.do_POST()

            class Process:
                pid = 12346
                def wait(self): return child_code

            def spawn(command, **kwargs):
                captured.update(command=command, passed_token=kwargs['env'].get('YANDEX_DISK_TOKEN'))
                return Process()

            args = ['authorize.py', '--client-id', 'a' * 32]
            if availability:
                args += ['--availability-only', '--volume', '/Volumes/KINGSTON', '--workers', '128']
            args += list(extra)
            with mock.patch.object(auth, '__file__', str(root / 'authorize.py')), \
                    mock.patch.object(auth.sys, 'argv', args), \
                    mock.patch.object(auth, 'HTTPServer', Server), \
                    mock.patch.object(auth.threading, 'Thread', Thread), \
                    mock.patch.object(auth.os, 'environ', {}), \
                    mock.patch.object(auth.secrets, 'token_urlsafe', return_value='test_nonce'), \
                    mock.patch('download.DiskAPI') as api, \
                    mock.patch.object(auth.subprocess, 'Popen', side_effect=spawn), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                api.return_value.get.return_value = {'used_space': 0}
                with self.assertRaises(SystemExit) as ended:
                    auth.main()
                self.assertEqual(ended.exception.code, child_code)
            captured['stdout'] = stdout.getvalue()
            if availability:
                self.assertEqual((root / 'broker.json').read_bytes(), original)
                self.assertEqual((root / 'retry-download').read_text(), 'leave the migration trigger alone')
                self.assertFalse((root / 'download.log').exists())
            own_broker = root / ('availability-broker.json' if availability else 'broker.json')
            captured['broker'] = json.loads(own_broker.read_text())
            self.assertNotIn(fake_token, captured['stdout'])
            self.assertNotIn(fake_token, captured['page'])
            self.assertNotIn(fake_token, captured['post_reply'])
            self.assertEqual(captured['passed_token'], fake_token)
            return captured

    def test_availability_dispatch_never_starts_download_or_changes_migration_state(self):
        captured = self.exercise(True)
        command = captured['command']
        self.assertTrue(any(value.endswith('/availability.py') for value in command))
        self.assertFalse(any(value.endswith('/download.py') for value in command))
        self.assertEqual(command[-4:], ['--volume', '/Volumes/KINGSTON', '--workers', '128'])
        self.assertEqual(captured['broker']['status'], 'complete')
        self.assertIn('Проверить доступность', captured['page'])
        self.assertIn('/Volumes/KINGSTON', captured['page'])
        self.assertNotIn('/Volumes/ADATA', captured['page'])

    def test_availability_child_failure_does_not_enter_download_retry_loop(self):
        captured = self.exercise(True, child_code=1)
        self.assertEqual(captured['broker']['status'], 'failed')
        self.assertEqual(captured['broker']['return_code'], 1)

    def test_original_default_authorization_still_dispatches_download(self):
        captured = self.exercise(False)
        self.assertTrue(any(value.endswith('/download.py') for value in captured['command']))
        self.assertFalse(any(value.endswith('/availability.py') for value in captured['command']))
        self.assertEqual(captured['broker']['status'], 'complete')

    def test_kingston_download_form_and_child_share_the_explicit_journal_and_volume(self):
        extra = ['--volume', '/Volumes/KINGSTON', '--workers', '128', '--journal-path', '/private/tmp/synthetic.sqlite3']
        captured = self.exercise(False, extra=extra)
        self.assertEqual(captured['command'][-6:], extra)
        self.assertIn('Скачать Яндекс Диск на KINGSTON', captured['page'])
        self.assertIn('/Volumes/KINGSTON/YandexDisk-backup/data', captured['page'])
        self.assertNotIn('/Volumes/ADATA', captured['page'])

    def test_availability_requires_volume_and_cannot_replace_downloader(self):
        for extra in (['--availability-only'],
                      ['--availability-only', '--volume', '/Volumes/KINGSTON', '--replace-pid', '999']):
            with self.subTest(extra=extra), mock.patch.object(auth.sys, 'argv',
                    ['authorize.py', '--client-id', 'a' * 32, *extra]), \
                    mock.patch.object(auth, 'HTTPServer', side_effect=AssertionError('no server allowed')), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as ended:
                    auth.main()
                self.assertEqual(ended.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
