"""Three complete file attempts using synthetic files and mocked API/transports."""
import contextlib
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
import urllib.error

import download


class StopEvent:
    def __init__(self):
        self.stopped = False
        self.delays = []
        self.cancel_on_wait = False

    def is_set(self):
        return self.stopped

    def set(self):
        self.stopped = True

    def wait(self, seconds):
        self.delays.append(seconds)
        if self.cancel_on_wait:
            self.set()
        return self.stopped


class FileRetryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name).resolve()
        self.destination = self.root / 'backup'
        (self.destination / 'data').mkdir(parents=True)
        (self.destination / '.partial').mkdir()
        volume = SimpleNamespace(is_mount=lambda: True, stat=lambda: self.root.stat())
        self.api = SimpleNamespace(token='synthetic-token', get=mock.Mock())
        self.api.get.side_effect = lambda *args, **kwargs: dict(
            href=f'https://storage.yandex.net/synthetic-{self.api.get.call_count}', method='GET')
        self.backup = download.Backup(self.api, volume, self.destination)
        self.backup.stop = StopEvent()
        self.backup.transport = 'curl'
        self.content = b'synthetic file contents'
        self.item = dict(path='disk:/sample.bin', size=len(self.content), md5=hashlib.md5(self.content).hexdigest())
        self.key = hashlib.sha256(self.item['path'].encode()).hexdigest()
        self.target = self.destination / 'data' / 'sample.bin'
        self.partial = self.destination / '.partial' / self.key
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(download, 'PROGRESS', self.root / 'progress.json'))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.body_outcomes = []
        self.body_urls = []
        self.backup.curl_download = mock.Mock(side_effect=self.transfer)

    def transfer(self, href, output, key, host):
        self.body_urls.append(href)
        result = self.body_outcomes.pop(0) if self.body_outcomes else self.content
        if isinstance(result, BaseException):
            raise result
        output.write(result)
        return len(result)

    def assert_attempt_configuration(self, count):
        self.assertEqual(self.api.get.call_count, count)
        for call in self.api.get.call_args_list:
            self.assertEqual(call.kwargs['_attempts'], 1)
            self.assertIs(call.kwargs['_stop_event'], self.backup.stop)
        self.assertEqual(self.backup.state['download_attempts_max'], 3)

    def test_first_success_stops_after_one_complete_attempt(self):
        self.assertTrue(self.backup.download(self.item))
        self.assertEqual(self.target.read_bytes(), self.content)
        self.assert_attempt_configuration(1)
        self.assertEqual(self.backup.stop.delays, [])
        self.assertEqual(self.backup.transfers, {})

    def test_third_body_success_gets_three_fresh_links_and_two_backoffs(self):
        self.body_outcomes = [download.CurlFailure(28, None) for _ in range(2)] + [self.content]
        self.assertTrue(self.backup.download(self.item))
        self.assert_attempt_configuration(3)
        self.assertEqual(len(set(self.body_urls)), 3)
        self.assertEqual(self.backup.stop.delays, [1, 2])
        self.assertEqual(self.target.read_bytes(), self.content)

    def test_third_api_success_retries_link_failures_as_part_of_file_attempts(self):
        self.api.get.side_effect = [download.HTTPFailure(503) for _ in range(2)] + [
            dict(href='https://storage.yandex.net/synthetic-three', method='GET')]
        self.assertTrue(self.backup.download(self.item))
        self.assert_attempt_configuration(3)
        self.assertEqual(self.backup.curl_download.call_count, 1)
        self.assertEqual(self.backup.stop.delays, [1, 2])

    def test_api_exhaustion_has_three_attempts_not_four_and_publishes_attempt_limits(self):
        self.api.get.side_effect = download.BackupError('Synthetic link unavailable')
        with self.assertRaises(download.BackupError):
            self.backup.download(self.item)
        self.assert_attempt_configuration(3)
        self.assertEqual(self.backup.curl_download.call_count, 0)
        self.assertEqual(self.backup.stop.delays, [1, 2])
        transfer = self.backup.transfers[self.key]
        self.assertEqual((transfer['attempt'], transfer['attempts_max']), (3, 3))
        self.assertFalse(self.target.exists())

    def test_api_and_body_failures_share_one_three_attempt_budget(self):
        self.api.get.side_effect = [download.HTTPFailure(503)] + [
            dict(href=f'https://storage.yandex.net/synthetic-{attempt}', method='GET') for attempt in (2, 3)]
        self.body_outcomes = [download.CurlFailure(28, None)] * 2
        with self.assertRaises(download.BackupError):
            self.backup.download(self.item)
        self.assert_attempt_configuration(3)
        self.assertEqual(self.backup.curl_download.call_count, 2)
        self.assertEqual(self.backup.stop.delays, [1, 2])
        self.assertFalse(self.target.exists())

    def test_body_and_integrity_exhaustion_never_publishes_corrupt_file(self):
        for failure in (download.CurlFailure(18, 200), b'corrupt'):
            with self.subTest(failure=type(failure).__name__):
                self.api.get.reset_mock()
                self.backup.stop.delays.clear()
                self.body_outcomes = [failure] * 3
                with self.assertRaises(download.BackupError):
                    self.backup.download(self.item)
                self.assert_attempt_configuration(3)
                self.assertFalse(self.target.exists())

    def test_incorrect_md5_retries_even_when_size_matches_and_partial_is_truncated(self):
        self.body_outcomes = [b'x' * len(self.content), self.content]
        self.assertTrue(self.backup.download(self.item))
        self.assert_attempt_configuration(2)
        self.assertEqual(self.target.read_bytes(), self.content)
        self.assertEqual(self.backup.stop.delays, [1])

    def test_urllib_incomplete_body_retries_and_success_is_verified(self):
        self.backup.transport = 'urllib'
        opener = SimpleNamespace(open=mock.Mock(side_effect=[http.client.IncompleteRead(b'partial'), io.BytesIO(self.content)]))
        with mock.patch.object(download.urllib.request, 'build_opener', return_value=opener):
            self.assertTrue(self.backup.download(self.item))
        self.assert_attempt_configuration(2)
        self.assertEqual(self.target.read_bytes(), self.content)

    def test_401_and_curl_configuration_or_local_write_errors_stop_immediately(self):
        failures = (download.CurlFailure(22, 401), download.CurlFailure(23, None),
                    download.CurlFailure(3, None), download.FatalBackupError('Synthetic fatal'))
        for failure in failures:
            with self.subTest(error=type(failure).__name__, code=getattr(failure, 'exit_code', None)):
                self.api.get.reset_mock()
                self.backup.stop.delays.clear()
                self.body_outcomes = [failure]
                with self.assertRaises(download.FatalBackupError):
                    self.backup.download(self.item)
                self.assert_attempt_configuration(1)
                self.assertEqual(self.backup.stop.delays, [])
        self.api.get.reset_mock()
        self.api.get.side_effect = download.HTTPFailure(401)
        with self.assertRaises(download.FatalBackupError):
            self.backup.download(self.item)
        self.assert_attempt_configuration(1)

    def test_urllib_http401_is_fatal_and_closes_error_response(self):
        self.backup.transport = 'urllib'
        response = io.BytesIO(b'synthetic')
        error = urllib.error.HTTPError('https://storage.yandex.net/synthetic', 401, 'synthetic', {}, response)
        opener = SimpleNamespace(open=mock.Mock(side_effect=error))
        with mock.patch.object(download.urllib.request, 'build_opener', return_value=opener), \
                self.assertRaises(download.FatalBackupError):
            self.backup.download(self.item)
        self.assert_attempt_configuration(1)
        self.assertTrue(response.closed)

    def test_invalid_https_endpoint_is_fatal_without_a_body_attempt(self):
        for href in ('http://storage.yandex.net/synthetic', 'https://other.invalid/synthetic', 'https://[invalid'):
            with self.subTest(href=href):
                self.api.get.reset_mock()
                self.api.get.side_effect = None
                self.api.get.return_value = dict(href=href, method='GET')
                with self.assertRaises(download.FatalBackupError):
                    self.backup.download(self.item)
                self.assert_attempt_configuration(1)
                self.assertEqual(self.backup.curl_download.call_count, 0)

    def test_existing_file_and_publish_race_never_overwrite_or_retry(self):
        self.target.write_bytes(b'existing different file')
        with self.assertRaises(download.FatalBackupError):
            self.backup.download(self.item)
        self.assertEqual(self.api.get.call_count, 0)
        self.assertEqual(self.target.read_bytes(), b'existing different file')
        self.target.unlink()
        original = self.transfer

        def racing_transfer(*args):
            self.target.write_bytes(b'concurrent file')
            return original(*args)

        self.backup.curl_download.side_effect = racing_transfer
        with self.assertRaises(download.FatalBackupError):
            self.backup.download(self.item)
        self.assert_attempt_configuration(1)
        self.assertEqual(self.target.read_bytes(), b'concurrent file')
        self.assertEqual(self.backup.stop.delays, [])

    def test_checkpoint_failure_stops_after_verified_body_without_network_retry(self):
        self.backup.journal = SimpleNamespace(hit=mock.Mock(return_value=False), record=mock.Mock(return_value=False))
        with self.assertRaises(download.FatalBackupError):
            self.backup.download(self.item)
        self.assert_attempt_configuration(1)
        self.assertEqual(self.backup.journal.record.call_count, 1)
        self.assertEqual(self.backup.stop.delays, [])

    def test_local_timeout_errors_in_open_fsync_or_progress_never_retry(self):
        actual_open = os.open

        def failing_partial(path, *args, **kwargs):
            if Path(path) == self.partial:
                raise TimeoutError('synthetic local timeout')
            return actual_open(path, *args, **kwargs)

        with mock.patch.object(download.os, 'open', side_effect=failing_partial), self.assertRaises(download.FatalBackupError):
            self.backup.download(self.item)
        self.assert_attempt_configuration(1)
        self.api.get.reset_mock()
        with mock.patch.object(download.os, 'fsync', side_effect=TimeoutError('synthetic local timeout')), \
                self.assertRaises(download.FatalBackupError):
            self.backup.download(self.item)
        self.assert_attempt_configuration(1)
        self.api.get.reset_mock()
        with mock.patch.object(self.backup, '_progress_locked', side_effect=TimeoutError('synthetic status timeout')), \
                self.assertRaises(download.FatalBackupError):
            self.backup.download(self.item)
        self.assertEqual(self.api.get.call_count, 0)
        self.assertEqual(self.backup.stop.delays, [])

    def test_initial_local_metadata_failure_stops_batch_without_recording_unavailable_file(self):
        with mock.patch.object(self.backup, 'local_matches', side_effect=TimeoutError('synthetic local metadata timeout')), \
                mock.patch.object(self.backup, 'record_failure', wraps=self.backup.record_failure) as record, \
                self.assertRaises(download.FatalBackupError):
            self.backup.download_batch([self.item], workers=1)
        self.assertEqual(self.api.get.call_count, 0)
        record.assert_not_called()
        self.assertTrue(self.backup.stop.is_set())

    def test_local_curl_fstat_timeout_is_fatal_not_a_network_retry(self):
        self.backup.curl_download = download.Backup.curl_download.__get__(self.backup)
        process = SimpleNamespace(stdin=io.BytesIO(), stderr=io.BytesIO(), returncode=0,
                                  communicate=mock.Mock(return_value=(None, b'200')), poll=mock.Mock(return_value=0))
        with mock.patch.object(download.subprocess, 'Popen', return_value=process), \
                mock.patch.object(download.os, 'environ', {'SYNTHETIC': 'test'}), \
                mock.patch.object(download.os, 'fstat', side_effect=TimeoutError('synthetic local metadata timeout')), \
                self.assertRaises(download.FatalBackupError):
            self.backup.download(self.item)
        self.assert_attempt_configuration(1)
        self.assertEqual(self.backup.stop.delays, [])

    def test_keyboard_interrupt_and_system_exit_are_never_retried(self):
        for interrupt in (KeyboardInterrupt(), SystemExit(130)):
            with self.subTest(interrupt=type(interrupt).__name__):
                self.api.get.reset_mock()
                self.api.get.side_effect = interrupt
                with self.assertRaises(type(interrupt)):
                    self.backup.download(self.item)
                self.assert_attempt_configuration(1)
                self.assertEqual(self.backup.stop.delays, [])

    def test_cancellation_before_attempt_or_during_backoff_prevents_another_request(self):
        self.backup.stop.set()
        with self.assertRaises(download.FatalBackupError):
            self.backup.download(self.item)
        self.assertEqual(self.api.get.call_count, 0)
        self.backup.stop.stopped = False
        self.backup.stop.cancel_on_wait = True
        self.body_outcomes = [download.CurlFailure(28, None)]
        with self.assertRaises(download.FatalBackupError):
            self.backup.download(self.item)
        self.assert_attempt_configuration(1)
        self.assertEqual(self.backup.stop.delays, [1])

    def test_three_exhausted_attempts_record_one_failed_file_and_remove_active_transfer(self):
        self.backup.failed = {self.item['path']: dict(self.item)}
        self.backup.failed_bytes = self.item['size']
        self.backup.state.update(files_total=1, bytes_total=self.item['size'], files_failed_count=1, bytes_failed=self.item['size'])
        self.api.get.side_effect = download.BackupError('Synthetic link unavailable')
        with mock.patch.object(self.backup, 'record_failure', wraps=self.backup.record_failure) as record:
            self.backup.download_batch([self.item], workers=1)
        self.assert_attempt_configuration(3)
        self.assertEqual(record.call_count, 1)
        self.assertEqual(self.backup.state['files_failed_count'], 1)
        self.assertEqual(self.backup.state['files_pending_count'], 0)
        self.assertEqual(self.backup.transfers, {})
        self.assertEqual(self.backup.state['active_transfers'], {})
        queue = json.loads((self.destination / 'failed-files.json').read_text())
        self.assertEqual(len(queue['files']), 1)


if __name__ == '__main__':
    unittest.main()
