"""Synthetic-only availability checks: never open real accounts or backups."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.error

import availability

REAL_BUILD_OPENER = availability.urllib.request.build_opener


class HeadersResponse:
    def __init__(self, status=200, close_callback=None):
        self.status = status
        self.closed = False
        self.close_callback = close_callback

    def read(self, *args):
        raise AssertionError('File body must never be read')

    read1 = read

    def __iter__(self):
        raise AssertionError('File body must never be iterated')

    def close(self):
        self.closed = True
        if self.close_callback:
            self.close_callback()


class FakeAPI:
    def __init__(self):
        self.token = 'synthetic-token'
        self.calls = []
        self.lock = threading.Lock()
        self.side_effect = None

    def get(self, endpoint, **kwargs):
        with self.lock:
            self.calls.append((endpoint, kwargs))
        if self.side_effect:
            return self.side_effect(endpoint, **kwargs)
        identifier = hashlib.sha256(kwargs['path'].encode()).hexdigest()
        return dict(href=f'https://storage.yandex.net/{identifier}?synthetic=private', method='GET')

    def request_snapshot(self):
        return dict(api_requests_total=len(self.calls), api_rate_limit_rps=20)


class AvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name).resolve()
        self.home = self.root / 'scripts'
        self.home.mkdir()
        self.volume = self.root / 'KINGSTON'
        self.volume.mkdir()
        self.dest = self.volume / 'YandexDisk-backup'
        self.dest.mkdir()
        (self.dest / 'data').mkdir()
        (self.dest / '.partial').mkdir()
        self.items = [dict(path='disk:/synthetic-' + str(i), size=i + 1, md5='a' * 32) for i in range(4)]
        self.save(self.dest / 'manifest.json', dict(files=self.items, directories=[]), 0o700)
        self.save_queue(self.items)
        # These synthetic sentinels must not be opened or altered by the worker.
        for name in ('summary.json', 'verified.sqlite3', 'data/complete', '.partial/unfinished'):
            path = self.dest / name
            path.write_bytes(b'synthetic unchanged sentinel')
            path.chmod(0o700)
        for name in ('progress.json', 'broker.json', 'retry-remaining.json'):
            self.save(self.home / name, dict(sentinel=name))
        self.api = FakeAPI()
        self.responses = []
        self.requests = []
        self.output = io.StringIO()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(availability, 'BASE', self.home))
        self.stack.enter_context(contextlib.redirect_stdout(self.output))
        real_stat = Path.stat
        real_mount = Path.is_mount
        self.mounted = True

        def volume_stat(path, *args, **kwargs):
            value = real_stat(path, *args, **kwargs)
            if path == self.volume:
                values = list(value)
                values[2] += 1
                return os.stat_result(values)
            return value

        def is_mount(path):
            return self.mounted if path == self.volume else real_mount(path)

        self.stack.enter_context(mock.patch.object(Path, 'stat', volume_stat))
        self.stack.enter_context(mock.patch.object(Path, 'is_mount', is_mount))
        self.opener = mock.Mock()
        self.opener.open.side_effect = self.open_headers
        self.stack.enter_context(mock.patch.object(availability.urllib.request, 'build_opener', return_value=self.opener))

    @staticmethod
    def save(path, value, mode=0o600):
        path.write_text(json.dumps(value), encoding='utf-8')
        path.chmod(mode)

    def save_queue(self, items):
        self.save(self.dest / 'failed-files.json', dict(files=items, directories=[],
                  files_failed_count=len(items), bytes_failed=sum(item['size'] for item in items)), 0o700)

    def open_headers(self, request, timeout):
        self.requests.append(request)
        response = HeadersResponse()
        self.responses.append(response)
        return response

    def immutable_snapshot(self):
        selected = list(self.dest.rglob('*')) + [self.home / name for name in ('progress.json', 'broker.json', 'retry-remaining.json')]
        return {str(path): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                for path in selected if path.is_file()}

    def run_worker(self, workers=3, stop=None):
        return availability.run_check(self.api, self.volume, workers, stop)

    def rows(self):
        return [json.loads(line) for line in (self.home / 'availability-results.jsonl').read_text().splitlines()]

    def test_headers_only_success_closes_responses_and_preserves_every_migration_file(self):
        before = self.immutable_snapshot()
        state = self.run_worker()
        self.assertEqual(state['phase'], 'complete')
        self.assertEqual(state['files_checked'], 4)
        self.assertEqual(state['available_headers_only_count'], 4)
        self.assertEqual(state['bytes_checked_metadata'], 10)
        self.assertFalse(state['content_downloaded'])
        self.assertEqual(self.immutable_snapshot(), before)
        self.assertTrue(all(response.closed for response in self.responses))
        self.assertEqual(len(self.rows()), 4)
        self.assertTrue(all('path' not in row and len(row['file_id']) == 64 for row in self.rows()))
        self.assertEqual(len(self.api.calls), 4)
        for endpoint, kwargs in self.api.calls:
            self.assertEqual(endpoint, '/resources/download')
            self.assertEqual(kwargs['_attempts'], 1)
            self.assertEqual(kwargs['_timeout'], 15)
            self.assertIsInstance(kwargs['_stop_event'], threading.Event)
        self.assertTrue(all(request.unredirected_hdrs['Authorization'] == 'OAuth synthetic-token' for request in self.requests))
        self.assertTrue(all(request.get_header('Range') == 'bytes=0-0' for request in self.requests))

    def test_private700_inputs_accepted_but_public_input_refused_without_change(self):
        source = availability.Source(self.volume)
        self.assertEqual(len(source.items), 4)
        (self.dest / 'failed-files.json').chmod(0o744)
        before = self.immutable_snapshot()
        with self.assertRaises(availability.AvailabilityError):
            self.run_worker()
        self.assertEqual(self.immutable_snapshot(), before)

    def test_unsupported_endpoint_is_fatal_and_no_body_request_occurs(self):
        self.api.side_effect = lambda *args, **kwargs: dict(href='http://other.invalid/?signed=SECRET', method='GET')
        state = self.run_worker(workers=1)
        self.assertEqual(state['phase'], 'failed')
        self.assertEqual(state['error_code'], 'unsafe_download_endpoint')
        self.assertEqual(self.opener.open.call_count, 0)
        self.assertEqual(state['files_checked'], 0)

    def test_api_and_header_failures_are_classified_without_leaking_exception_text(self):
        responses = [HeadersResponse(206), urllib.error.HTTPError('https://signed.invalid/?token=SECRET', 404, 'SECRET', {}, None),
                     urllib.error.URLError('https://signed.invalid/?token=SECRET'), HeadersResponse(503)]
        self.opener.open.side_effect = responses
        state = self.run_worker(workers=1)
        self.assertEqual(state['available_headers_only_count'], 1)
        self.assertEqual(state['unavailable_in_check_count'], 1)
        self.assertEqual(state['inconclusive_count'], 2)
        self.assertEqual(state['files_checked'], 4)
        public = self.output.getvalue() + ''.join((self.home / name).read_text() for name in
                  ('availability-results.jsonl', 'availability-progress.json', 'availability-summary.json'))
        self.assertNotIn('SECRET', public)
        self.assertNotIn('https://', public)
        self.assertNotIn('synthetic-token', public)
        self.assertNotIn('disk:/', public)
        self.assertTrue(responses[0].closed)
        self.assertTrue(responses[3].closed)

    def test_header_401_closes_response_and_stops_as_authentication_failure(self):
        response = HeadersResponse(401)
        self.opener.open.side_effect = None
        self.opener.open.return_value = response
        state = self.run_worker(workers=1)
        self.assertEqual(state['phase'], 'failed')
        self.assertEqual(state['error_code'], 'authentication_failed_http401')
        self.assertTrue(response.closed)
        self.assertEqual(len(self.api.calls), 1)

    def test_api_401_fatal_stops_once_with_safe_reason(self):
        def fail(*args, **kwargs):
            raise availability.FatalBackupError('SECRET https://signed.invalid')

        self.api.side_effect = fail
        state = self.run_worker(workers=1)
        self.assertEqual(state['phase'], 'failed')
        self.assertEqual(state['error_code'], 'api_authentication_or_safety_failure')
        self.assertEqual(len(self.api.calls), 1)
        self.assertEqual(self.opener.open.call_count, 0)
        self.assertNotIn('SECRET', self.output.getvalue())

    def test_api_permission_failure_is_unavailable_not_retried(self):
        def fail(*args, **kwargs):
            raise availability.HTTPFailure(403)

        self.api.side_effect = fail
        state = self.run_worker(workers=1)
        self.assertEqual(state['phase'], 'complete')
        self.assertEqual(state['unavailable_in_check_count'], 4)
        self.assertEqual(len(self.api.calls), 4)
        self.assertEqual(self.opener.open.call_count, 0)

    def test_api_nonfatal_failure_is_checked_once_and_recorded_inconclusive(self):
        def fail(*args, **kwargs):
            raise availability.BackupError('synthetic temporary failure')

        self.api.side_effect = fail
        state = self.run_worker(workers=2)
        self.assertEqual(state['phase'], 'complete')
        self.assertEqual(state['inconclusive_count'], 4)
        self.assertEqual(len(self.api.calls), 4)
        self.assertEqual(self.opener.open.call_count, 0)

    def test_active_work_is_bounded_and_all_calls_share_one_api_budget(self):
        self.items = [dict(path='disk:/synthetic-' + str(i), size=i + 1, md5='a' * 32) for i in range(11)]
        self.save(self.dest / 'manifest.json', dict(files=self.items, directories=[]), 0o700)
        self.save_queue(self.items)
        lock, barrier = threading.Lock(), threading.Barrier(3)
        active = peak = started = 0

        def opening(request, timeout):
            nonlocal active, peak, started
            with lock:
                active += 1
                started += 1
                number = started
                peak = max(peak, active)
            if number <= 3:
                barrier.wait(timeout=2)
            time.sleep(0.002)

            def closing():
                nonlocal active
                with lock:
                    active -= 1

            return HeadersResponse(close_callback=closing)

        self.opener.open.side_effect = opening
        state = self.run_worker(workers=3)
        self.assertEqual(state['phase'], 'complete')
        self.assertEqual(state['files_checked'], 11)
        self.assertEqual(peak, 3)
        self.assertEqual(active, 0)
        self.assertEqual(len(self.api.calls), 11)
        self.assertEqual(state['api_rate_limit_rps'], 20)

    def test_changed_queue_aborts_before_claiming_a_current_complete_snapshot(self):
        def opening(request, timeout):
            self.save_queue(self.items[:-1])
            return HeadersResponse()

        self.opener.open.side_effect = opening
        state = self.run_worker(workers=1)
        self.assertEqual(state['phase'], 'failed')
        self.assertEqual(state['error_code'], 'input_metadata_changed')
        self.assertTrue(state['source_changed'])

    def test_mount_disconnection_aborts_safely(self):
        def link(*args, **kwargs):
            self.mounted = False
            return dict(href='https://storage.yandex.net/synthetic', method='GET')

        self.api.side_effect = link
        state = self.run_worker(workers=1)
        self.assertEqual(state['phase'], 'failed')
        self.assertEqual(state['error_code'], 'external_volume_disconnected_or_changed')
        self.assertTrue(state['source_changed'])
        self.assertEqual(self.opener.open.call_count, 0)

    def test_cancelled_check_writes_partial_summary_without_touching_migration(self):
        before = self.immutable_snapshot()
        stop = threading.Event()
        stop.set()
        state = self.run_worker(stop=stop)
        self.assertEqual(state['phase'], 'interrupted')
        self.assertEqual(state['files_checked'], 0)
        self.assertEqual(state['files_remaining'], 4)
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.immutable_snapshot(), before)
        self.assertEqual(json.loads((self.home / 'availability-summary.json').read_text())['phase'], 'interrupted')

    def test_zero_size_file_does_not_send_unsatisfiable_range(self):
        item = dict(path='disk:/empty', size=0, md5=hashlib.md5(b'').hexdigest())
        self.save(self.dest / 'manifest.json', dict(files=[item], directories=[]), 0o700)
        self.save_queue([item])
        self.assertEqual(self.run_worker()['files_checked'], 1)
        self.assertIsNone(self.requests[0].get_header('Range'))

    def test_second_run_is_fresh_instead_of_accumulating_old_results(self):
        first = self.run_worker()
        second = self.run_worker()
        self.assertEqual(first['queue_hash'], second['queue_hash'])
        self.assertEqual(len(self.rows()), 4)
        self.assertEqual(len(self.api.calls), 8)

    def test_symlink_reports_are_refused_without_overwriting_target(self):
        other = self.root / 'must-remain'
        other.write_bytes(b'synthetic sentinel')
        (self.home / 'availability-results.jsonl').symlink_to(other)
        with self.assertRaises((availability.AvailabilityError, availability.BackupError)):
            self.run_worker()
        self.assertEqual(other.read_bytes(), b'synthetic sentinel')

    def test_real_urllib_redirect_pipeline_never_reads_redirect_body_or_forwards_oauth(self):
        responses, requests = [], []

        class HTTPSHandler(availability.urllib.request.HTTPSHandler):
            def https_open(self, request):
                requests.append(request)
                response = HeadersResponse(302 if len(requests) == 1 else 206)
                response.code = response.status
                response.msg = 'synthetic'
                response.headers = {'Location': 'https://mds.yandex.net/next'} if response.status == 302 else {}
                response.info = lambda: response.headers
                response.getcode = lambda: response.status
                response.geturl = lambda: request.full_url
                responses.append(response)
                return response

        opener = REAL_BUILD_OPENER(availability.NoRedirect(), HTTPSHandler())
        request = availability.urllib.request.Request('https://storage.yandex.net/synthetic')
        request.add_unredirected_header('Authorization', 'OAuth synthetic-token')
        request.add_header('Range', 'bytes=0-0')
        response = availability.open_headers(opener, request, threading.Event())
        response.close()
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(item.closed for item in responses))
        self.assertEqual(requests[0].unredirected_hdrs['Authorization'], 'OAuth synthetic-token')
        self.assertIsNone(requests[1].get_header('Authorization'))
        self.assertEqual(requests[1].get_header('Range'), 'bytes=0-0')

    def test_redirect_limits_https_and_control_characters_close_without_body_reads(self):
        for location in ('http://other.invalid/file', 'https://other.invalid/\nSECRET'):
            response = HeadersResponse(302)
            response.headers = {'Location': location}
            opener = mock.Mock(open=mock.Mock(return_value=response))
            request = availability.urllib.request.Request('https://storage.yandex.net/synthetic')
            with self.subTest(location=location), self.assertRaises(availability.AvailabilityError):
                availability.open_headers(opener, request, threading.Event())
            self.assertTrue(response.closed)
        response = HeadersResponse(302)
        response.headers = {'Location': '/same'}
        opener = mock.Mock(open=mock.Mock(return_value=response))
        with self.assertRaisesRegex(availability.AvailabilityError, 'redirect_limit_exceeded'):
            availability.open_headers(opener, request, threading.Event())
        self.assertEqual(opener.open.call_count, 11)
        self.assertTrue(response.closed)


if __name__ == '__main__':
    unittest.main()
