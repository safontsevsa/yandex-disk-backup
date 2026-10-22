#!/usr/bin/env python3
"""Check saved failure-queue response headers without downloading file contents."""
import argparse
import concurrent.futures
from datetime import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import ssl
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from zoneinfo import ZoneInfo

from download import (BackupError, DiskAPI, FatalBackupError, HTTPFailure, NoRedirect,
                      atomic_json, canonical_inventory, check_tree, read_private_inventory)


BASE = Path(__file__).resolve().parent
NETWORK_ERRORS = (urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException, ssl.SSLError)


class AvailabilityError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class CancelledCheck(Exception):
    pass


def timestamp():
    return datetime.now(ZoneInfo('Europe/Moscow')).isoformat(timespec='seconds')


def private_fd(path, flags):
    check_tree(path)
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise AvailabilityError('unsafe_report_or_lock')
        return fd
    except BaseException:
        os.close(fd)
        raise


def save_json(name, value):
    path = BASE / name
    check_tree(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise AvailabilityError('unsafe_report_or_lock')
    atomic_json(path, value)


def file_identity(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise AvailabilityError('unsafe_input_metadata')
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


class Source:
    def __init__(self, volume):
        self.volume = volume.absolute()
        check_tree(self.volume)
        if not self.volume.is_mount() or self.volume.stat().st_dev == Path('/').stat().st_dev:
            raise AvailabilityError('external_volume_not_mounted')
        self.device = self.volume.stat().st_dev
        destination = self.volume / 'YandexDisk-backup'
        self.paths = (destination / 'manifest.json', destination / 'failed-files.json')
        self.identities = tuple(file_identity(path) for path in self.paths)
        manifest = canonical_inventory(read_private_inventory(self.paths[0]))
        raw = read_private_inventory(self.paths[1])
        failures = canonical_inventory(raw)
        known = {item['path']: item for item in manifest['files']}
        for item in failures['files']:
            original = known.get(item['path'])
            if original is None or any(original.get(key) != item.get(key) for key in ('size', 'md5')):
                raise AvailabilityError('queue_does_not_match_manifest')
        self.items = failures['files']
        self.bytes_total = sum(item['size'] for item in self.items)
        if (type(raw.get('files_failed_count')) is not int or type(raw.get('bytes_failed')) is not int
                or raw['files_failed_count'] != len(self.items) or raw['bytes_failed'] != self.bytes_total
                or len(raw['files']) != len(self.items)):
            raise AvailabilityError('queue_totals_not_consistent')
        encoded = json.dumps(self.items, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        self.queue_hash = hashlib.sha256(encoded).hexdigest()
        self.check()

    def check(self):
        try:
            if not self.volume.is_mount() or self.volume.stat().st_dev != self.device:
                raise AvailabilityError('external_volume_disconnected_or_changed')
            if tuple(file_identity(path) for path in self.paths) != self.identities:
                raise AvailabilityError('input_metadata_changed')
        except OSError:
            raise AvailabilityError('input_metadata_unavailable') from None


def safe_type(exc):
    for kind in (urllib.error.HTTPError, HTTPFailure, FatalBackupError, BackupError,
                 urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError, http.client.HTTPException):
        if isinstance(exc, kind):
            return kind.__name__
    return 'UnexpectedError'


def http_result(stage, code):
    if code == 401:
        raise AvailabilityError('authentication_failed_http401')
    if stage == 'response_headers' and code in (200, 206):
        category = 'available_headers_only'
    elif 400 <= code < 500 and code not in (408, 425, 429):
        category = 'unavailable_in_check'
    else:
        category = 'inconclusive'
    return dict(category=category, stage=stage, http_code=code)


def open_headers(opener, request, stop):
    """Follow HTTPS redirects manually; urllib's normal handler reads their bodies."""
    range_header = request.get_header('Range')
    for hop in range(11):
        if stop.is_set():
            raise CancelledCheck()
        try:
            response = opener.open(request, timeout=15)
        except urllib.error.HTTPError as exc:
            response = exc
        try:
            code = getattr(response, 'status', None)
            if code is None:
                code = response.getcode()
        except BaseException:
            response.close()
            raise
        if code not in (301, 302, 303, 307, 308):
            return response
        try:
            location = response.headers.get('Location')
        finally:
            response.close()
        if hop == 10:
            raise AvailabilityError('redirect_limit_exceeded')
        if not isinstance(location, str) or not location or any(ord(char) <= 32 or ord(char) == 127 for char in location):
            raise AvailabilityError('unsafe_response_redirect')
        try:
            target = urllib.parse.urljoin(request.full_url, location)
            parsed = urllib.parse.urlsplit(target)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError()
            parsed.port  # Validate malformed ports without printing the URL.
        except (TypeError, ValueError):
            raise AvailabilityError('unsafe_response_redirect') from None
        request = urllib.request.Request(target, method='GET')
        # Never forward Authorization or any other original header on redirects.
        if range_header:
            request.add_header('Range', range_header)


def probe_one(item, source, api, stop):
    if stop.is_set():
        raise CancelledCheck()
    source.check()
    base = dict(file_id=hashlib.sha256(item['path'].encode('utf-8')).hexdigest(), size=item['size'])
    try:
        try:
            link = api.get('/resources/download', _attempts=1, _timeout=15, _stop_event=stop, path=item['path'])
        except FatalBackupError:
            raise AvailabilityError('api_authentication_or_safety_failure') from None
        except HTTPFailure as exc:
            return dict(base, checked_at=timestamp(), **http_result('api_link', exc.http_code))
        except urllib.error.HTTPError as exc:
            try:
                return dict(base, checked_at=timestamp(), **http_result('api_link', exc.code))
            finally:
                exc.close()
        except (BackupError, *NETWORK_ERRORS) as exc:
            if stop.is_set():
                raise CancelledCheck() from None
            return dict(base, checked_at=timestamp(), category='inconclusive', stage='api_link', error_type=safe_type(exc))
        if stop.is_set():
            raise CancelledCheck()
        source.check()
        if not isinstance(link, dict) or not isinstance(link.get('href'), str) or link.get('method') != 'GET':
            raise AvailabilityError('unsafe_download_endpoint')
        try:
            parsed = urllib.parse.urlsplit(link['href'])
            host = parsed.hostname or ''
        except ValueError:
            raise AvailabilityError('unsafe_download_endpoint') from None
        if parsed.scheme != 'https' or not any(host == domain or host.endswith('.' + domain)
                                               for domain in ('yandex.net', 'yandex.ru', 'yandex.com')):
            raise AvailabilityError('unsafe_download_endpoint')
        request = urllib.request.Request(link['href'], method='GET')
        request.add_unredirected_header('Authorization', 'OAuth ' + api.token)
        if item['size']:
            request.add_header('Range', 'bytes=0-0')
        opener = urllib.request.build_opener(NoRedirect())
        try:
            response = open_headers(opener, request, stop)
            try:
                code = getattr(response, 'status', None)
                if code is None:
                    code = response.getcode()
                if type(code) is not int or not 100 <= code <= 599:
                    return dict(base, checked_at=timestamp(), category='inconclusive',
                                stage='response_headers', error_type='InvalidHTTPStatus')
                result = http_result('response_headers', code)
            finally:
                response.close()  # Deliberately never call read(), read1() or iterate the body.
            source.check()
            return dict(base, checked_at=timestamp(), **result)
        except urllib.error.HTTPError as exc:
            try:
                return dict(base, checked_at=timestamp(), **http_result('response_headers', exc.code))
            finally:
                exc.close()
        except FatalBackupError:
            raise AvailabilityError('unsafe_response_redirect') from None
        except NETWORK_ERRORS as exc:
            if stop.is_set():
                raise CancelledCheck() from None
            return dict(base, checked_at=timestamp(), category='inconclusive',
                        stage='response_headers', error_type=safe_type(exc))
    except OSError:
        raise AvailabilityError('local_input_or_report_io_failure') from None


def run_check(api, volume, workers=128, stop=None):
    if type(workers) is not int or not 1 <= workers <= 128:
        raise AvailabilityError('invalid_workers')
    stop = stop if stop is not None else threading.Event()
    fd = private_fd(BASE / 'availability.lock', os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, 'r+') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        source = Source(volume)
        state = dict(version=1, phase='checking_availability', started_at=timestamp(), queue_hash=source.queue_hash,
                     workers=workers, files_total=len(source.items), bytes_total_metadata=source.bytes_total,
                     files_checked=0, bytes_checked_metadata=0, files_remaining=len(source.items),
                     available_headers_only_count=0, unavailable_in_check_count=0, inconclusive_count=0,
                     content_downloaded=False, source_changed=False)
        result_fd = private_fd(BASE / 'availability-results.jsonl', os.O_WRONLY | os.O_CREAT)
        os.ftruncate(result_fd, 0)
        last_save, last_print, saved_count = 0.0, 0.0, 0

        def publish(force=False):
            nonlocal last_save, last_print, saved_count
            now = time.monotonic()
            if not force and now - last_save < 1 and state['files_checked'] - saved_count < 50:
                return
            state['updated_at'] = timestamp()
            snapshot = getattr(api, 'request_snapshot', None)
            if callable(snapshot):
                counters = snapshot()
                for key in ('api_requests_total', 'api_http_429_count', 'api_rate_limit_rps'):
                    value = counters.get(key)
                    if type(value) is int and value >= 0:
                        state[key] = value
                errors = counters.get('api_http_error_counts')
                if isinstance(errors, dict):
                    state['api_http_error_counts'] = {key: value for key, value in errors.items()
                        if isinstance(key, str) and len(key) == 3 and key.isascii() and key.isdigit()
                        and type(value) is int and value >= 0}
            save_json('availability-progress.json', state)
            last_save, saved_count = now, state['files_checked']
            if force or now - last_print >= 10:
                print(json.dumps(state, ensure_ascii=False), flush=True)
                last_print = now

        def record(stream, result):
            stream.write(json.dumps(dict(queue_hash=source.queue_hash, **result), ensure_ascii=False) + '\n')
            stream.flush()
            state['files_checked'] += 1
            state['bytes_checked_metadata'] += result['size']
            state['files_remaining'] -= 1
            state[result['category'] + '_count'] += 1
            publish()

        iterator = iter(source.items)
        pending = {}
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        with os.fdopen(result_fd, 'w', encoding='utf-8') as results:
            try:
                publish(force=True)

                def fill():
                    while len(pending) < workers and not stop.is_set():
                        try:
                            item = next(iterator)
                        except StopIteration:
                            return
                        source.check()
                        pending[pool.submit(probe_one, item, source, api, stop)] = item

                fill()
                while pending:
                    done, _ = concurrent.futures.wait(tuple(pending), timeout=0.5,
                                                     return_when=concurrent.futures.FIRST_COMPLETED)
                    for future in done:
                        pending.pop(future)
                        try:
                            record(results, future.result())
                        except CancelledCheck:
                            pass
                    if stop.is_set():
                        break
                    fill()
                source.check()
                state['phase'] = 'interrupted' if stop.is_set() else 'complete'
            except KeyboardInterrupt:
                state['phase'] = 'interrupted'
                stop.set()
            except Exception as exc:
                state['phase'] = 'failed'
                state['error_code'] = exc.code if isinstance(exc, AvailabilityError) else 'unexpected_check_failure'
                state['source_changed'] = state['error_code'] in (
                    'external_volume_disconnected_or_changed', 'input_metadata_changed', 'input_metadata_unavailable')
                stop.set()
            finally:
                for future in pending:
                    future.cancel()
                pool.shutdown(wait=True, cancel_futures=True)
                # Retain completed headers checks even if a different task failed or was interrupted.
                for future in pending:
                    if future.cancelled():
                        continue
                    try:
                        record(results, future.result())
                    except CancelledCheck:
                        pass
                    except Exception:
                        pass
                results.flush()
                os.fsync(results.fileno())
                state['finished_at'] = timestamp()
                publish(force=True)
                save_json('availability-summary.json', state)
        return state


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volume', type=Path, default=Path('/Volumes/KINGSTON'))
    parser.add_argument('--workers', type=int, choices=range(1, 129), default=128)
    args = parser.parse_args(argv)
    os.umask(0o077)
    token = os.environ.get('YANDEX_DISK_TOKEN', '').strip()
    if not token:
        raise AvailabilityError('authorization_required')

    def interrupted(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, interrupted)
    result = run_check(DiskAPI(token), args.volume, args.workers)
    return 0 if result['phase'] == 'complete' else (130 if result['phase'] == 'interrupted' else 1)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(json.dumps(dict(phase='interrupted')), flush=True)
        raise SystemExit(130) from None
    except Exception as exc:
        print(json.dumps(dict(phase='failed', error_code=exc.code if isinstance(exc, AvailabilityError)
                              else 'availability_check_failed')), flush=True)
        raise SystemExit(1) from None
