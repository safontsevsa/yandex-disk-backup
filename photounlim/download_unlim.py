#!/usr/bin/env python3
"""Download originals from Yandex Disk photounlim through the saved browser session.

Only originals are published, and only when the received size matches the listing.
Existing files with the expected size are skipped, so the script can be rerun.
Failed files are kept in failed.json for a later pass. No previews are saved.
URLs, cookies and upstream error messages are never printed.
"""
import argparse
import concurrent.futures
import fcntl
import json
import os
from pathlib import Path
import sys
import threading
import time
from datetime import datetime
from urllib.error import HTTPError

HERE = Path(__file__).resolve().parent
TRIAL = HERE.parent / 'experiments' / 'ydisksaver-20-20261016'
sys.path.insert(0, str(TRIAL))
sys.path.insert(0, str(HERE.parent))
import run_trial  # noqa: E402  (applies the Yandex 360 adapter to the pinned vendor code)

DEST = Path('/Volumes/KINGSTON/YandexDisk-photounlim')
STATE = TRIAL / 'browser-session.json'


def stamp():
    return datetime.now().astimezone().isoformat(timespec='seconds')


def atomic_json(path, value):
    tmp = path.with_name(path.name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


class SessionExpired(Exception):
    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--attempts', type=int, default=2)
    parser.add_argument('--socket-timeout', type=float, default=30)
    parser.add_argument('--only-failed', action='store_true', help='retry only files from failed.json')
    args = parser.parse_args()

    os.umask(0o077)
    if not DEST.parent.is_mount():
        raise SystemExit('KINGSTON is not mounted')
    data = DEST / 'data'
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = open(HERE / 'download.lock', 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    ys = run_trial.load_vendor()
    files = json.load(open(HERE / 'inventory.json'))['files']
    if args.only_failed and (HERE / 'failed.json').exists():
        wanted = set(json.load(open(HERE / 'failed.json'))['paths'])
        files = [f for f in files if f['path'] in wanted]

    def done(f):
        p = data / ys.safe_name(f['name'])
        return p.is_file() and p.stat().st_size == f['size']

    queue = [f for f in files if not done(f)]
    total = {'files': len(files), 'bytes': sum(f['size'] for f in files)}
    stats = {'verified': len(files) - len(queue), 'verified_bytes': total['bytes'] - sum(f['size'] for f in queue),
             'downloaded_now': 0, 'downloaded_now_bytes': 0, 'failed': 0}
    failed, lock_stats, local, stop = [], threading.Lock(), threading.local(), threading.Event()
    started = time.monotonic()

    def progress(phase):
        elapsed = time.monotonic() - started
        atomic_json(HERE / 'progress.json', {
            'phase': phase, 'updated_at': stamp(), 'workers': args.workers,
            'files_total': total['files'], 'bytes_total': total['bytes'],
            **stats, 'queue_at_start': len(queue), 'elapsed_seconds': round(elapsed),
            'MB_per_second_now': round(stats['downloaded_now_bytes'] / max(elapsed, 1) / 1e6, 2)})

    def client():
        if not hasattr(local, 'c'):
            try:
                local.c = ys.DiskWeb(STATE, '/photounlim', args.socket_timeout)
            except (HTTPError, RuntimeError) as e:
                raise SessionExpired(type(e).__name__)
        return local.c

    def fetch(f):
        if stop.is_set():
            return 'stopped'
        target = data / ys.safe_name(f['name'])
        for attempt in range(args.attempts):
            try:
                c = client()
                url = c.download_url(f['path'])
                with c.open_download(url) as response:
                    status = ys.save_stream(response, target, DEST, f['size'],
                                            time.monotonic() + max(600, f['size'] / 200_000))
                if status in ('downloaded', 'skipped') and done(f):
                    t = f.get('etime') or f.get('mtime')
                    if isinstance(t, int):
                        os.utime(target, (t, t))
                    return 'ok'
            except SessionExpired:
                stop.set()
                return 'session_expired'
            except HTTPError as e:
                if e.code in (401, 403):
                    try:
                        local.c.refresh_session()
                    except Exception:
                        stop.set()
                        return 'session_expired'
            except Exception:
                pass
            if attempt + 1 < args.attempts:
                time.sleep(2)
        return 'failed'

    progress('downloading')
    last = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        jobs = {pool.submit(fetch, f): f for f in queue}
        for job in concurrent.futures.as_completed(jobs):
            f, result = jobs[job], job.result()
            with lock_stats:
                if result == 'ok':
                    stats['verified'] += 1
                    stats['verified_bytes'] += f['size']
                    stats['downloaded_now'] += 1
                    stats['downloaded_now_bytes'] += f['size']
                else:
                    stats['failed'] += 1
                    failed.append(f['path'])
            if time.monotonic() - last > 5:
                progress('downloading')
                last = time.monotonic()
    atomic_json(HERE / 'failed.json', {'updated_at': stamp(), 'paths': failed,
                                       'bytes': sum(f['size'] for f in files if f['path'] in set(failed))})
    phase = 'session_expired' if stop.is_set() else ('complete' if not failed else 'complete_with_errors')
    progress(phase)
    print(json.dumps({'phase': phase, **stats}, ensure_ascii=False))


if __name__ == '__main__':
    main()
