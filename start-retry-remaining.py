#!/usr/bin/env python3
"""Retry saved failures after completion, or use --resume-paused to continue a pause."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import shlex
import stat
import subprocess
import sys
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from download import DOWNLOAD_ATTEMPTS, atomic_json, canonical_inventory, read_private_inventory, selected_workers
from target_config import arguments_match_target, read_target

BASE = Path(__file__).resolve().parent
VOLUME = Path('/Volumes/ADATA')
DEST = VOLUME / 'YandexDisk-backup'
STATUS = BASE / 'retry-remaining.json'


def configure_target():
    global VOLUME, DEST
    if os.path.lexists(BASE / 'target.json'):
        VOLUME = read_target(BASE / 'target.json')['volume']
        DEST = VOLUME / 'YandexDisk-backup'


def publish(status, **fields):
    record = dict(status=status, coordinator_pid=os.getpid(), updated_at=datetime.now(ZoneInfo('Europe/Moscow')).isoformat(timespec='seconds'), **fields)
    atomic_json(STATUS, record)
    print(json.dumps(record, ensure_ascii=False), flush=True)


def read_state(name):
    return read_private_inventory(BASE / name)


def owned_broker(pid):
    if type(pid) is not int or pid <= 1:
        return False
    result = subprocess.run(['/bin/ps', '-ww', '-p', str(pid), '-o', 'uid=', '-o', 'command='], capture_output=True, text=True)
    fields = result.stdout.strip().split(None, 1)
    if result.returncode or len(fields) != 2 or fields[0] != str(os.getuid()):
        return False
    try:
        command = shlex.split(fields[1])
    except ValueError:
        return False
    if command[:2] == ['/usr/bin/caffeinate', '-im']:
        command = command[2:]
    if not command:
        return False
    executable = Path(command[0]).name
    if executable not in ('Python', 'python', 'python3') and not (
            executable.startswith('python3.') and executable[8:].isdigit()):
        return False
    arguments = command[1:]
    while arguments:
        if arguments[0] in ('-u', '-B', '-E', '-I', '-s', '-S', '-Xutf8'):
            arguments = arguments[1:]
        elif arguments[:2] == ['-X', 'utf8']:
            arguments = arguments[2:]
        else:
            break
    return bool(arguments and arguments[0] == str(BASE / 'authorize.py')
                and arguments_match_target(arguments, BASE / 'target.json'))


def private_lock(path, *, create=False, readonly=False):
    flags = (os.O_RDONLY if readonly else os.O_RDWR) | os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError('unsafe_lock_file')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return os.fdopen(fd, 'r' if readonly else 'r+')
    except BaseException:
        os.close(fd)
        raise


def marker_exists(name):
    return os.path.lexists(BASE / name)


def nonnegative(value):
    return type(value) is int and value >= 0


def paused_state(progress, broker):
    if (broker.get('status') != 'failed_waiting_retry' or broker.get('return_code') != 130
            or broker.get('child_pid') is not None or progress.get('phase') != 'paused'
            or progress.get('retry_only_failed') is not True):
        raise RuntimeError('backup_is_not_a_paused_failure_retry')


def validate_plan(progress, *, resume_paused=False):
    if not VOLUME.is_mount() or VOLUME.stat().st_dev == Path('/').stat().st_dev:
        raise RuntimeError('external_volume_not_mounted')
    summary = read_private_inventory(DEST / 'summary.json')
    inventory = canonical_inventory(read_private_inventory(DEST / 'manifest.json'))
    failure_record = read_private_inventory(DEST / 'failed-files.json')
    failures = canonical_inventory(failure_record)
    count = len(inventory['files'])
    size = sum(item['size'] for item in inventory['files'])
    attempted_count = summary.get('inventory_files_attempted')
    attempted_size = summary.get('inventory_bytes_attempted')
    if attempted_count is None and not summary.get('retry_only_failed'):
        totals = [summary.get(key) for key in ('files_verified', 'files_failed_count', 'bytes_verified', 'bytes_failed')]
        if all(nonnegative(value) for value in totals):
            attempted_count, attempted_size = totals[0] + totals[1], totals[2] + totals[3]
    if (summary.get('phase') != 'complete_with_errors' or summary.get('inventory_verified') is not True
            or summary.get('source_changed') is not False or attempted_count != count or attempted_size != size):
        raise RuntimeError('completed_summary_not_consistent')
    known = {item['path']: item for item in inventory['files']}
    for item in failures['files']:
        original = known.get(item['path'])
        if original is None or any(original.get(key) != item.get(key) for key in ('size', 'md5')):
            raise RuntimeError('failure_queue_not_consistent')
    failed_count = len(failures['files'])
    failed_bytes = sum(item['size'] for item in failures['files'])
    if (not failed_count or failure_record.get('files_failed_count') != failed_count
            or failure_record.get('bytes_failed') != failed_bytes):
        raise RuntimeError('failure_totals_not_consistent')
    if resume_paused:
        previous = read_state('retry-remaining.json').get('previous_verified', {})
        if not isinstance(previous, dict):
            raise RuntimeError('paused_baseline_not_consistent')
        keys = ('files_verified', 'bytes_verified', 'files_total', 'bytes_total')
        progress_keys = (*keys, 'files_failed_count', 'bytes_failed')
        if (not all(nonnegative(previous.get(key)) for key in keys)
                or not all(nonnegative(progress.get(key)) for key in progress_keys)
                or previous['files_total'] != count or previous['bytes_total'] != size
                or previous['files_verified'] + progress['files_total'] != count
                or previous['bytes_verified'] + progress['bytes_total'] != size
                or progress['files_verified'] + failed_count != progress['files_total']
                or progress['bytes_verified'] + failed_bytes != progress['bytes_total']
                or progress['files_failed_count'] != failed_count or progress['bytes_failed'] != failed_bytes):
            raise RuntimeError('paused_baseline_not_consistent')
    elif failed_count != summary.get('files_failed_count') or failed_bytes != summary.get('bytes_failed'):
        raise RuntimeError('failure_totals_not_consistent')
    if shutil.disk_usage(VOLUME).free < failed_bytes + 256 * 1024 * 1024:
        raise RuntimeError('insufficient_external_space')
    previous = dict(files_verified=count-failed_count, bytes_verified=size-failed_bytes,
                    files_total=count, bytes_total=size)
    queue = dict(files_total=failed_count, bytes_total=failed_bytes)
    return previous, queue


def startup_acknowledged(progress, broker, broker_pid, old_child_pid, old_progress_at, queue):
    child = broker.get('child_pid')
    return (broker.get('broker_pid') == broker_pid and broker.get('status') == 'running'
            and type(child) is int and child > 1 and child != old_child_pid
            and isinstance(progress.get('updated_at'), str) and progress['updated_at'] != old_progress_at
            and progress.get('phase') not in ('paused', 'failed') and progress.get('retry_only_failed') is True
            and progress.get('download_attempts_max') == DOWNLOAD_ATTEMPTS
            and progress.get('files_total') == queue['files_total']
            and progress.get('bytes_total') == queue['bytes_total'])


def startup_failed(progress, broker, initial_broker, old_progress_at, mode_read, trigger_pending):
    # The broker consumes the trigger before publishing its newly started child.
    # During that interval the old return code 130 still means the original pause.
    # The child can write its first progress before the broker publishes running.
    # A new progress timestamp alone therefore cannot prove a failed new child.
    changed = broker != initial_broker or mode_read
    return (changed and broker.get('status') == 'failed_waiting_retry'
            and broker.get('return_code') != 2 and (mode_read or not trigger_pending))


def report_failure(exc, *, check=False, resume_paused=False):
    error = dict(status='not_started_or_requires_attention', error_type=type(exc).__name__)
    if check or resume_paused:
        # A validation failure must retain the previous pause/checkpoint metadata.
        print(json.dumps(error), flush=True)
    else:
        publish(error.pop('status'), **error)


def marker(name):
    path = BASE / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write('authorized one-time retry\n')
        info = os.fstat(stream.fileno())
    return path, (info.st_dev, info.st_ino)


def remove_own_marker(value):
    if value is None:
        return
    path, identity = value
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == identity:
        path.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Start one saved failure-queue retry with 128 download workers.')
    parser.add_argument('--resume-paused', action='store_true', help='Continue the manually paused saved failure queue.')
    parser.add_argument('--check', action='store_true', help='Validate --resume-paused without starting or changing state.')
    args = parser.parse_args(argv)
    configure_target()
    if args.check and not args.resume_paused:
        parser.error('--check requires --resume-paused')
    os.umask(0o077)
    with private_lock(BASE / 'retry-remaining.lock', create=not args.check, readonly=args.check):
        initial = read_state('broker.json')
        broker_pid = initial.get('broker_pid')
        child_pid = initial.get('child_pid')
        if not owned_broker(broker_pid):
            raise RuntimeError('broker_not_owned_or_alive')
        if selected_workers() != 128:
            raise RuntimeError('workers_not_128')
        deadline = time.monotonic() + 7200
        last_progress_at = None
        if not args.resume_paused:
            publish('waiting_for_current_verification', workers=128)
        while True:
            p, b = read_state('progress.json'), read_state('broker.json')
            if b.get('broker_pid') != broker_pid or not owned_broker(broker_pid):
                raise RuntimeError('broker_changed_or_stopped')
            if args.resume_paused:
                paused_state(p, b)
                if os.path.lexists(BASE / 'target.json') and p.get('destination') != str(DEST):
                    raise RuntimeError('paused_destination_does_not_match_target')
                break
            if b.get('status') == 'failed_waiting_retry':
                if b.get('return_code') != 2 or p.get('phase') != 'complete_with_errors':
                    raise RuntimeError('current_backup_did_not_complete_partial')
                break
            if b.get('status') != 'running':
                raise RuntimeError('current_backup_not_running_or_waiting')
            # A healthy large directory scan may take more than two hours.
            # Limit inactivity, rather than canceling an advancing scan.
            current_progress_at = p.get('updated_at')
            if current_progress_at != last_progress_at:
                deadline = time.monotonic() + 7200
                last_progress_at = current_progress_at
            if time.monotonic() >= deadline:
                raise RuntimeError('verification_progress_timeout')
            time.sleep(5)

        mode = trigger = None
        with private_lock(BASE / 'download.lock', readonly=args.check):
            b = read_state('broker.json')
            p = read_state('progress.json')
            if args.resume_paused:
                paused_state(p, b)
            expected_code = 130 if args.resume_paused else 2
            if (b.get('status') != 'failed_waiting_retry' or b.get('return_code') != expected_code
                    or b.get('broker_pid') != broker_pid or not owned_broker(broker_pid)):
                raise RuntimeError('broker_changed_before_retry')
            if selected_workers() != 128 or any(marker_exists(name) for name in ('retry-download', 'retry-only-failed', 'use-inventory-cache')):
                raise RuntimeError('configuration_or_pending_marker_changed')
            previous, queue = validate_plan(p, resume_paused=args.resume_paused)
            failed_count, failed_bytes = queue['files_total'], queue['bytes_total']
            old_progress_at = p.get('updated_at')
            handoff_broker = dict(b)
            # Validation can take a moment on an external volume; refuse a changed handoff.
            if read_state('broker.json') != b or read_state('progress.json') != p:
                raise RuntimeError('state_changed_during_validation')
            if args.check:
                print(json.dumps(dict(status='paused_retry_ready', workers=128,
                                      previous_verified=previous, retry_queue=queue), ensure_ascii=False), flush=True)
                return
            mode = marker('retry-only-failed')
        mode_read = False
        try:
            publish('starting_saved_failure_retry', workers=128, previous_verified=previous, retry_queue=queue)
            trigger = marker('retry-download')
            startup_deadline = time.monotonic() + 180
            while time.monotonic() < startup_deadline:
                p, b = read_state('progress.json'), read_state('broker.json')
                if startup_acknowledged(p, b, broker_pid, child_pid, old_progress_at, queue):
                    mode_read = True
                    remove_own_marker(mode)
                    if p.get('phase') in ('downloading', 'downloading_missing') and p.get('workers') == 128:
                        if p['files_total'] != failed_count or p['bytes_total'] != failed_bytes:
                            raise RuntimeError('new_retry_scope_changed')
                        publish('downloading_saved_failures', workers=128, previous_verified=previous, retry_queue=queue,
                                retry_start={key:p.get(key) for key in ('updated_at','files_verified','bytes_verified','files_failed_count','api_http_429_count')})
                        return
                if mode_read and p.get('phase') == 'complete_with_errors' and b.get('status') == 'failed_waiting_retry' and b.get('return_code') == 2:
                    publish('saved_failure_retry_completed_with_errors', workers=128, previous_verified=previous, retry_queue=queue)
                    return
                if startup_failed(p, b, handoff_broker, old_progress_at, mode_read,
                                  marker_exists('retry-download')):
                    raise RuntimeError('new_retry_failed_to_start')
                time.sleep(1)
            raise RuntimeError('retry_start_timeout')
        finally:
            # After handoff the child may not yet have read the mode. Keep it
            # until confirmed, so a slow start cannot fall back to full resume.
            if mode_read or trigger is None:
                remove_own_marker(mode)
                remove_own_marker(trigger)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Never publish raw exception text, paths, or signed download URLs.
        report_failure(exc, check='--check' in sys.argv[1:], resume_paused='--resume-paused' in sys.argv[1:])
        raise SystemExit(1) from None
