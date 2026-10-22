#!/usr/bin/env python3
"""Gracefully pause this live backup; retain its broker and saved checkpoint."""
import argparse
from datetime import datetime
import importlib.util
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import time
from zoneinfo import ZoneInfo


BASE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('pause_retry_helpers', BASE / 'start-retry-remaining.py')
retry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retry)


class PauseError(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def python_script(command, script):
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
    return bool(arguments and arguments[0] == str(script))


def process_identity(pid):
    if type(pid) is not int or pid <= 1:
        raise PauseError('invalid_child_pid')
    result = subprocess.run(['/bin/ps', '-ww', '-p', str(pid), '-o', 'uid=', '-o', 'ppid=', '-o', 'command='],
                            capture_output=True, text=True)
    fields = result.stdout.strip().split(None, 2)
    if result.returncode or len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
        raise PauseError('child_process_not_found')
    try:
        command = tuple(shlex.split(fields[2]))
    except ValueError:
        raise PauseError('invalid_child_command') from None
    return int(fields[0]), int(fields[1]), command


def owned_downloader(child_pid, broker_pid):
    identity = process_identity(child_pid)
    uid, parent, command = identity
    if uid != os.getuid() or parent != broker_pid:
        raise PauseError('child_ownership_mismatch')
    if not retry.arguments_match_target(list(command), BASE / 'target.json'):
        raise PauseError('child_destination_does_not_match_target')
    script = BASE / 'download.py'
    if python_script(list(command), script):
        return child_pid, identity
    if list(command[:2]) != ['/usr/bin/caffeinate', '-im'] or not python_script(list(command[2:]), script):
        raise PauseError('child_command_mismatch')
    result = subprocess.run(['/usr/bin/pgrep', '-P', str(child_pid)], capture_output=True, text=True)
    if result.returncode not in (0, 1):
        raise PauseError('wrapper_children_unavailable')
    candidates = []
    for raw_pid in result.stdout.split():
        if not raw_pid.isdigit():
            raise PauseError('invalid_wrapper_child')
        candidate = int(raw_pid)
        child_identity = process_identity(candidate)
        child_uid, child_parent, child_command = child_identity
        if child_uid == os.getuid() and child_parent == child_pid and python_script(list(child_command), script):
            if not retry.arguments_match_target(list(child_command), BASE / 'target.json'):
                raise PauseError('child_destination_does_not_match_target')
            candidates.append((candidate, child_identity))
    if len(candidates) != 1:
        raise PauseError('owned_python_child_not_unique')
    return candidates[0]


def lock_identity():
    fd = os.open(BASE / 'download.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PauseError('unsafe_download_lock')
        return info.st_dev, info.st_ino
    finally:
        os.close(fd)


def no_pending_markers():
    if any(retry.marker_exists(name) for name in ('retry-download', 'retry-only-failed', 'use-inventory-cache')):
        raise PauseError('retry_request_pending')


def stopped_broker(broker, broker_pid):
    return (broker.get('broker_pid') == broker_pid and broker.get('status') == 'failed_waiting_retry'
            and broker.get('return_code') == 130 and broker.get('child_pid') is None)


def pause_totals(progress, record):
    manifest = retry.canonical_inventory(retry.read_private_inventory(retry.DEST / 'manifest.json'))
    failure_record = retry.read_private_inventory(retry.DEST / 'failed-files.json')
    failures = retry.canonical_inventory(failure_record)
    full_count = len(manifest['files'])
    full_size = sum(item['size'] for item in manifest['files'])
    known = {item['path']: item for item in manifest['files']}
    for item in failures['files']:
        original = known.get(item['path'])
        if original is None or any(original.get(key) != item.get(key) for key in ('size', 'md5')):
            raise PauseError('failure_queue_not_consistent')
    failed_count = len(failures['files'])
    failed_size = sum(item['size'] for item in failures['files'])
    fields = ('files_verified', 'bytes_verified', 'files_total', 'bytes_total', 'files_failed_count', 'bytes_failed')
    if (not all(retry.nonnegative(progress.get(key)) for key in fields)
            or failure_record.get('files_failed_count') != failed_count or failure_record.get('bytes_failed') != failed_size
            or progress['files_failed_count'] != failed_count or progress['bytes_failed'] != failed_size
            or progress['files_verified'] + failed_count != progress['files_total']
            or progress['bytes_verified'] + failed_size != progress['bytes_total']):
        raise PauseError('paused_totals_not_consistent')
    overall_count, overall_size = progress['files_verified'], progress['bytes_verified']
    if progress.get('retry_only_failed') is True:
        previous = record.get('previous_verified', {})
        if (not isinstance(previous, dict)
                or not all(retry.nonnegative(previous.get(key)) for key in ('files_verified', 'bytes_verified', 'files_total', 'bytes_total'))
                or previous['files_total'] != full_count or previous['bytes_total'] != full_size
                or previous['files_verified'] + progress['files_total'] != full_count
                or previous['bytes_verified'] + progress['bytes_total'] != full_size):
            raise PauseError('paused_baseline_not_consistent')
        overall_count += previous['files_verified']
        overall_size += previous['bytes_verified']
    elif progress['files_total'] != full_count or progress['bytes_total'] != full_size:
        raise PauseError('paused_inventory_not_consistent')
    return dict(files_verified=overall_count, bytes_verified=overall_size,
                files_remaining=failed_count, bytes_remaining=failed_size,
                inventory_files_total=full_count, inventory_bytes_total=full_size)


def finish_pause(broker_pid, initial_lock, *, already_paused=False, validate_only=False):
    with retry.private_lock(BASE / 'download.lock', readonly=True) as lock:
        info = os.fstat(lock.fileno())
        if (info.st_dev, info.st_ino) != initial_lock:
            raise PauseError('download_lock_changed')
        no_pending_markers()
        broker = retry.read_state('broker.json')
        progress = retry.read_state('progress.json')
        if not stopped_broker(broker, broker_pid) or not retry.owned_broker(broker_pid):
            raise PauseError('broker_not_stopped_after_pause')
        record = retry.read_state('retry-remaining.json')
        totals = pause_totals(progress, record)
        if retry.read_state('broker.json') != broker or retry.read_state('progress.json') != progress:
            raise PauseError('state_changed_during_pause_validation')
        if not already_paused and not validate_only:
            paused_at = datetime.now(ZoneInfo('Europe/Moscow')).isoformat(timespec='seconds')
            progress.update(phase='paused', updated_at=paused_at, paused_at=paused_at, resume_policy='manual',
                            active_transfers={}, current_file=None, current_directory=None)
            retry.atomic_json(BASE / 'progress.json', progress)
            record.update(status='paused', updated_at=paused_at, paused_at=paused_at, resume_policy='manual',
                          pause_totals=totals)
            retry.atomic_json(BASE / 'retry-remaining.json', record)
        status = 'already_paused' if already_paused else ('pause_ready' if validate_only else 'paused')
        print(json.dumps(dict(status=status, **totals)), flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Pause this live backup without stopping its authorization broker.')
    parser.add_argument('--check', action='store_true', help='Validate the pause target without sending a signal or changing state.')
    parser.add_argument('--timeout', type=int, default=90, metavar='SECONDS', help='Graceful stop timeout, 1-300 seconds (default: 90).')
    args = parser.parse_args(argv)
    retry.configure_target()
    if not 1 <= args.timeout <= 300:
        parser.error('--timeout must be between 1 and 300')
    os.umask(0o077)
    # An active one-shot retry coordinator must be handled explicitly, not raced.
    with retry.private_lock(BASE / 'retry-remaining.lock', readonly=True):
        no_pending_markers()
        broker = retry.read_state('broker.json')
        progress = retry.read_state('progress.json')
        if retry.marker_exists('target.json') and progress.get('destination') != str(retry.DEST):
            raise PauseError('progress_destination_does_not_match_target')
        broker_pid = broker.get('broker_pid')
        if not retry.owned_broker(broker_pid):
            raise PauseError('broker_not_owned_or_alive')
        initial_lock = lock_identity()
        if stopped_broker(broker, broker_pid):
            # A previous invocation may have timed out before the child finished.
            finish_pause(broker_pid, initial_lock, already_paused=progress.get('phase') == 'paused',
                         validate_only=args.check)
            return
        if broker.get('status') != 'running':
            raise PauseError('backup_not_running_or_already_paused')
        child_pid = broker.get('child_pid')
        target, identity = owned_downloader(child_pid, broker_pid)
        # Recheck both the exact process and broker immediately before signalling.
        no_pending_markers()
        if (retry.read_state('broker.json') != broker or not retry.owned_broker(broker_pid)
                or process_identity(target) != identity or lock_identity() != initial_lock):
            raise PauseError('ownership_changed_before_pause')
        if args.check:
            print(json.dumps(dict(status='pause_ready', workers=progress.get('workers'),
                                  retry_only_failed=progress.get('retry_only_failed') is True)), flush=True)
            return
        os.kill(target, signal.SIGTERM)
        print(json.dumps(dict(status='pausing', resume_policy='manual')), flush=True)
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            current = retry.read_state('broker.json')
            if current.get('broker_pid') != broker_pid or not retry.owned_broker(broker_pid):
                raise PauseError('broker_changed_during_pause')
            if stopped_broker(current, broker_pid):
                try:
                    finish_pause(broker_pid, initial_lock)
                    return
                except BlockingIOError:
                    pass
            elif current.get('status') != 'running' or current.get('child_pid') != child_pid:
                raise PauseError('backup_did_not_stop_with_pause_code')
            time.sleep(0.5)
        raise PauseError('pause_timeout_process_may_still_be_draining')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps(dict(status='pause_requires_attention', error_type=type(exc).__name__,
                              reason=exc.reason if isinstance(exc, PauseError) else 'validation_failed')), flush=True)
        raise SystemExit(1) from None
