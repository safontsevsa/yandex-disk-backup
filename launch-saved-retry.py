#!/usr/bin/env python3
"""Authorize a new broker for one saved failure-queue retry on the selected disk."""
import argparse
from contextlib import ExitStack
from datetime import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time
from zoneinfo import ZoneInfo

import target_config


BASE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('saved_retry_helpers', BASE / 'start-retry-remaining.py')
retry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retry)
START_TIMEOUT = 1200


class LaunchError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def timestamp():
    return datetime.now(ZoneInfo('Europe/Moscow')).isoformat(timespec='seconds')


def optional_state(name):
    try:
        return retry.read_state(name)
    except FileNotFoundError:
        return {}


def script_arguments(command, script):
    if command[:2] == ['/usr/bin/caffeinate', '-im']:
        command = command[2:]
    if not command:
        return None
    executable = Path(command[0]).name
    if executable not in ('Python', 'python', 'python3') and not (
            executable.startswith('python3.') and executable[8:].isdigit()):
        return None
    arguments = command[1:]
    while arguments:
        if arguments[0] in ('-u', '-B', '-E', '-I', '-s', '-S', '-Xutf8'):
            arguments = arguments[1:]
        elif arguments[:2] == ['-X', 'utf8']:
            arguments = arguments[2:]
        else:
            break
    return arguments if arguments and arguments[0] == str(script) else None


def raw_owned_authorizer(pid):
    """Check the old broker independently of its destination configuration."""
    if type(pid) is not int or pid <= 1:
        return False
    result = subprocess.run(['/bin/ps', '-ww', '-p', str(pid), '-o', 'uid=', '-o', 'command='],
                            capture_output=True, text=True)
    fields = result.stdout.strip().split(None, 1)
    if result.returncode or len(fields) != 2 or fields[0] != str(os.getuid()):
        return False
    try:
        return script_arguments(shlex.split(fields[1]), BASE / 'authorize.py') is not None
    except ValueError:
        return False


def owned_child(pid, broker_pid):
    if type(pid) is not int or pid <= 1:
        return False
    result = subprocess.run(['/bin/ps', '-ww', '-p', str(pid), '-o', 'uid=', '-o', 'ppid=', '-o', 'command='],
                            capture_output=True, text=True)
    fields = result.stdout.strip().split(None, 2)
    if result.returncode or len(fields) != 3 or fields[:2] != [str(os.getuid()), str(broker_pid)]:
        return False
    try:
        arguments = script_arguments(shlex.split(fields[2]), BASE / 'download.py')
        return arguments is not None and target_config.arguments_match_target(arguments, BASE / 'target.json')
    except ValueError:
        return False


def input_identities(destination):
    values = []
    for name in ('manifest.json', 'failed-files.json', 'summary.json'):
        path = destination / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise LaunchError('unsafe_saved_metadata')
        values.append((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
    return tuple(values)


def journal_ready(path, *, create=False):
    root = BASE / 'journals'
    if not path.is_absolute() or not path.is_relative_to(root) or path.suffix != '.sqlite3' or '..' in path.parts:
        raise LaunchError('journal_must_use_private_local_directory')
    directory = root
    directories = [root]
    for part in path.parent.relative_to(root).parts:
        directory = directory / part
        directories.append(directory)
    for directory in directories:
        try:
            info = directory.lstat()
        except FileNotFoundError:
            if not create:
                continue
            directory.mkdir(mode=0o700)
            info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise LaunchError('unsafe_journal_directory')
    for suffix in ('', '-journal', '-wal', '-shm'):
        candidate = Path(str(path) + suffix)
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise LaunchError('unsafe_local_journal')


def no_pending():
    if any(retry.marker_exists(name) for name in ('retry-download', 'retry-only-failed', 'use-inventory-cache', 'probe-transport')):
        raise LaunchError('pending_launch_marker')


def validate_auth_status():
    path = BASE / 'authorization-status.log'
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise LaunchError('unsafe_authorization_status_log')


def open_auth_status():
    path = BASE / 'authorization-status.log'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise LaunchError('unsafe_authorization_status_log')
        os.ftruncate(fd, 0)
        return os.fdopen(fd, 'ab', buffering=0), (info.st_dev, info.st_ino)
    except BaseException:
        os.close(fd)
        raise


def authorization_url(identity):
    """Read the controlled status file, returning only an exact loopback form URL."""
    path = BASE / 'authorization-status.log'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino) != identity or info.st_size > 65536):
            raise LaunchError('authorization_status_log_changed_or_unsafe')
        content = source.read(65537)
    # Only complete, exact lines are eligible. Never echo other authorizer output.
    for line in content.split(b'\n')[:-1]:
        match = re.fullmatch(rb'LOCAL_AUTH_URL=(http://127\.0\.0\.1:([0-9]{1,5})/)', line)
        if match and 1 <= int(match[2]) <= 65535 and str(int(match[2])).encode('ascii') == match[2]:
            return match[1].decode('ascii')
    return None


def publish(status, previous, queue, target, **extra):
    value = dict(status=status, coordinator_pid=os.getpid(), updated_at=timestamp(), workers=128,
                 previous_verified=previous, retry_queue=queue, volume=str(target['volume']),
                 journal_path=str(target['journal_path']), prior_copy_integrity_confirmed=False, **extra)
    retry.atomic_json(BASE / 'retry-remaining.json', value)
    print(json.dumps(value, ensure_ascii=False), flush=True)


def acknowledged(progress, broker, pid, old_stamp, queue, target):
    return (broker.get('broker_pid') == pid and broker.get('status') == 'running'
            and retry.owned_broker(pid) and owned_child(broker.get('child_pid'), pid)
            and isinstance(progress.get('updated_at'), str) and progress['updated_at'] != old_stamp
            and progress.get('phase') in ('downloading', 'downloading_missing')
            and progress.get('retry_only_failed') is True
            and progress.get('destination') == str(target['volume'] / 'YandexDisk-backup')
            and progress.get('workers') == 128 and progress.get('download_attempts_max') == retry.DOWNLOAD_ATTEMPTS
            and progress.get('files_total') == queue['files_total']
            and progress.get('bytes_total') == queue['bytes_total'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volume', type=Path)
    parser.add_argument('--journal-path', type=Path)
    parser.add_argument('--client-id', required=True)
    parser.add_argument('--workers', type=int, choices=(128,), default=128)
    parser.add_argument('--check', action='store_true', help='Validate only; do not write state, authorize or start downloads.')
    args = parser.parse_args(argv)
    if not re.fullmatch(r'[0-9a-fA-F]{32}', args.client_id):
        parser.error('--client-id must contain 32 hexadecimal characters')
    configured = target_config.read_target(BASE / 'target.json')
    volume = args.volume or configured['volume']
    journal = args.journal_path or configured['journal_path']
    if journal is None:
        raise LaunchError('explicit_private_journal_required')
    target = target_config.validate_target(dict(volume=str(volume), journal_path=str(journal)), BASE)
    retry.BASE, retry.VOLUME = BASE, target['volume']
    retry.DEST = target['volume'] / 'YandexDisk-backup'
    destination = retry.DEST
    os.umask(0o077)
    with retry.private_lock(BASE / 'retry-remaining.lock', create=not args.check, readonly=args.check), ExitStack() as cleanup:
        with retry.private_lock(BASE / 'download.lock', readonly=args.check):
            no_pending()
            old_broker = optional_state('broker.json')
            if raw_owned_authorizer(old_broker.get('broker_pid')):
                raise LaunchError('existing_authorizer_is_still_alive')
            progress = retry.read_state('progress.json')
            identities = input_identities(destination)
            journal_ready(target['journal_path'])
            validate_auth_status()
            previous, queue = retry.validate_plan(progress, resume_paused=progress.get('phase') == 'paused')
            if (input_identities(destination) != identities or optional_state('broker.json') != old_broker
                    or retry.read_state('progress.json') != progress):
                raise LaunchError('saved_state_changed_during_validation')
            if raw_owned_authorizer(old_broker.get('broker_pid')):
                raise LaunchError('existing_authorizer_is_still_alive')
            if args.check:
                print(json.dumps(dict(status='saved_retry_ready', workers=128, previous_verified=previous,
                                      retry_queue=queue, volume=str(target['volume']),
                                      journal_path=str(target['journal_path'])), ensure_ascii=False), flush=True)
                return
            journal_ready(target['journal_path'], create=True)
            retry.atomic_json(BASE / 'target.json', {key: str(value) for key, value in target.items()})
            if target_config.read_target(BASE / 'target.json') != target:
                raise LaunchError('target_configuration_changed')
            auth_status, status_identity = open_auth_status()
            cleanup.callback(auth_status.close)
            mode = retry.marker('retry-only-failed')
            try:
                publish('waiting_for_new_authorization', previous, queue, target)
            except BaseException:
                retry.remove_own_marker(mode)
                raise
        process = None
        confirmed = False
        try:
            command = [sys.executable, str(BASE / 'authorize.py'), '--client-id', args.client_id,
                       '--volume', str(target['volume']), '--workers', '128',
                       '--journal-path', str(target['journal_path'])]
            try:
                process = subprocess.Popen(command, cwd=BASE, start_new_session=True, stdin=subprocess.DEVNULL,
                                           stdout=auth_status, stderr=subprocess.STDOUT, close_fds=True)
            finally:
                auth_status.close()  # Only the detached authorizer retains its log descriptor.
            retry.atomic_json(BASE / 'broker.json', dict(status='waiting_token', broker_pid=process.pid,
                              volume=str(target['volume']), workers=128, journal_path=str(target['journal_path'])))
            deadline = time.monotonic() + START_TIMEOUT
            relayed = False
            while time.monotonic() < deadline:
                if not relayed:
                    url = authorization_url(status_identity)
                    if url is not None:
                        print('LOCAL_AUTH_URL=' + url, flush=True)
                        relayed = True
                current, broker = retry.read_state('progress.json'), retry.read_state('broker.json')
                if acknowledged(current, broker, process.pid, progress.get('updated_at'), queue, target):
                    confirmed = True
                    retry.remove_own_marker(mode)
                    publish('downloading_saved_failures', previous, queue, target, broker_pid=process.pid,
                            retry_start={key: current.get(key) for key in
                                         ('updated_at', 'files_verified', 'bytes_verified', 'files_failed_count')})
                    return
                if process.poll() is not None:
                    raise LaunchError('authorizer_exited_before_download_confirmation')
                if broker.get('broker_pid') != process.pid:
                    raise LaunchError('new_broker_identity_changed')
                if broker.get('status') == 'failed_waiting_retry':
                    raise LaunchError('new_downloader_requires_attention')
                time.sleep(1)
            raise LaunchError('authorization_or_download_start_timeout')
        finally:
            if confirmed or process is None:
                retry.remove_own_marker(mode)
            # An exited authorizer may have spawned a child that has not yet
            # acquired download.lock or published its PID. Keep retry-only mode
            # after every successful spawn until the new downloader acknowledges it.


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps(dict(status='saved_retry_requires_attention', error_code=exc.code if isinstance(exc, LaunchError)
                              else 'launch_validation_failed')), flush=True)
        raise SystemExit(1) from None
