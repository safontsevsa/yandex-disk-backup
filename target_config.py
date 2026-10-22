"""Private destination settings shared by the live launch and control commands."""
import json
import os
from pathlib import Path
import stat


class TargetConfigError(RuntimeError):
    pass


def read_target(path=None):
    path = Path(path) if path is not None else Path(__file__).with_name('target.json')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return dict(volume=Path('/Volumes/ADATA'), journal_path=None)
    with os.fdopen(fd, 'r', encoding='utf-8') as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 4096):
            raise TargetConfigError('unsafe_target_configuration')
        try:
            value = json.load(source)
        except (ValueError, UnicodeError):
            raise TargetConfigError('invalid_target_configuration') from None
        after, current = os.fstat(source.fileno()), path.lstat()
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(after) or identity(before) != identity(current):
            raise TargetConfigError('target_configuration_changed')
    return validate_target(value, path.parent)


def validate_target(value, base):
    base = Path(base)
    if not isinstance(value, dict) or set(value) != {'volume', 'journal_path'}:
        raise TargetConfigError('invalid_target_configuration')
    if not all(isinstance(value[key], str) and value[key] for key in value):
        raise TargetConfigError('invalid_target_configuration')
    volume, journal = Path(value['volume']), Path(value['journal_path'])
    if not volume.is_absolute() or volume.parent != Path('/Volumes') or '..' in volume.parts:
        raise TargetConfigError('invalid_target_volume')
    if (not journal.is_absolute() or '..' in journal.parts or journal.suffix != '.sqlite3'
            or not journal.is_relative_to(base / 'journals')):
        raise TargetConfigError('journal_must_use_private_local_directory')
    return dict(volume=volume, journal_path=journal)


def arguments_match_target(arguments, path):
    if not os.path.lexists(path):
        return True
    target = read_target(path)

    def option(name):
        values = []
        for index, argument in enumerate(arguments):
            if argument == name and index + 1 < len(arguments):
                values.append(arguments[index + 1])
            elif argument.startswith(name + '='):
                values.append(argument.split('=', 1)[1])
        return values

    volumes, journals = option('--volume'), option('--journal-path')
    if volumes != [str(target['volume'])]:
        return False
    return journals == [str(target['journal_path'])]
