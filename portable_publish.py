"""Publish a verified temporary file without replacing any target."""

import ctypes
import errno
import os
import stat
import sys


# macOS SDK sys/stdio.h: renamex_np(const char *, const char *, unsigned int).
# RENAME_EXCL prevents replacement of an existing destination, including a
# destination created after an earlier filesystem check.
RENAME_EXCL = 0x00000004
_UNSUPPORTED_LINK_ERRORS = {errno.EPERM, errno.EOPNOTSUPP, errno.ENOTSUP}
_UNSUPPORTED_RENAME_ERRORS = {errno.EOPNOTSUPP, errno.ENOTSUP, errno.ENOSYS}
_COPY_CHUNK_SIZE = 1024 * 1024


def _encoded_path(path):
    encoded = os.fsencode(path)
    if b"\x00" in encoded:
        raise ValueError("Publication path contains a null byte")
    return encoded


def _rename_exclusive(source, target):
    """Use the native exclusive rename operation; never emulate it unsafely."""
    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "Atomic exclusive publication is unavailable")
    try:
        library = ctypes.CDLL(None, use_errno=True)
        rename = library.renamex_np
    except (AttributeError, OSError):
        raise OSError(errno.ENOTSUP, "Atomic exclusive publication is unavailable") from None
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    if rename(_encoded_path(source), _encoded_path(target), RENAME_EXCL) != 0:
        raise OSError(ctypes.get_errno() or errno.EIO, "Atomic exclusive publication failed")


def _check_cancelled(stop_event):
    if stop_event is not None and stop_event.is_set():
        raise OSError(errno.ECANCELED, "Publication cancelled")


def _identity(info):
    return info.st_dev, info.st_ino


def _source_snapshot(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_uid, stat.S_IMODE(info.st_mode))


def _exclusive_copy(source, target, stop_event):
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    target_fd = None
    try:
        before = os.fstat(source_fd)
        if (not stat.S_ISREG(before.st_mode)
                or _source_snapshot(os.lstat(source)) != _source_snapshot(before)):
            raise OSError(errno.ESTALE, "Verified source changed before publication")
        _check_cancelled(stop_event)
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        copied = 0
        while True:
            _check_cancelled(stop_event)
            chunk = os.read(source_fd, min(_COPY_CHUNK_SIZE, before.st_size - copied + 1))
            if not chunk:
                break
            if len(chunk) > before.st_size - copied:
                raise OSError(errno.ESTALE, "Verified source grew during publication")
            remaining = memoryview(chunk)
            while remaining:
                _check_cancelled(stop_event)
                written = os.write(target_fd, remaining)
                if written <= 0:
                    raise OSError(errno.EIO, "Publication copy made no write progress")
                copied += written
                remaining = remaining[written:]
        os.fsync(target_fd)
        _check_cancelled(stop_event)
        if (copied != before.st_size
                or _source_snapshot(os.fstat(source_fd)) != _source_snapshot(before)
                or _source_snapshot(os.lstat(source)) != _source_snapshot(before)):
            raise OSError(errno.ESTALE, "Verified source changed during publication")
        opened, named = os.fstat(target_fd), os.lstat(target)
        # exFAT can assign a new inode when its first data cluster is allocated.
        # Compare the current open file with its current name after fsync,
        # instead of comparing either with an empty-file inode observed earlier.
        if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode)
                or _identity(opened) != _identity(named) or opened.st_size != copied):
            raise OSError(errno.ESTALE, "Publication target changed during copy")
        # The caller must verify this new inode and save its checkpoint before
        # removing source. Copied contents are not a verification certificate.
    finally:
        # Never unlink a failed copy by name: lstat + unlink cannot atomically
        # prove ownership of a directory entry that another process can replace.
        # Keep both source and any unverified target for fail-closed recovery.
        try:
            os.close(source_fd)
        finally:
            if target_fd is not None:
                os.close(target_fd)


def publish_verified(source, target, *, stop_event=None):
    """Publish ``source`` once, preserving any pre-existing ``target``.

    The caller verifies source contents and safe parent paths before calling.
    Hard links retain the existing publication method on supported filesystems.
    If links are unsupported, Darwin's RENAME_EXCL is tried next. If native
    exclusive rename is also unsupported, O_EXCL creates a new target for a
    checked copy. Return value is ``hardlink``, ``rename`` or ``exclusive_copy``.

    An exclusive copy retains source until the caller has verified the target
    and saved its checkpoint. Its target is visible while copying. Any failure,
    cancellation or crash can leave an unverified target; it is never unlinked
    automatically because compare-and-unlink is not atomic. Subsequent calls
    fail closed on an existing target rather than replacing it. Other publish
    errors never select another method, and errors after a successful link never
    cause another publish.
    """
    _encoded_path(source)
    _encoded_path(target)
    _check_cancelled(stop_event)
    try:
        os.link(source, target)
    except OSError as exc:
        if exc.errno not in _UNSUPPORTED_LINK_ERRORS:
            raise
    else:
        os.unlink(source)
        return "hardlink"
    _check_cancelled(stop_event)
    try:
        _rename_exclusive(source, target)
    except OSError as exc:
        if exc.errno not in _UNSUPPORTED_RENAME_ERRORS:
            raise
        _exclusive_copy(source, target, stop_event)
        return "exclusive_copy"
    return "rename"
