"""Isolated temporary-file publication tests; no backup data or network."""

import ctypes
import contextlib
import errno
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import portable_publish as publish


class PortablePublishTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        self.source, self.target = root / "partial", root / "published"
        self.content = b"synthetic verified file contents"
        self.source.write_bytes(self.content)

    def unsupported_link(self, *args, **kwargs):
        raise OSError(errno.EOPNOTSUPP, "synthetic unsupported hard link")

    def test_hardlink_success_publishes_and_removes_source(self):
        with mock.patch.object(publish, "_rename_exclusive") as native:
            result = publish.publish_verified(self.source, self.target)
        self.assertEqual(result, "hardlink")
        self.assertFalse(self.source.exists())
        self.assertEqual(self.target.read_bytes(), self.content)
        native.assert_not_called()

    def test_existing_target_is_never_replaced_or_given_a_rename_fallback(self):
        self.target.write_bytes(b"existing synthetic target")
        with mock.patch.object(publish, "_rename_exclusive") as native:
            with self.assertRaises(OSError) as failed:
                publish.publish_verified(self.source, self.target)
        self.assertEqual(failed.exception.errno, errno.EEXIST)
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertEqual(self.target.read_bytes(), b"existing synthetic target")
        native.assert_not_called()

    def test_noneligible_link_errors_never_try_native_rename(self):
        for code in (errno.EIO, errno.EXDEV, errno.EACCES, errno.ENOENT, errno.ENOSPC, errno.EEXIST):
            with self.subTest(errno=code), mock.patch.object(publish.os, "link", side_effect=OSError(code, "synthetic")), \
                    mock.patch.object(publish, "_rename_exclusive") as native:
                with self.assertRaises(OSError) as failed:
                    publish.publish_verified(self.source, self.target)
                self.assertEqual(failed.exception.errno, code)
                native.assert_not_called()
                self.assertEqual(self.source.read_bytes(), self.content)
                self.assertFalse(self.target.exists())

    def test_cleanup_failure_after_successful_link_is_reported_without_rename(self):
        with mock.patch.object(publish.os, "unlink", side_effect=OSError(errno.EPERM, "synthetic cleanup failure")), \
                mock.patch.object(publish, "_rename_exclusive") as native:
            with self.assertRaises(OSError) as failed:
                publish.publish_verified(self.source, self.target)
        self.assertEqual(failed.exception.errno, errno.EPERM)
        self.assertEqual(self.source.stat().st_ino, self.target.stat().st_ino)
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertEqual(self.target.read_bytes(), self.content)
        native.assert_not_called()

    def test_only_supported_link_errors_select_native_rename(self):
        for code in (errno.EPERM, errno.EOPNOTSUPP, errno.ENOTSUP):
            with self.subTest(errno=code), mock.patch.object(publish.os, "link", side_effect=OSError(code, "synthetic")), \
                    mock.patch.object(publish, "_rename_exclusive") as native:
                publish.publish_verified(self.source, self.target)
                native.assert_called_once_with(self.source, self.target)

    def test_unsupported_platform_uses_exclusive_copy_and_preserves_source(self):
        with mock.patch.object(publish.os, "link", side_effect=self.unsupported_link), \
                mock.patch.object(publish.sys, "platform", "other"), \
                mock.patch.object(publish.ctypes, "CDLL") as library:
            method = publish.publish_verified(self.source, self.target)
        self.assertEqual(method, "exclusive_copy")
        library.assert_not_called()
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertEqual(self.target.read_bytes(), self.content)

    def test_missing_native_symbol_uses_exclusive_copy_and_preserves_source(self):
        with mock.patch.object(publish.os, "link", side_effect=self.unsupported_link), \
                mock.patch.object(publish.sys, "platform", "darwin"), \
                mock.patch.object(publish.ctypes, "CDLL", return_value=object()) as library:
            method = publish.publish_verified(self.source, self.target)
        self.assertEqual(method, "exclusive_copy")
        library.assert_called_once_with(None, use_errno=True)
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertEqual(self.target.read_bytes(), self.content)

    def test_native_signature_flag_and_errno_are_explicit(self):
        rename = mock.Mock(side_effect=lambda *args: (ctypes.set_errno(errno.EIO), -1)[1])
        library = mock.Mock(renamex_np=rename)
        with mock.patch.object(publish.os, "link", side_effect=self.unsupported_link), \
                mock.patch.object(publish.sys, "platform", "darwin"), \
                mock.patch.object(publish.ctypes, "CDLL", return_value=library):
            with self.assertRaises(OSError) as failed:
                publish.publish_verified(self.source, self.target)
        self.assertEqual(failed.exception.errno, errno.EIO)
        self.assertEqual(rename.argtypes, [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint])
        self.assertIs(rename.restype, ctypes.c_int)
        rename.assert_called_once_with(os.fsencode(self.source), os.fsencode(self.target), 0x00000004)
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertFalse(self.target.exists())

    def test_embedded_null_is_rejected_before_any_publication(self):
        with mock.patch.object(publish.os, "link") as link, \
                mock.patch.object(publish, "_rename_exclusive") as native:
            for source, target in (("unsafe\x00source", self.target), (self.source, b"unsafe\x00target")):
                with self.subTest(source=type(source).__name__, target=type(target).__name__), self.assertRaises(ValueError):
                    publish.publish_verified(source, target)
        link.assert_not_called()
        native.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "Darwin native rename test")
    def test_native_exclusive_rename_publishes_when_links_are_unsupported(self):
        with mock.patch.object(publish.os, "link", side_effect=self.unsupported_link):
            self.assertEqual(publish.publish_verified(self.source, self.target), "rename")
        self.assertFalse(self.source.exists())
        self.assertEqual(self.target.read_bytes(), self.content)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin native rename test")
    def test_native_existing_destination_never_changes_source_or_target(self):
        self.target.write_bytes(b"existing synthetic destination")
        with mock.patch.object(publish.os, "link", side_effect=self.unsupported_link):
            with self.assertRaises(OSError) as failed:
                publish.publish_verified(self.source, self.target)
        self.assertEqual(failed.exception.errno, errno.EEXIST)
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertEqual(self.target.read_bytes(), b"existing synthetic destination")

    @unittest.skipUnless(sys.platform == "darwin", "Darwin native rename race test")
    def test_native_racing_destination_is_not_replaced(self):
        def racing_link(*args, **kwargs):
            self.target.write_bytes(b"synthetic concurrent destination")
            self.unsupported_link()

        with mock.patch.object(publish.os, "link", side_effect=racing_link):
            with self.assertRaises(OSError) as failed:
                publish.publish_verified(self.source, self.target)
        self.assertEqual(failed.exception.errno, errno.EEXIST)
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertEqual(self.target.read_bytes(), b"synthetic concurrent destination")

    def copy_fallback(self):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(publish.os, "link", side_effect=self.unsupported_link))
        stack.enter_context(mock.patch.object(publish, "_rename_exclusive", side_effect=OSError(errno.ENOTSUP, "synthetic")))
        return stack

    def test_exclusive_copy_fsyncs_and_preserves_source_for_caller_verification(self):
        with self.copy_fallback(), mock.patch.object(publish.os, "fsync", wraps=os.fsync) as sync:
            method = publish.publish_verified(self.source, self.target)
        self.assertEqual(method, "exclusive_copy")
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertEqual(self.target.read_bytes(), self.content)
        self.assertNotEqual(self.source.stat().st_ino, self.target.stat().st_ino)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        sync.assert_called_once()

    def test_copy_accepts_exfat_inode_assignment_on_first_write(self):
        original_open, original_fstat, original_write = os.open, os.fstat, os.write
        target_fd = None
        wrote = False

        def opening(path, *args, **kwargs):
            nonlocal target_fd
            fd = original_open(path, *args, **kwargs)
            if Path(path) == self.target:
                target_fd = fd
            return fd

        def fstat(fd):
            info = original_fstat(fd)
            if fd == target_fd and not wrote:
                return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 987654,
                                       st_size=info.st_size, st_mode=info.st_mode)
            return info

        def write(fd, data):
            nonlocal wrote
            result = original_write(fd, data)
            if fd == target_fd:
                wrote = True
            return result

        with self.copy_fallback(), mock.patch.object(publish.os, "open", side_effect=opening), \
                mock.patch.object(publish.os, "fstat", side_effect=fstat), \
                mock.patch.object(publish.os, "write", side_effect=write):
            self.assertEqual(publish.publish_verified(self.source, self.target), "exclusive_copy")
        self.assertTrue(wrote)
        self.assertEqual(self.target.read_bytes(), self.content)
        self.assertEqual(self.source.read_bytes(), self.content)

    def test_failed_copy_cannot_remove_a_foreign_replacement_after_lstat(self):
        original_lstat = os.lstat
        foreign = self.target.with_name("foreign")
        foreign.write_bytes(b"foreign replacement")

        def replace_after_stat(path, *args, **kwargs):
            info = original_lstat(path, *args, **kwargs)
            if Path(path) == self.target:
                os.replace(foreign, self.target)
            return info

        with self.copy_fallback(), mock.patch.object(publish.os, "write", side_effect=OSError(errno.EIO, "synthetic")), \
                mock.patch.object(publish.os, "lstat", side_effect=replace_after_stat), \
                mock.patch.object(publish.os, "unlink", side_effect=AssertionError("Never remove a failed target")):
            with self.assertRaises(OSError):
                publish.publish_verified(self.source, self.target)
        self.assertEqual(self.source.read_bytes(), self.content)

    def test_exclusive_copy_never_overwrites_existing_target(self):
        self.target.write_bytes(b"existing copy target")
        with self.copy_fallback(), self.assertRaises(OSError) as failed:
            publish.publish_verified(self.source, self.target)
        self.assertEqual(failed.exception.errno, errno.EEXIST)
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertEqual(self.target.read_bytes(), b"existing copy target")

    def test_copy_write_failure_retains_unverified_target_and_preserves_source(self):
        with self.copy_fallback(), mock.patch.object(publish.os, "write", side_effect=OSError(errno.ENOSPC, "synthetic")):
            with self.assertRaises(OSError) as failed:
                publish.publish_verified(self.source, self.target)
        self.assertEqual(failed.exception.errno, errno.ENOSPC)
        self.assertTrue(self.target.exists())
        self.assertEqual(self.target.read_bytes(), b"")
        self.assertEqual(self.source.read_bytes(), self.content)

    def test_copy_cleanup_preserves_a_foreign_replacement(self):
        foreign = self.target.with_name("foreign")
        foreign.write_bytes(b"foreign replacement")

        def replace_then_fail(*args):
            os.replace(foreign, self.target)
            raise OSError(errno.EIO, "synthetic write failure")

        with self.copy_fallback(), mock.patch.object(publish.os, "write", side_effect=replace_then_fail):
            with self.assertRaises(OSError):
                publish.publish_verified(self.source, self.target)
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertEqual(self.target.read_bytes(), b"foreign replacement")

    def test_copy_cancellation_retains_unverified_target_and_preserves_source(self):
        stopped = threading.Event()
        original_write = os.write

        def write_then_stop(*args):
            result = original_write(*args)
            stopped.set()
            return result

        with self.copy_fallback(), mock.patch.object(publish.os, "write", side_effect=write_then_stop):
            with self.assertRaises(OSError) as failed:
                publish.publish_verified(self.source, self.target, stop_event=stopped)
        self.assertEqual(failed.exception.errno, errno.ECANCELED)
        self.assertTrue(self.target.exists())
        self.assertEqual(self.source.read_bytes(), self.content)

    def test_copy_keyboard_interrupt_retains_unverified_target(self):
        with self.copy_fallback(), mock.patch.object(publish.os, "write", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                publish.publish_verified(self.source, self.target)
        self.assertTrue(self.target.exists())
        self.assertEqual(self.target.read_bytes(), b"")
        self.assertEqual(self.source.read_bytes(), self.content)

    def test_changed_source_is_rejected_and_copy_target_is_retained_unverified(self):
        original_write = os.write

        def write_then_change_source(*args):
            result = original_write(*args)
            self.source.write_bytes(b"changed source")
            return result

        with self.copy_fallback(), mock.patch.object(publish.os, "write", side_effect=write_then_change_source):
            with self.assertRaises(OSError) as failed:
                publish.publish_verified(self.source, self.target)
        self.assertEqual(failed.exception.errno, errno.ESTALE)
        self.assertTrue(self.target.exists())
        self.assertEqual(self.source.read_bytes(), b"changed source")

    def test_native_errors_other_than_unsupported_never_select_copy(self):
        for code in (errno.EEXIST, errno.EXDEV, errno.EIO, errno.EPERM, errno.EINVAL):
            with self.subTest(errno=code), mock.patch.object(publish.os, "link", side_effect=self.unsupported_link), \
                    mock.patch.object(publish, "_rename_exclusive", side_effect=OSError(code, "synthetic")), \
                    mock.patch.object(publish, "_exclusive_copy") as copy:
                with self.assertRaises(OSError) as failed:
                    publish.publish_verified(self.source, self.target)
                self.assertEqual(failed.exception.errno, code)
                copy.assert_not_called()

    def test_native_unsupported_errors_select_copy(self):
        for code in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS):
            with self.subTest(errno=code), mock.patch.object(publish.os, "link", side_effect=self.unsupported_link), \
                    mock.patch.object(publish, "_rename_exclusive", side_effect=OSError(code, "synthetic")), \
                    mock.patch.object(publish, "_exclusive_copy") as copy:
                method = publish.publish_verified(self.source, self.target)
                self.assertEqual(method, "exclusive_copy")
                copy.assert_called_once_with(self.source, self.target, None)


if __name__ == "__main__":
    unittest.main()
