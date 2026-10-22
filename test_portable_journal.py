"""Portable journal tests use only synthetic temporary files and mocked APIs."""
import contextlib
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import download
import verified_journal
import portable_publish


class PortableJournalTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name).resolve()
        self.volume = self.root / 'KINGSTON'
        self.volume.mkdir(mode=0o700)
        self.destination = self.volume / 'YandexDisk-backup'
        self.destination.mkdir(mode=0o700)
        (self.destination / 'data').mkdir(mode=0o700)
        (self.destination / '.partial').mkdir(mode=0o700)
        self.home = self.root / 'scripts'
        self.home.mkdir(mode=0o700)
        self.journals = self.home / 'journals'
        self.journals.mkdir(mode=0o700)
        self.home_journal = self.journals / 'KINGSTON.sqlite3'
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(download, 'PROGRESS', self.home / 'progress.json'))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.content = b'synthetic verified file'
        self.item = dict(path='disk:/sample.bin', size=len(self.content), md5=hashlib.md5(self.content).hexdigest())
        self.file = self.destination / 'data' / 'sample.bin'
        self.file.write_bytes(self.content)
        self.file.chmod(0o700)

    def journal(self, path=None):
        journal = verified_journal.VerifiedJournal(path or self.home_journal, download)
        self.addCleanup(journal.close)
        return journal

    def test_private700_regular_file_can_be_verified_reopened_and_cached_in_home600_db(self):
        actual = download.verified_file_snapshot(self.file, self.item)
        self.assertEqual(actual[-1], 0o700)
        journal = verified_journal.VerifiedJournal(self.home_journal, download)
        try:
            self.assertTrue(journal.record(self.item['path'], self.item, 'sample.bin', self.file, actual))
            self.assertTrue(journal.hit(self.item['path'], self.item, 'sample.bin', self.file))
        finally:
            journal.close()
        self.assertEqual(self.home_journal.stat().st_mode & 0o777, 0o600)
        reopened = self.journal()
        self.assertTrue(reopened.hit(self.item['path'], self.item, 'sample.bin', self.file))

    def test_public_or_wrong_owner_snapshots_are_not_accepted(self):
        value = list(verified_journal.snapshot(self.file, download))
        for mode in (0o644, 0o640, 0o744, 0o755, 0o777):
            self.assertFalse(verified_journal.private_snapshot([*value[:6], mode]))
        changed = list(value)
        changed[5] += 1
        self.assertFalse(verified_journal.private_snapshot(changed))
        self.file.chmod(0o744)
        journal = self.journal()
        self.assertFalse(journal.record(self.item['path'], self.item, 'sample.bin', self.file,
                                        verified_journal.snapshot(self.file, download)))

    def test_copy_to_new_inode_never_reuses_or_rebases_old_certificate(self):
        journal = self.journal()
        original = download.verified_file_snapshot(self.file, self.item)
        self.assertTrue(journal.record(self.item['path'], self.item, 'sample.bin', self.file, original))
        moved = self.destination / 'data' / 'new-inode.bin'
        moved.write_bytes(self.content)
        moved.chmod(0o700)
        self.assertNotEqual(moved.stat().st_ino, self.file.stat().st_ino)
        self.assertFalse(journal.hit(self.item['path'], self.item, 'sample.bin', moved))
        self.assertFalse(journal.record(self.item['path'], self.item, 'sample.bin', moved, original))
        row = journal.db.execute('SELECT fingerprint FROM verified').fetchone()
        self.assertEqual(tuple(json.loads(row[0])), original)

    def test_journal_and_sidecars_remain_strictly_private600(self):
        bad = self.journals / 'wrong-mode.sqlite3'
        bad.write_bytes(b'synthetic untouched old journal')
        bad.chmod(0o700)
        with self.assertRaises(download.FatalBackupError):
            verified_journal.VerifiedJournal(bad, download)
        self.assertEqual(bad.read_bytes(), b'synthetic untouched old journal')
        journal = self.journal()
        sidecar = Path(str(self.home_journal) + '-wal')
        sidecar.write_bytes(b'synthetic unsafe sidecar')
        sidecar.chmod(0o700)
        actual = download.verified_file_snapshot(self.file, self.item)
        with self.assertRaises(download.FatalBackupError):
            journal.record(self.item['path'], self.item, 'sample.bin', self.file, actual)

    def test_symlink_data_and_journal_and_public_directory_are_rejected(self):
        link = self.destination / 'data' / 'link'
        link.symlink_to(self.file)
        with self.assertRaises(download.FatalBackupError):
            verified_journal.snapshot(link, download)
        linked_db = self.journals / 'link.sqlite3'
        linked_db.symlink_to(self.file)
        with self.assertRaises(download.FatalBackupError):
            verified_journal.VerifiedJournal(linked_db, download)
        self.journals.chmod(0o777)
        with self.assertRaises(download.FatalBackupError):
            verified_journal.VerifiedJournal(self.home_journal, download)

    def copy_backup(self):
        self.file.unlink()
        api = SimpleNamespace(token='synthetic', get=mock.Mock(return_value={
            'href': 'https://storage.yandex.net/synthetic', 'method': 'GET'}))
        volume = SimpleNamespace(stat=lambda: self.root.stat(), is_mount=lambda: True)
        backup = download.Backup(api, volume, self.destination, journal_path=self.home_journal)
        backup.journal = self.journal()
        backup.transport = 'curl'

        def body(href, output, key, host):
            output.write(self.content)
            return len(self.content)

        backup.curl_download = mock.Mock(side_effect=body)
        return backup

    def test_exclusive_copy_rehashes_new_inode_and_checkpoints_before_removing_partial(self):
        backup = self.copy_backup()
        original_record = backup.journal.record
        temporary = self.destination / '.partial' / hashlib.sha256(self.item['path'].encode()).hexdigest()

        def record(*args, **kwargs):
            self.assertTrue(temporary.exists())
            self.assertNotEqual(temporary.stat().st_ino, self.file.stat().st_ino)
            return original_record(*args, **kwargs)

        with mock.patch.object(portable_publish.os, 'link', side_effect=OSError(errno.EPERM, 'synthetic unsupported')), \
                mock.patch.object(portable_publish, '_rename_exclusive', side_effect=OSError(errno.ENOTSUP, 'synthetic unsupported')), \
                mock.patch.object(backup.journal, 'record', side_effect=record) as checkpoint:
            self.assertTrue(backup.download(self.item))
        checkpoint.assert_called_once()
        self.assertFalse(temporary.exists())
        self.assertEqual(self.file.read_bytes(), self.content)
        self.assertTrue(backup.journal.hit(self.item['path'], self.item, 'sample.bin', self.file))

    def test_exclusive_copy_checksum_failure_keeps_both_files_and_never_checkpoints(self):
        backup = self.copy_backup()

        def corrupt(source, target, **kwargs):
            target.write_bytes(b'corrupt copy')
            return 'exclusive_copy'

        with mock.patch.object(portable_publish, 'publish_verified', side_effect=corrupt), \
                mock.patch.object(backup.journal, 'record') as checkpoint, \
                self.assertRaises(download.FatalBackupError):
            backup.download(self.item)
        checkpoint.assert_not_called()
        temporary = self.destination / '.partial' / hashlib.sha256(self.item['path'].encode()).hexdigest()
        self.assertTrue(temporary.exists())
        self.assertEqual(self.file.read_bytes(), b'corrupt copy')
        self.assertEqual(backup.api.get.call_count, 1)

    def test_exclusive_copy_checkpoint_failure_keeps_verified_target_and_partial(self):
        backup = self.copy_backup()
        with mock.patch.object(portable_publish.os, 'link', side_effect=OSError(errno.EPERM, 'synthetic unsupported')), \
                mock.patch.object(portable_publish, '_rename_exclusive', side_effect=OSError(errno.ENOTSUP, 'synthetic unsupported')), \
                mock.patch.object(backup.journal, 'record', return_value=False), self.assertRaises(download.FatalBackupError):
            backup.download(self.item)
        temporary = self.destination / '.partial' / hashlib.sha256(self.item['path'].encode()).hexdigest()
        self.assertTrue(temporary.exists())
        self.assertEqual(self.file.read_bytes(), self.content)
        self.assertEqual(backup.api.get.call_count, 1)


class QueueJournalIntegrationTests(unittest.TestCase):
    setUp = PortableJournalTests.setUp
    def prepare_queue(self):
        self.file.unlink()
        old_content, pending_content = b'old verified copy', b'pending data'
        old = dict(path='disk:/old.bin', size=len(old_content), md5=hashlib.md5(old_content).hexdigest())
        pending = dict(path='disk:/pending.bin', size=len(pending_content), md5=hashlib.md5(pending_content).hexdigest())
        old_path = self.destination / 'data' / 'old.bin'
        old_path.write_bytes(old_content)
        old_path.chmod(0o700)
        inventory = dict(files=[old, pending], directories=[], local_paths={'disk:/old.bin': 'old.bin',
                         'disk:/pending.bin': 'pending.bin'}, local_directory_paths={})
        total = old['size'] + pending['size']
        summary = dict(phase='complete_with_errors', inventory_verified=True, source_changed=False,
                       inventory_files_attempted=2, inventory_bytes_attempted=total,
                       files_verified=1, bytes_verified=old['size'], files_failed_count=1, bytes_failed=pending['size'])
        failure = dict(files=[pending], directories=[], files_failed_count=1, bytes_failed=pending['size'])
        for name, data in (('manifest.json', inventory), ('summary.json', summary), ('failed-files.json', failure)):
            path = self.destination / name
            path.write_text(json.dumps(data), encoding='utf-8')
            path.chmod(0o700)
        api = SimpleNamespace(get=mock.Mock(return_value=dict(used_space=total)),
                              inventory=mock.Mock(return_value=inventory))
        self.stack.enter_context(mock.patch.object(Path, 'is_mount', lambda path: path == self.volume))
        self.stack.enter_context(mock.patch.object(download, 'private_marker', lambda path: path == download.RETRY_FAILED_MARKER))
        self.stack.enter_context(mock.patch.object(download, 'selected_transport', return_value='curl'))
        self.stack.enter_context(mock.patch.object(download, 'selected_curl_profile', return_value=('default', ())))
        return api, old, pending, old_path

    def test_external_empty_journal_checks_only_queue_before_download_and_preserves_old_volume_db(self):
        api, old, pending, old_path = self.prepare_queue()
        old_db = self.destination / 'verified.sqlite3'
        old_db.write_bytes(b'synthetic copied old journal')
        old_db.chmod(0o700)
        backup = download.Backup(api, self.volume, self.destination, journal_path=self.home_journal)
        seen = []
        real_snapshot = download.verified_file_snapshot

        def tracked_snapshot(path, item):
            seen.append(path)
            return real_snapshot(path, item)

        class ReachedDownload(Exception):
            pass

        def reached(files, workers):
            self.assertEqual(files, [pending])
            self.assertEqual(workers, 128)
            self.assertNotIn(old_path, seen)
            raise ReachedDownload()

        with mock.patch.object(download, 'verified_file_snapshot', side_effect=tracked_snapshot), \
                mock.patch.object(backup, 'download_batch', side_effect=reached), self.assertRaises(ReachedDownload):
            try:
                backup.run(False, 128)
            finally:
                if backup.journal is not None:
                    backup.journal.close()
        self.assertEqual(old_db.read_bytes(), b'synthetic copied old journal')
        self.assertEqual(self.home_journal.stat().st_mode & 0o777, 0o600)
        self.assertFalse(backup.state['prior_copy_integrity_confirmed'])
        self.assertEqual(api.inventory.call_count, 0)

    def completed_queue(self, external):
        api, old, pending, old_path = self.prepare_queue()
        backup = download.Backup(api, self.volume, self.destination,
                                 journal_path=self.home_journal if external else None)

        def finish(files, workers):
            backup.failed.clear()
            backup.failed_bytes = 0
            backup.progress(files_verified=1, bytes_verified=pending['size'], files_failed_count=0, bytes_failed=0,
                            files_pending_count=0)

        with mock.patch.object(backup, 'download_batch', side_effect=finish):
            try:
                backup.run(False, 128)
            finally:
                if backup.journal is not None:
                    backup.journal.close()
        return backup

    def test_completed_queue_with_new_external_journal_does_not_claim_full_relocated_copy_integrity(self):
        backup = self.completed_queue(external=True)
        self.assertEqual(backup.state['phase'], 'complete')
        self.assertFalse(backup.state['prior_copy_integrity_confirmed'])
        self.assertFalse(backup.state['backup_complete'])

    def test_default_journal_keeps_existing_completion_semantics(self):
        backup = self.completed_queue(external=False)
        self.assertEqual(backup.state['phase'], 'complete')
        self.assertTrue(backup.state['prior_copy_integrity_confirmed'])
        self.assertTrue(backup.state['backup_complete'])

    def test_cli_forwards_explicit_journal_and_volume_without_touching_live_lock(self):
        fake = SimpleNamespace(journal=None, state={'phase': 'plan'}, run=mock.Mock())
        real_stat = Path.stat

        def volume_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if path == self.volume:
                values = list(result)
                values[2] += 1
                return os.stat_result(values)
            return result

        command = ['download.py', '--plan', '--volume', str(self.volume), '--workers', '128',
                   '--journal-path', str(self.home_journal)]
        with mock.patch.object(download, '__file__', str(self.home / 'download.py')), \
                mock.patch.object(sys, 'argv', command), \
                mock.patch.object(download.os, 'environ', {'YANDEX_DISK_TOKEN': 'synthetic'}), \
                mock.patch.object(Path, 'is_mount', lambda path: path == self.volume), \
                mock.patch.object(Path, 'stat', volume_stat), \
                mock.patch.object(download, 'DiskAPI', return_value=object()), \
                mock.patch.object(download, 'Backup', return_value=fake) as constructor, \
                mock.patch.object(download, 'private_marker', return_value=False), \
                mock.patch.object(download.signal, 'signal'):
            self.assertEqual(download.main(), 0)
        self.assertEqual(constructor.call_args.kwargs['journal_path'], self.home_journal)
        self.assertEqual(constructor.call_args.args[1], self.volume)
        fake.run.assert_called_once_with(True, 128)
        self.assertTrue((self.home / 'download.lock').exists())


if __name__ == '__main__':
    unittest.main()
