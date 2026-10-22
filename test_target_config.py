"""Destination configuration tests use only private temporary files."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from target_config import TargetConfigError, arguments_match_target, read_target, validate_target


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.base = Path(self.folder.name).resolve()
        self.path = self.base / 'target.json'
        self.value = dict(volume='/Volumes/KINGSTON', journal_path=str(self.base / 'journals' / 'kingston' / 'verified.sqlite3'))

    def save(self, value=None, mode=0o600):
        self.path.write_text(json.dumps(self.value if value is None else value))
        self.path.chmod(mode)

    def test_missing_configuration_only_uses_legacy_default(self):
        self.assertEqual(read_target(self.path), dict(volume=Path('/Volumes/ADATA'), journal_path=None))
        self.save()
        self.assertEqual(read_target(self.path)['volume'], Path('/Volumes/KINGSTON'))

    def test_invalid_or_public_configuration_never_falls_back_to_adata(self):
        for value in ({}, [], {**self.value, 'extra': 1}, {**self.value, 'volume': '/'}):
            self.save(value)
            with self.assertRaises(TargetConfigError): read_target(self.path)
        self.save(mode=0o644)
        with self.assertRaises(TargetConfigError): read_target(self.path)
        self.save(); self.path.write_text('{broken')
        with self.assertRaises(TargetConfigError): read_target(self.path)

    def test_symlink_and_parent_traversal_are_refused(self):
        actual = self.base / 'actual.json'
        actual.write_text(json.dumps(self.value)); actual.chmod(0o600)
        self.path.symlink_to(actual)
        with self.assertRaises(OSError): read_target(self.path)
        for journal in ('relative.sqlite3', '/private/tmp/foreign.sqlite3', str(self.base / 'journals' / '..' / 'foreign.sqlite3')):
            with self.assertRaises(TargetConfigError): validate_target({**self.value, 'journal_path': journal}, self.base)

    def test_process_arguments_must_match_both_volume_and_journal(self):
        self.save()
        args = ['python3', 'authorize.py', '--volume', '/Volumes/KINGSTON', '--journal-path', self.value['journal_path']]
        self.assertTrue(arguments_match_target(args, self.path))
        self.assertFalse(arguments_match_target(args[:-2], self.path))
        self.assertFalse(arguments_match_target([*args[:3], '/Volumes/ADATA', *args[4:]], self.path))
        self.assertFalse(arguments_match_target([*args, '--volume', '/Volumes/ADATA'], self.path))
        equals = ['python3', 'authorize.py', '--volume=/Volumes/KINGSTON', '--journal-path=' + self.value['journal_path']]
        self.assertTrue(arguments_match_target(equals, self.path))


if __name__ == '__main__':
    unittest.main()
