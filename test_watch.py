import json
import os
from pathlib import Path
import tempfile
import unittest
import watch


class WatchTests(unittest.TestCase):
    def test_retry_summary_keeps_previous_verified_and_distinguishes_pending_errors(self):
        p={'phase':'downloading','workers':128,'retry_only_failed':True,'files_total':100,
           'files_verified':2,'bytes_verified':10**9,'bytes_total':10**10,
           'files_failed_count':98,'files_pending_count':93,'active_transfers':{}}
        r={'previous_verified':{'files_verified':200,'bytes_verified':20*10**9}}
        text=watch.summary(p,r)
        self.assertIn('202 файлов, 21.00 ГБ',text)
        self.assertIn('неудачных: 5',text)
        self.assertIn('В этой очереди проверено: 2/100',text)

    def test_rates_use_real_elapsed_and_ignore_failed_and_removed_transfers(self):
        old={'bytes_verified':0,'active_transfers':{'a':{'stage':'reading','bytes_written':10**6},'gone':{'bytes_written':9*10**6}}}
        new={'bytes_verified':2*10**6,'active_transfers':{'a':{'stage':'reading','bytes_written':5*10**6},'b':{'stage':'reading','bytes_written':2*10**6},'bad':{'stage':'retrying','bytes_written':99*10**6}}}
        self.assertEqual(watch.rates(old,new,2),(1,3))
        self.assertEqual(watch.rates(old,new,2,False),(None,None))

    def test_terminal_controls_and_urls_are_not_rendered(self):
        row=watch.transfer_line('a',{'stage':'reading','bytes_written':1,'url':'https://invalid/?token=SECRET','host':'SECRET'},
                                {'a':('name\x1b]52;c;SECRET\x07\nfile',100)})
        self.assertNotIn('\x1b',row)
        self.assertNotIn('\x07',row)
        self.assertNotIn('\n',row)
        self.assertNotIn('https://',row)
        self.assertNotIn('token=',row)

    def test_private_json_reader_rejects_symlinks_and_world_readable_files(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'p.json';file.write_text(json.dumps({'phase':'downloading'}));file.chmod(0o600)
            self.assertEqual(watch.read_json(file)['phase'],'downloading')
            link=Path(folder)/'link';link.symlink_to(file)
            with self.assertRaises(OSError):watch.read_json(link)
            file.chmod(0o644)
            with self.assertRaises(ValueError):watch.read_json(file)


if __name__=='__main__':
    unittest.main()
