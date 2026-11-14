import datetime as dt
import gzip
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).with_name('monitoring')))
import agent_query_guest as guest


class AuditPageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.patcher=patch.object(guest,'AUDIT_ROOT',self.root);self.patcher.start();self.addCleanup(self.patcher.stop)
        self.request=dict(role=7,query='audit',start='2026-11-04T19:26:00+00:00',end='2026-11-04T19:29:00+00:00',match='')
        self.at=dt.datetime(2026,11,4,19,27,tzinfo=dt.timezone.utc).timestamp()

    def lines(self,start,end):
        return b''.join(f'type=PATH msg=audit({self.at}:{n}): name="/lab_backup/item{n}" uid=0\n'.encode() for n in range(start,end))

    def all_pages(self,request=None):
        request=dict(request or self.request);pages=[]
        while True:
            page=guest.run(request);pages.append(page)
            self.assertTrue(page['ok']);self.assertLessEqual(len(page['records']),80)
            if not page['has_more']:return pages
            self.assertLess(len(pages),100)
            request['cursor']=page['continuation']

    def test_all_213_records_across_plain_and_compressed_rotation_without_overlap(self):
        (self.root/'audit.log.2.gz').write_bytes(gzip.compress(self.lines(0,71)))
        (self.root/'audit.log.1').write_bytes(self.lines(71,142))
        (self.root/'audit.log').write_bytes(self.lines(142,213))
        pages=self.all_pages();records=[r for p in pages for r in p['records']]
        self.assertEqual([len(p['records']) for p in pages],[80,80,53])
        self.assertEqual([r['audit_id'] for r in records],list(map(str,range(213))))
        self.assertTrue(pages[-1]['coverage_complete']);self.assertFalse(pages[-1]['truncated'])
        self.assertEqual(pages[-1]['records_seen'],213)

    def test_exact_80_can_finish_with_empty_terminal_page(self):
        (self.root/'audit.log').write_bytes(self.lines(0,80))
        pages=self.all_pages()
        self.assertEqual([len(p['records']) for p in pages],[80,0])
        self.assertTrue(pages[-1]['coverage_complete'])

    def test_window_before_last_four_megabytes_is_not_omitted(self):
        (self.root/'audit.log').write_bytes(self.lines(1,2)+b'older unrelated text\n'*250000)
        pages=self.all_pages()
        self.assertEqual([r['audit_id'] for p in pages for r in p['records']],['1'])

    def test_empty_scan_batch_requires_continuation(self):
        (self.root/'audit.log').write_bytes(b'unrelated\n'*30+self.lines(1,2))
        with patch.object(guest,'AUDIT_SCAN_BYTES',100):pages=self.all_pages()
        self.assertEqual(pages[0]['records'],[]);self.assertTrue(pages[0]['has_more'])
        self.assertEqual([r['audit_id'] for p in pages for r in p['records']],['1'])

    def test_appends_and_rename_rotation_do_not_duplicate_or_extend_snapshot(self):
        active=self.root/'audit.log';active.write_bytes(self.lines(0,81))
        first=guest.run(self.request)
        with active.open('ab') as stream:stream.write(self.lines(81,90))
        active.rename(self.root/'audit.log.1');active.write_bytes(self.lines(90,95))
        tail=self.all_pages(dict(self.request,cursor=first['continuation']))
        self.assertEqual([r['audit_id'] for p in tail for r in p['records']],['80'])
        self.assertTrue(tail[-1]['coverage_complete'])

    def test_removed_snapshot_and_symlinks_report_incomplete(self):
        active=self.root/'audit.log';active.write_bytes(self.lines(0,81))
        first=guest.run(self.request);active.rename(self.root/'unavailable')
        last=guest.run(dict(self.request,cursor=first['continuation']))
        self.assertFalse(last['ok']);self.assertFalse(last['coverage_complete'])
        active.symlink_to(self.root/'unavailable')
        self.assertFalse(guest.run(self.request)['ok'])

    def test_cursor_cannot_change_scope_or_filename(self):
        (self.root/'audit.log').write_bytes(self.lines(0,81))
        cursor=guest.run(self.request)['continuation']
        with self.assertRaises(ValueError):guest.run(dict(self.request,match='other',cursor=cursor))
        cursor['files'][0]['name']='../../etc/shadow'
        with self.assertRaises(ValueError):guest.run(dict(self.request,cursor=cursor))

    def test_oversized_line_and_withheld_types_do_not_hide_later_records(self):
        raw=b'x'*70000+b'\n'+f'type=EXECVE msg=audit({self.at}:500): a0="SENSITIVE"\n'.encode()+self.lines(1,3)
        (self.root/'audit.log').write_bytes(raw)
        pages=self.all_pages()
        self.assertEqual([r['audit_id'] for p in pages for r in p['records']],['1','2'])
        self.assertEqual(pages[-1]['skipped_long_lines'],1);self.assertFalse(pages[-1]['coverage_complete'])


if __name__=='__main__':unittest.main()
