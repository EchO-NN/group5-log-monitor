import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).with_name('monitoring')))
from core import Store,canonical,now
import collected_evidence as collected

class CollectedEvidenceTests(unittest.TestCase):
    def test_database_operations_preserve_objects_but_exclude_literals(self):
        e={'full_log':'2026-11-04T19:27:45.519004Z\t 1 Query\tRENAME TABLE lab_orders TO held_orders, lab_tickets TO held_tickets'}
        r=collected.parse('database_changes',e,now())
        self.assertEqual(r['operation'],'RENAME TABLE');self.assertEqual(r['renames'][1],{'from':'lab_tickets','to':'held_tickets'})
        e={'full_log':"1 Query UPDATE lab_orders SET password='SECRET' WHERE id=1"}
        r=collected.parse('database_changes',e,now());self.assertEqual(r['object'],'lab_orders');self.assertNotIn('SECRET',json.dumps(r))
        self.assertIsNone(collected.parse('database_changes',{'full_log':"1 Query SELECT password FROM users"},now()))
    def test_application_errors_keep_table_identifier_without_arbitrary_message(self):
        e={'full_log':'''pymysql.err.ProgrammingError: (1146, "Table 'lab_db.lab_orders' doesn't exist") password=SECRET'''}
        r=collected.parse('application_errors',e,now());self.assertEqual(r['table'],'lab_db.lab_orders');self.assertEqual(r['error_code'],1146);self.assertNotIn('SECRET',json.dumps(r))
    def test_missing_http_status_does_not_become_fabricated_500(self):
        e={'data':{'endpoint':'orders','group5':{'kind':'business_probe_failure'},'http_status':None}}
        r=collected.parse('business_probes',e,now());self.assertEqual(r['outcome'],'failure');self.assertIsNone(r['http_status'])
    def test_query_is_scoped_and_deduplicates_two_captures(self):
        with tempfile.TemporaryDirectory() as d:
            s=Store(d);s.begin('test',case_id=2);rid=s.current()['id'];at=now()
            for n in range(2):
                e={'id':str(n),'timestamp':at,'agent':{'name':'group5-vm6'},'location':'/var/log/mysql/lab-general.log','full_log':at+'\t 1 Query\tRENAME TABLE lab_orders TO held_orders'}
                with s.db:s.enqueue(e,canonical(e),'test')
            request={'role':6,'query':'database_changes','start':'2020-01-01T00:00:00+00:00','end':'2030-01-01T00:00:00+00:00','match':''}
            r=collected.query(s,rid,request);self.assertEqual(len(r['records']),1);self.assertEqual(r['duplicate_captures_merged'],1);self.assertFalse(r['truncated'])
            self.assertEqual(len(r['records'][0]['source_event_ids']),2)
            self.assertEqual(collected.catalog(s,rid)[0]['saved_records'],2)
            self.assertFalse(collected.query(s,'another-run',request)['records'])
            with self.assertRaises(ValueError):collected.query(s,rid,dict(request,role=5))
            s.db.close()

if __name__=='__main__':unittest.main()
