"""Durability, reconciliation, redaction and honest coverage regression tests."""
import datetime as dt
import gzip
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).with_name('monitoring')))
from core import Store,classify,canonical,now,redact,discover,sha
from iris import Iris,RemoteError
from bridge import deliver,add_attachment,send,summary_events


def event(identifier='one',role=7,**kwargs):
    return dict(id=identifier,timestamp=now(),agent={'id':str(role),'name':'group5-vm'+str(role)},
                manager={'name':'test-manager'},rule={'id':'100511'},full_log='backup-integrity-check status=FAILED',**kwargs)


class MonitoringTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.store=Store(self.root/'state')
        self.addCleanup(self.store.db.close)
        self.source=self.root/'alerts.json'

    def rows(self):return self.store.db.execute('SELECT * FROM events').fetchall()

    def test_case_reset_stays_empty_until_begin_and_skips_delayed_old_events(self):
        paused_run = self.store.current()['id']
        with self.store.db:
            self.store.db.execute('INSERT INTO metadata VALUES(?,?)', ('case_reset_waiting', paused_run))
        old = event('before-begin')
        self.assertTrue(self.store.waiting_for_begin())
        self.assertIsNone(self.store.enqueue(old, canonical(old), 'fixture'))
        client = Mock()
        deliver(self.store, client)
        self.assertEqual(client.mock_calls, [])
        self.store.begin('new exercise')
        self.assertFalse(self.store.waiting_for_begin())
        self.assertIsNone(self.store.enqueue(old, canonical(old), 'delayed-source'))
        new = event('after-begin')
        self.assertIsNotNone(self.store.enqueue(new, canonical(new), 'fixture'))
        self.assertEqual(len(self.rows()), 1)

    def test_partial_line_is_held_until_complete(self):
        blob=canonical(event());self.source.write_bytes(blob[:30])
        self.store.ingest(self.source);self.assertEqual(len(self.rows()),0)
        with self.source.open('ab') as f:f.write(blob[30:]+b'\n')
        self.store.ingest(self.source);self.assertEqual(len(self.rows()),1)

    def test_batch_limit_does_not_skip_unread_lines(self):
        self.source.write_bytes(b''.join(canonical(event(str(i)))+b'\n' for i in range(3)))
        for _ in range(3):self.store.ingest(self.source,limit=1)
        self.assertEqual(len(self.rows()),3)

    def test_oversize_line_does_not_starve_following_event(self):
        self.source.write_bytes(b'x'*2000+b'\n'+canonical(event())+b'\n')
        with patch('core.MAX_LINE',512):self.store.ingest(self.source)
        self.assertEqual(len(self.rows()),1)

    def test_new_decoding_enriches_sent_event_and_queues_revision(self):
        item=event();self.source.write_bytes(canonical(item)+b'\n');self.store.ingest(self.source)
        self.store.db.execute('UPDATE events SET status="sent"');self.store.db.commit()
        item['full_log']+=' audit type=PATH /lab_backup/TEST nametype=DELETE'
        other=self.root/'archives.json';other.write_bytes(canonical(item)+b'\n');self.store.ingest(other)
        row=self.rows()[0]
        self.assertEqual(row['status'],'pending')
        self.assertEqual(json.loads(row['payload'])['revision'],2)
        self.assertIn('backup_change',json.loads(row['kinds']))

    def test_repeated_and_cross_source_ids_deduplicated(self):
        blob=canonical(event())+b'\n';self.source.write_bytes(blob*2)
        other=self.root/'archives.json';other.write_bytes(blob)
        self.store.ingest(self.source);self.store.ingest(other)
        self.assertEqual(len(self.rows()),1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM provenance').fetchone()[0],2)

    def test_alert_fields_enrich_archive_even_when_kinds_unchanged(self):
        item=event();archive=dict(item);archive.pop('rule')
        with self.store.db:self.store.enqueue(archive,canonical(archive),'archives')
        self.store.db.execute('UPDATE events SET status="sent"');self.store.db.commit()
        with self.store.db:self.store.enqueue(item,canonical(item),'alerts')
        row=self.rows()[0]
        self.assertEqual(row['status'],'pending')
        self.assertEqual(json.loads(row['payload'])['event']['rule']['id'],'100511')

    def test_rename_and_copytruncate(self):
        self.source.write_bytes(canonical(event('a'))+b'\n');self.store.ingest(self.source)
        moved=self.root/'alerts.json.1';self.source.rename(moved)
        self.source.write_bytes(canonical(event('b'))+b'\n')
        for path in discover([self.root]):self.store.ingest(path)
        self.source.write_bytes(canonical(event('c'))+b'\n');self.store.ingest(self.source)
        self.assertEqual(len(self.rows()),3)

    def test_gzip_recovery(self):
        path=self.root/'old.json.gz'
        with gzip.open(path,'wb') as f:f.write(canonical(event())+b'\n')
        self.store.ingest(path);self.store.ingest(path)
        self.assertEqual(len(self.rows()),1)

    def test_sqlite_transaction_rolls_back_cursor_with_event(self):
        self.source.write_bytes(canonical(event())+b'\n')
        original=self.store.enqueue
        def failing(*a,**k):original(*a,**k);raise RuntimeError('crash fixture')
        with patch.object(self.store,'enqueue',side_effect=failing),self.assertRaises(RuntimeError):self.store.ingest(self.source)
        self.assertEqual(len(self.rows()),0)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM cursors').fetchone()[0],0)
        self.store.ingest(self.source);self.assertEqual(len(self.rows()),1)

    def test_invalid_json_does_not_block_valid_records(self):
        self.source.write_bytes(b'broken\n'+canonical(event())+b'\n')
        self.store.ingest(self.source)
        self.assertEqual(len(self.rows()),1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM issues').fetchone()[0],1)

    def test_selftests_do_not_satisfy_real_stage_coverage(self):
        item=event(full_log_override='unused')
        item['full_log']='TEST_SELFTEST';self.source.write_bytes(canonical(item)+b'\n')
        self.store.ingest(self.source);coverage=self.store.coverage()
        self.assertEqual(coverage['selftest_events'],1)
        self.assertTrue(all(stage['state']=='pending' for stage in coverage['stages']))

    def test_samba_selftest_keeps_its_real_category(self):
        item=event(role=4);item['rule']={};item['full_log']='smbd_audit release_share|read|TEST_SELFTEST canary'
        kinds,test=classify(item)
        self.assertTrue(test)
        self.assertIn('smb_access',kinds)
        self.assertNotIn('backup_integrity_failure',kinds)

    def test_reversible_table_fault_is_a_change_and_stays_selftest(self):
        item=event(role=6);item['rule']={}
        item['full_log']='mysql lab-general.log Query RENAME TABLE lab_orders TO TEST_SELFTEST_orders'
        kinds,is_test=classify(item)
        self.assertTrue(is_test)
        self.assertIn('sql_change',kinds)
        item['full_log']="mysql lab-general.log Query SELECT 'RENAME TABLE TEST_SELFTEST_orders'"
        self.assertNotIn('sql_change',classify(item)[0])

    def test_routine_monitoring_queries_are_not_course_data_reads(self):
        item=event(role=6);item['rule']={}
        for query in ["SELECT @@version", "SELECT * FROM performance_schema.global_status", "SELECT * FROM group5_verify_abc.lab_orders"]:
            item['full_log']='mysql lab-general.log Query '+query
            self.assertNotIn('sql_read',classify(item)[0])
        item['full_log']='mysql lab-general.log Query SELECT * FROM `lab_business`.`lab_orders`'
        self.assertIn('sql_read',classify(item)[0])

    def test_monitoring_acl_and_management_logins_do_not_fill_attack_stages(self):
        item=event(role=2);item['rule']={}
        item['full_log']='VM2-ACL ALLOW SRC=192.168.50.11 DST=192.168.31.30 DPT=80'
        self.assertNotIn('acl_allow',classify(item)[0])
        item['full_log']='VM2-ACL ALLOW SRC=192.168.33.15 DST=192.168.31.30 DPT=80'
        self.assertIn('acl_allow',classify(item)[0])
        item=event(role=3);item['rule']={};item['full_log']='Accepted password for empuser from 192.168.34.5'
        self.assertNotIn('ssh_login',classify(item)[0])
        item['full_log']='Accepted password for dev_zhang from 192.168.34.5'
        self.assertIn('ssh_login',classify(item)[0])

    def test_sudo_management_identity_is_distinct_from_course_user(self):
        item=event(role=5,data={'audit':{'auid':'1000','euid':'0'}});item['rule']={};item['full_log']='audit syscall=59'
        self.assertNotIn('privilege_identity',classify(item)[0])
        item['data']['audit']['auid']='1001'
        self.assertIn('privilege_identity',classify(item)[0])

    def test_old_and_naive_timestamps_do_not_become_current_evidence(self):
        for value in ['2020-01-01T00:00:00+00:00','2026-11-02T00:00:00']:
            item=event();item['timestamp']=value
            self.source.write_bytes(canonical(item)+b'\n');self.store.ingest(self.source)
        self.assertEqual(len(self.rows()),0)

    def test_no_automatic_confirmed_verdict(self):
        self.source.write_bytes(canonical(event())+b'\n');self.store.ingest(self.source)
        stage=self.store.coverage()['stages'][7]
        self.assertEqual(stage['state'],'partial')
        self.assertIsNone(stage['analyst_confirmation'])

    def test_metadata_cannot_claim_arbitrary_stages(self):
        item=event(role=3,data={'group5':{'kind':'offline_backup_verification'}})
        item['rule']={};item['full_log']='unrelated'
        self.assertNotIn('offline_backup_verification',classify(item)[0])

    def test_stage_classifier_samples(self):
        samples=[(1,'POST /login HTTP/1.1','web_request'),(3,'Accepted password for user','ssh_login'),
          (3,'audit EXECVE nmap','discovery_process'),(3,'audit type=PATH course-phase04','sensitive_file_access'),
          (4,'smbd_audit release_share|read','smb_access'),(5,'audit EXECVE sudoedit','sudoedit_activity'),
          (6,'mysql lab-general.log Query SELECT * FROM lab_orders','sql_read'),
          (7,'audit type=PATH /lab_backup/TEST nametype=DELETE','backup_change'),(5,'pymysql.err SQL error','application_sql_error'),
          (5,'audit type=PATH /var/log/group5-drill/TEST_application.log nametype=CREATE','application_log_change')]
        for role,text,kind in samples:
            with self.subTest(kind=kind):
                item=event(role=role);item['rule']={};item['full_log']=text
                self.assertIn(kind,classify(item)[0])

    def test_read_only_arguments_and_sql_literals_are_not_changes(self):
        samples=[(7,'audit EXECVE sha256sum /lab_backup/TEST','backup_change'),
                 (5,'audit EXECVE cat /var/log/group5-drill/TEST_application.log','application_log_change'),
                 (6,"mysql lab-general.log Query SELECT 'drop update delete'",'sql_change')]
        for role,text,kind in samples:
            item=event(role=role);item['rule']={};item['full_log']=text
            self.assertNotIn(kind,classify(item)[0])

    def test_secret_redaction_and_original_retention(self):
        secret='fixture-private-token'
        self.assertNotIn(secret,json.dumps(redact({'password':secret,'full_log':'token='+secret},[secret])))
        self.assertNotIn('abc',redact('-----BEGIN RSA PRIVATE KEY-----abc-----END RSA PRIVATE KEY-----'))

    def test_secret_attachment_and_symlink_rejected(self):
        path=self.root/'passwords.txt';path.write_text('fixture')
        with self.assertRaises(ValueError):add_attachment(self.store,path,'mail_sample',now(),'fixture')
        link=self.root/'sample.txt';link.symlink_to(path)
        with self.assertRaises(OSError):add_attachment(self.store,link,'mail_sample',now(),'fixture')

    def test_post_uncertainty_reconciles_before_second_create(self):
        client=Iris.__new__(Iris);created=[]
        def request(path,data=None):
            if path.startswith('alerts/filter'):return {'alerts':created}
            created.append({'alert_id':17,'alert_source_ref':'unique-ref'})
            raise RemoteError('response_lost')
        client.request=Mock(side_effect=request)
        with self.assertRaises(RemoteError):client.alert('unique-ref',{})
        self.assertEqual(client.alert('unique-ref',{}),17)
        self.assertEqual(sum(call.args[0]=='alerts/add' for call in client.request.call_args_list),1)

    def test_evidence_batch_cache_reconciles_uncertain_upload(self):
        client=Iris.__new__(Iris);client.cid=2
        created=[];contents={};lose=[True]
        def request(path,data=None,files=None,raw=False):
            if path.startswith('datastore/list/tree'):
                return {'d-1':{'name':'Evidences','files':list(created)}}
            if path.startswith('datastore/file/add'):
                name,blob=files['file_content'];identifier=len(created)+1
                item={'file_id':identifier,'file_original_name':name,'file_sha256':sha(blob)}
                created.append(item);contents[identifier]=blob
                if lose[0]:lose[0]=False;raise RemoteError('response_lost')
                return item
            if path.startswith('datastore/file/view'):return contents[int(path.split('/')[-1].split('?')[0])]
            self.fail(path)
        client.request=Mock(side_effect=request)
        with self.assertRaises(RemoteError):client.evidence('one.json',b'one','fixture')
        self.assertEqual(client.evidence('one.json',b'one','fixture'),1)
        self.assertEqual(client.evidence('two.json',b'two','fixture'),2)
        self.assertEqual(client.evidence('two.json',b'two','fixture'),2)
        self.assertEqual(len(created),2)
        self.assertEqual(sum(c.args[0].startswith('datastore/list/tree') for c in client.request.call_args_list),2)

    def test_timeline_batch_cache_reconciles_uncertain_create(self):
        client=Iris.__new__(Iris);client.cid=2;entries=[];lose=[True]
        def request(path,data=None):
            if '/list?' in path:return {'timeline':list(entries)}
            item=dict(data,event_id=len(entries)+1);entries.append(item)
            if lose[0]:lose[0]=False;raise RemoteError('response_lost')
            return item
        client.request=Mock(side_effect=request)
        with self.assertRaises(RemoteError):client.timeline('[one]',{'event_title':'[one] event'})
        self.assertEqual(client.timeline('[one]',{'event_title':'[one] event'}),1)
        self.assertEqual(client.timeline('[two]',{'event_title':'[two] event'}),2)
        self.assertEqual(client.timeline('[two]',{'event_title':'[two] event'}),2)
        self.assertEqual(len(entries),2)

    def test_stale_pending_row_is_not_delivered_twice(self):
        item=event();self.source.write_bytes(canonical(item)+b'\n');self.store.ingest(self.source)
        stale=self.rows()[0]
        with self.store.db:self.store.db.execute('UPDATE events SET status="sent"')
        client=Mock();send(self.store,client,stale)
        client.alert.assert_not_called()

    def test_current_incident_evidence_precedes_routine_backfill(self):
        routine=event('routine',role=3);routine['rule']={};routine['full_log']='audit EXECVE id'
        critical=event('critical')
        with self.store.db:
            first=self.store.enqueue(routine,canonical(routine),'fixture')
            second=self.store.enqueue(critical,canonical(critical),'fixture')
        seen=[]
        with patch('bridge.send',side_effect=lambda store,client,row:seen.append(row['id'])):
            deliver(self.store,Mock())
        self.assertEqual(seen,[second,first])

    def test_manual_confirmation_does_not_hide_missing_evidence(self):
        run=self.store.current()['id']
        with self.store.db:self.store.db.execute('INSERT INTO confirmations VALUES(?,?,?,?,?)',(run,1,'fixture','manual note',now()))
        stage=self.store.coverage()['stages'][0]
        self.assertEqual(stage['analyst_state'],'confirmed')
        self.assertEqual(stage['state'],'pending')
        self.assertTrue(stage['missing'])

    def test_retries_persist_and_nonretryable_failures_are_visible(self):
        self.source.write_bytes(canonical(event())+b'\n');self.store.ingest(self.source)
        with patch('bridge.send',side_effect=RemoteError('http_503')):deliver(self.store,Mock())
        row=self.rows()[0];self.assertEqual(row['attempts'],1);self.assertEqual(row['status'],'pending')
        self.store.db.execute('UPDATE events SET next_try=0');self.store.db.commit()
        with patch('bridge.send',side_effect=RemoteError('invalid_payload',False)):deliver(self.store,Mock())
        self.assertEqual(self.rows()[0]['status'],'blocked')

    def test_worker_restart_preserves_queue(self):
        self.source.write_bytes(canonical(event())+b'\n');self.store.ingest(self.source)
        restarted=Store(self.store.root);self.addCleanup(restarted.db.close)
        self.assertEqual(restarted.db.execute('SELECT count(*) FROM events').fetchone()[0],1)
        self.assertEqual(restarted.current()['id'],self.store.current()['id'])

    def test_snapshot_must_be_verified_and_preserved_before_change(self):
        original='classroom application log\n'
        snapshot=event('snapshot',role=5,data={'group5':{'kind':'application_log_snapshot'},
                       'snapshot_text':original,'snapshot_sha256':sha(original.encode())})
        snapshot['rule']={};snapshot['full_log']='application snapshot'
        with self.store.db:self.store.enqueue(snapshot,canonical(snapshot),'fixture')
        changed=event('changed',role=5,data={'group5':{'kind':'log_hash_comparison'},'before_sha256':sha(original.encode())})
        changed['rule']={};changed['full_log']='hash comparison'
        with self.store.db:eid=self.store.enqueue(changed,canonical(changed),'fixture')
        row=self.store.db.execute('SELECT * FROM events WHERE id=?',(eid,)).fetchone()
        self.assertIn('central_original_preserved',json.loads(row['kinds']))
        changed['id']='older';changed['timestamp']=snapshot['timestamp']
        with self.store.db:eid=self.store.enqueue(changed,canonical(changed),'fixture')
        row=self.store.db.execute('SELECT * FROM events WHERE id=?',(eid,)).fetchone()
        self.assertNotIn('central_original_preserved',json.loads(row['kinds']))

    def test_hash_change_requires_two_distinct_valid_digests(self):
        item=event(role=5,data={'group5':{'kind':'log_hash_comparison'},'before_sha256':'a'*64,'after_sha256':'b'*64})
        item['rule']={};item['full_log']='read-only comparison'
        self.assertIn('application_log_change',classify(item)[0])
        item['data']['after_sha256']='a'*64
        self.assertNotIn('application_log_change',classify(item)[0])

    def test_enrichment_during_send_remains_pending(self):
        item=event();self.source.write_bytes(canonical(item)+b'\n');self.store.ingest(self.source)
        stale=self.rows()[0];client=Mock();client.customer=2
        client.alert.return_value=17;client.evidence.return_value=18
        def enrich(*args):
            updated=dict(item,full_log=item['full_log']+' audit type=PATH /lab_backup/TEST nametype=DELETE')
            with self.store.db:self.store.enqueue(updated,canonical(updated),'second-source')
            return 99
        client.timeline.side_effect=enrich
        send(self.store,client,stale)
        row=self.rows()[0]
        self.assertEqual(row['status'],'pending')
        self.assertEqual(json.loads(row['payload'])['revision'],2)

    def test_new_run_does_not_reuse_previous_coverage(self):
        with self.store.db:self.store.enqueue(event(),canonical(event()),'fixture')
        previous=self.store.current()['id']
        self.assertEqual(self.store.coverage()['stages'][7]['state'],'partial')
        current=self.store.begin('next classroom run')
        self.assertNotEqual(previous,current)
        self.assertTrue(all(s['state']=='pending' for s in self.store.coverage()['stages']))
        self.assertEqual(self.store.coverage(previous)['run']['state'],'finished')

    def test_word_summary_bounds_references_and_keeps_total_counts(self):
        from bridge import risk_snapshot
        coverage=risk_snapshot(self.store)
        coverage['risk_events']=[{'event_time':now(),'event_ids':['event-'+str(i)]} for i in range(1000)]
        snapshots=summary_events(coverage,2)
        self.assertEqual(len(snapshots),100)
        detail=json.loads(snapshots[0]['event_raw'])
        self.assertEqual(sum(len(json.loads(s['event_raw'])['risk_events']) for s in snapshots),1000)
        self.assertEqual(detail['source_case_id'],2)
        self.assertEqual(len(coverage['risk_events']),1000)

    def test_word_summary_never_promotes_coverage_to_compromise(self):
        from bridge import risk_snapshot
        with self.store.db:self.store.enqueue(event(),canonical(event()),'fixture')
        snapshots=summary_events(risk_snapshot(self.store),2)
        self.assertTrue(snapshots)
        for item in snapshots:
            detail=json.loads(item['event_raw'])
            self.assertNotIn('stage',detail)
            self.assertIn('待核实',detail['risk_events'][0]['description'])


if __name__=='__main__':unittest.main()
