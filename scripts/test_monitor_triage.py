"""Defensive regressions: course detections survive noise reduction and aggregation."""
import sys,json,tempfile,unittest,datetime as dt
from pathlib import Path
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).with_name('monitoring')))
from core import Store,canonical,now,classify
from bridge import send,grouped_rows,supporting_summary,risk_snapshot,render_report,report
from triage import needs_alert,group_key,alert_text

class TriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name));self.addCleanup(self.store.db.close)
        self.at=now()
    def event(self,identifier,kind='acl_allow',host='vm3',level=0):
        e=dict(id=identifier,timestamp=self.at,agent={'id':host,'name':host},manager={'name':'fixture'},
               rule={'id':'fixture','level':level},full_log='fixture')
        with self.store.db: eid=self.store.enqueue(e,canonical(e),'fixture',kind)
        return self.store.db.execute('select * from events where id=?',(eid,)).fetchone()
    def client(self):
        c=Mock(customer=1);c.alert.return_value=10;c.evidence.return_value=20;c.timeline.return_value=30
        return c
    def test_support_keeps_raw_and_stage_evidence_without_api_calls(self):
        for kind in ['acl_allow','sql_read','command_execution','vm3_cpu']:
            row=self.event(kind,kind);c=self.client();send(self.store,c,row)
            self.assertEqual(c.mock_calls,[])
            self.assertEqual(self.store.db.execute('select status from events where id=?',(row['id'],)).fetchone()[0],'evidence_only')
            self.assertTrue((self.store.root/'original'/row['raw_hash'][:2]/row['raw_hash']).exists())
        summary=supporting_summary(self.store,None,self.store.current()['id'])
        self.assertEqual(summary['count'],4)
        self.assertNotIn('stages',summary)
        self.assertTrue(self.store.coverage()['stages'][6]['observations']['sql_read'])
    def test_course_detection_signals_never_suppressed(self):
        for kind in ['web_request','ssh_login','discovery_process','acl_drop','sensitive_file_access',
                     'credential_tool','smb_access','git_execution','ssh_publickey','ssh_password',
                     'sudoedit_activity','privilege_identity','sensitive_config_access','sql_export',
                     'data_transfer','backup_login','backup_change','backup_integrity_failure',
                     'sql_change','application_sql_error','business_probe_failure','application_log_change']:
            with self.subTest(kind=kind):self.assertTrue(needs_alert({'event':{}},[kind]))
    def test_wazuh_detection_overrides_support_and_promotes_existing_event(self):
        row=self.event('one','sql_read');send(self.store,self.client(),row)
        e=json.loads(row['payload'])['event'];e['rule']['level']=12
        with self.store.db:self.store.enqueue(e,canonical(e),'alert-source','sql_read')
        changed=self.store.db.execute('select * from events where id=?',(row['id'],)).fetchone()
        self.assertEqual(changed['status'],'pending');c=self.client();send(self.store,c,changed)
        self.assertEqual(c.alert.call_count,1);self.assertEqual(c.alert.call_args.args[1]['alert_severity_id'],5)
    def test_repeat_same_behavior_one_alert_and_timeline_all_members_preserved(self):
        rows=[self.event(str(i),'backup_integrity_failure') for i in range(6)];c=self.client()
        for row in rows:send(self.store,c,row)
        self.assertEqual(c.alert.call_count,1);self.assertEqual(c.timeline.call_count,1)
        alert=c.alert.call_args.args[1];self.assertEqual(alert['alert_source_content']['group']['count'],6)
        self.assertIn('备份完整性校验失败',alert['alert_description']);self.assertIn('vm3',alert['alert_description'])
        self.assertEqual(self.store.db.execute('select count(*) from events where status="sent"').fetchone()[0],6)
    def test_host_time_run_and_behavior_do_not_merge(self):
        first=self.event('a','backup_change');second=self.event('b','backup_change','vm7')
        self.assertNotEqual(group_key(first),group_key(second))
        changed=dict(first);changed['event_time']=(dt.datetime.fromisoformat(first['event_time'])+dt.timedelta(minutes=6)).isoformat()
        self.assertNotEqual(group_key(first),group_key(changed))
        changed=dict(first);changed['run']='other';self.assertNotEqual(group_key(first),group_key(changed))
        third=self.event('c','sql_change');self.assertNotEqual(group_key(first),group_key(third))
    def test_later_member_updates_same_alert_reference(self):
        c=self.client();first=self.event('a','backup_change');send(self.store,c,first)
        second=self.event('b','backup_change');send(self.store,c,second)
        self.assertEqual(c.alert.call_args_list[0].args[0],c.alert.call_args_list[1].args[0])
        self.assertEqual(c.alert.call_args.args[1]['alert_source_content']['group']['count'],2)
    def test_later_wazuh_enrichment_keeps_existing_group_reference(self):
        c=self.client();row=self.event('a','backup_change');send(self.store,c,row)
        original=c.alert.call_args.args[0]
        e=json.loads(row['payload'])['event'];e['rule']={'id':'100511','level':12}
        with self.store.db:self.store.enqueue(e,canonical(e),'later-alert','backup_change')
        changed=self.store.db.execute('select * from events where id=?',(row['id'],)).fetchone()
        send(self.store,c,changed)
        self.assertEqual(c.alert.call_args.args[0],original)
        self.assertEqual(c.alert.call_args.args[1]['alert_severity_id'],5)

    def test_hex_audit_tool_detection_matches_course_steps(self):
        for tool,expected in [('nmap','discovery_process'),('john','credential_tool'),('git','git_execution')]:
            e={'agent':{'name':'group5-vm3'},'full_log':'type=EXECVE msg=audit(1:1): argc=1 a0='+tool.encode().hex()}
            kinds,_=classify(e);self.assertIn(expected,kinds);self.assertTrue(needs_alert({'event':e},kinds))
    def test_mixed_support_and_critical_is_alert(self):
        self.assertTrue(needs_alert({'event':{}},['sql_read','sql_export']))
        self.assertTrue(needs_alert({'event':{}},['vm3_cpu','credential_tool']))
        self.assertFalse(needs_alert({'event':{'data':{'cpu_percent':99}}},['vm3_cpu']))
        # CPU alone is a measurement, not proof of password cracking.

    def test_risk_report_orders_by_event_time_and_ignores_stage_markers(self):
        later=self.event('later','backup_change')
        earlier=self.event('earlier','sql_change')
        early=(dt.datetime.fromisoformat(self.at)-dt.timedelta(minutes=10)).isoformat()
        with self.store.db:
            self.store.db.execute('UPDATE events SET event_time=? WHERE id=?',(early,earlier['id']))
            self.store.db.execute('INSERT INTO markers VALUES(?,?,?,?)',(self.store.current()['id'],9,'start',self.at))
        self.event('routine','sql_read')
        snapshot=risk_snapshot(self.store)
        self.assertEqual([r['event_ids'][0] for r in snapshot['risk_events']],[earlier['id'],later['id']])
        self.assertNotIn('stages',snapshot);self.assertNotIn('stage_markers',snapshot)
        md,page=render_report(snapshot,{'agent_connection':{'disconnected':0},'remote_deployment':{}})
        for content in (md,page):
            self.assertNotIn('阶段',content)
            self.assertLess(content.index('数据库变更语句'),content.index('备份文件变化'))
        self.assertIn('<table>',page)

    def test_alert_title_has_no_planned_stage_or_inferred_result(self):
        row=self.event('risk','sudoedit_activity');c=self.client();send(self.store,c,row)
        alert=c.alert.call_args.args[1]
        self.assertNotIn('阶段',alert['alert_title']+alert['alert_description'])
        self.assertNotIn('攻击成功',alert['alert_title'])
        self.assertEqual(alert['alert_source_event_time'],row['event_time'])

    def test_unknown_host_wazuh_detection_is_retained_without_course_mapping(self):
        e={'id':'generic','timestamp':self.at,'agent':{'id':'77','name':'new-host'},'rule':{'id':'unmapped','level':10,'description':'Suspicious activity'}}
        with self.store.db:eid=self.store.enqueue(e,canonical(e),'wazuh')
        self.assertIsNotNone(eid)
        self.assertEqual(risk_snapshot(self.store)['risk_events'][0]['host'],'new-host')

    def test_report_does_not_generate_stage_tasks_and_escapes_html(self):
        from unittest.mock import patch
        self.event('x','backup_change','<script>alert(1)</script>');client=self.client()
        health={'agent_connection':{'disconnected':0},'remote_deployment':{}}
        with patch('bridge.status',return_value=health):result=report(self.store,client)
        client.tasks.assert_not_called()
        page=(Path(result['directory'])/'report-draft.html').read_text()
        self.assertNotIn('<script>',page);self.assertIn('&lt;script&gt;',page)

    def test_title_migration_preserves_analyst_disposition(self):
        from iris import Iris
        client=Iris.__new__(Iris)
        original={'alert_id':10,'alert_source_ref':'ref','alert_title':'阶段 6 | old','alert_source_content':{},
                  'alert_owner_id':None,'alert_status_id':5,'alert_resolution_status_id':4}
        client.request=Mock(side_effect=[{'alerts':[original]},{}])
        client.alert('ref',{'alert_title':'vm5 | sudoedit 权限操作','alert_source_content':{},'alert_status_id':2})
        update=client.request.call_args.args[1]
        self.assertNotIn('alert_status_id',update);self.assertNotIn('alert_resolution_status_id',update)
        self.assertEqual(update['alert_owner_id'],-1)

if __name__=='__main__':unittest.main()
