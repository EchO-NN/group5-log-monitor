import copy
import hashlib
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).with_name('monitoring')))
from core import Store,now,canonical
from bridge import send,report
from case_runs import INITIAL_BLOCK
import fact_alerts
import investigation as inv
import summary_jobs as jobs
import case_writer


def result_for(data):
    refs=[o['reference'] for o in data['observations']]
    first=data['observations'][0] if refs else None
    return dict(overview='中文告警概况',observations=[{'text':'观察到规则命中','references':refs}] if refs else [],
        assessment='需要结合实际记录研判，未确认攻击成功',gaps=['缺少上下文'],next_steps=['人工核实'],
        timeline=[{'at':first['first_seen'],'title':'观察到告警','content':'日志记录发生变化','references':refs}] if refs else [],
        tasks=[{'title':'核查相关活动','description':'核对操作是否获得授权','references':refs}],
        assets=[{'host':first['host'],'description':'告警涉及的主机','references':refs}] if refs else [],
        notes=[{'title':'调查说明','content':'记录事实和证据边界','references':refs}],
        evidence=[{'title':'本轮告警证据','description':'实际告警记录和引用','references':refs}] if refs else [])


class PostFinishTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.store=Store(tmp.name);self.addCleanup(self.store.db.close)
        self.store.presentation_mode='post_finish';self.store.default_case_id=5;self.store.summary_enabled=True
        self.store.analysis_settle_seconds=0;self.store.analysis_drain_seconds=300
        self.rid=self.store.begin('不能发给模型的预设阶段秘密',case_id=5)
        self.client=Mock(cid=5,customer=2,config={"wazuh_url":"https://wazuh.example.invalid"});self.client.alert.return_value=80

    def event(self,rule='100511',level=12,**extra):
        return dict(id='event-'+rule,timestamp=now(),agent={'id':'7','name':'vm7-backup-srv','ip':'192.168.29.50'},
                    rule={'id':rule,'level':level,'description':'Integrity check failed'},full_log='backup-integrity-check status=FAILED',**extra)

    def deliver(self,event=None):
        event=event or self.event()
        with self.store.db:eid=self.store.enqueue(event,canonical(event),'fixture')
        row=self.store.db.execute('SELECT * FROM events WHERE id=?',(eid,)).fetchone()
        send(self.store,self.client,row);return row

    def ready(self):
        self.deliver();inv.finish(self.store);return jobs.claim(self.store)

    def test_fixed_alert_has_no_stage_or_analysis_and_no_case_mutations(self):
        self.deliver();payload=self.client.alert.call_args.args[1]
        self.assertNotIn('阶段',payload['alert_title']);self.assertNotIn('判断状态',payload['alert_description'])
        self.assertNotIn('observed_kinds',json.dumps(payload));self.assertNotIn('candidate',json.dumps(payload))
        self.assertEqual(payload['alert_source_content']['schema'],'wazuh-facts-v1')
        self.assertEqual(payload['alert_source_content']['records'][0]['level'],12)
        self.client.merge.assert_not_called();self.client.timeline.assert_not_called();self.client.evidence.assert_not_called()

    def test_running_report_and_summary_do_not_call_model_or_write_case(self):
        self.deliver();self.client.reset_mock()
        with patch('bridge.status',return_value={'agent_connection':{'disconnected':0},'remote_deployment':{}}):
            result=report(self.store,self.client,summary_retry=True)
        self.assertEqual(result['summary']['state'],'waiting_for_finish')
        self.client.request.assert_not_called();self.client.evidence.assert_not_called();self.client.timeline.assert_not_called();self.assertIsNone(jobs.claim(self.store))

    def test_auto_closed_run_does_not_authorize_analysis(self):
        self.deliver();self.store.begin('another',case_id=6)
        self.assertEqual(self.store.db.execute('SELECT state FROM runs WHERE id=?',(self.rid,)).fetchone()[0],'finished')
        self.assertIsNone(jobs.claim(self.store))

    def test_finish_has_no_prior_plan_and_retry_keeps_cutoff(self):
        job=self.ready();end=self.store.current()['end'];inv.finish(self.store)
        self.assertEqual(end,self.store.current()['end'])
        data=job['payload'];serialized=json.dumps(data,ensure_ascii=False)
        self.assertNotIn('不能发给模型',serialized);self.assertNotIn('preset_stage',serialized)
        self.assertNotIn('classroom',serialized);self.assertEqual(data['case_id'],5)
        self.assertEqual(len(data['observations']),1);inv.validate(result_for(data),data)

    def test_settle_and_pending_delivery_gate(self):
        self.deliver();self.store.analysis_settle_seconds=60;inv.finish(self.store)
        self.assertIsNone(jobs.claim(self.store))
        self.store.analysis_settle_seconds=0
        with self.store.db:self.store.db.execute('UPDATE events SET status="pending"')
        self.assertIsNone(jobs.claim(self.store))
        self.store.analysis_drain_seconds=0
        job=jobs.claim(self.store);self.assertEqual(job['payload']['queue']['pending'],1)

    def test_empty_finished_run_has_chinese_scope_note_not_invented_events(self):
        inv.finish(self.store);job=jobs.claim(self.store)
        self.assertEqual(job['payload']['observations'],[])
        inv.validate(result_for(job['payload']),job['payload'])

    def test_fresh_revision_preserves_old_job_and_uses_new_durable_identity(self):
        original=self.ready();old=jobs.read(self.store,'summary_job:'+original['id']);old['state']='done'
        with self.store.db:jobs.write(self.store,'summary_job:'+old['id'],old)
        result=inv.request_revision(self.store,self.rid,'基于原始证据重新独立调查。',{'max_steps':64})
        self.assertNotEqual(result['job_id'],old['id'])
        self.assertEqual(jobs.read(self.store,'summary_job:'+old['id'])['state'],'done')
        self.assertFalse(inv.publish_current(self.store,old))
        fresh=jobs.claim(self.store);self.assertEqual(fresh['id'],result['job_id'])
        saved=jobs.read(self.store,'summary_job:'+fresh['id'])
        self.assertTrue(inv.publish_current(self.store,saved))
        self.assertEqual(saved['agent_limits']['max_steps'],64)
        self.assertEqual(saved['revision_request'],'基于原始证据重新独立调查。')
        self.assertEqual(inv.schedule(self.store,self.rid)['job_id'],fresh['id'])
        inv.finish(self.store)
        self.assertEqual(inv.schedule(self.store,self.rid)['job_id'],fresh['id'])

    def test_revision_does_not_interrupt_active_generation(self):
        job=self.ready()
        with self.assertRaisesRegex(ValueError,'still active'):inv.request_revision(self.store,self.rid,'重新分析')
        self.assertEqual(jobs.read(self.store,'summary_requested:'+self.rid),job['id'])

    def test_revision_rejects_unfinished_runs_and_invalid_budgets(self):
        with self.assertRaises(ValueError):inv.request_revision(self.store,self.rid,'重新分析')
        inv.finish(self.store)
        with self.assertRaises(ValueError):inv.request_revision(self.store,self.rid,'重新分析',{'max_total_tokens':12000001})

    def test_invalid_reference_asset_time_coverage_and_language_rejected(self):
        job=self.ready();data=job['payload'];base=result_for(data)
        variants=[]
        x=copy.deepcopy(base);x['timeline'][0]['at']='2000-01-01T00:00:00+00:00';variants.append(x)
        x=copy.deepcopy(base);x['assets'][0]['host']='invented';variants.append(x)
        x=copy.deepcopy(base);x['notes'][0]['references']=['wrong-run'];variants.append(x)
        x=copy.deepcopy(base);x['evidence']=[];variants.append(x)
        x=copy.deepcopy(base);x['overview']='English only';variants.append(x)
        x=copy.deepcopy(base);x['tasks'][0]['title']='Do something';variants.append(x)
        for item in variants:
            with self.assertRaises(ValueError):inv.validate(item,data)

    def test_late_alert_supersedes_model_response_before_write(self):
        job=self.ready();event=self.event('100510',7)
        event['timestamp']=job['payload']['observations'][0]['first_seen']
        self.client.alert.return_value=81;self.deliver(event);self.client.reset_mock()
        request=dict(id=job['id'],token=job['token'],result=result_for(job['payload']),model='gpt-6.1-sol',effort='xhigh',usage={})
        self.assertEqual(jobs.publish(self.store,self.client,request)['state'],'superseded')
        self.assertFalse(self.client.mock_calls)

    def test_alerts_from_another_run_are_excluded(self):
        self.deliver();inv.finish(self.store);self.store.begin('second',case_id=6)
        data=inv.input_data(self.store,self.store.current()['id']);self.assertEqual(data['observations'],[])

    def test_local_only_counts_do_not_supersede_running_analysis(self):
        job=self.ready();data=inv.input_data(self.store,self.rid)
        extra=copy.deepcopy(data);extra['queue']['evidence_only']+=100;extra['queue']['sent']+=1
        self.assertEqual(inv.digest(data),inv.digest(extra))
        with patch.object(inv,'input_data',return_value=extra):
            self.assertEqual(inv.schedule(self.store,self.rid)['job_id'],job['id'])
            self.assertTrue(inv.publish_current(self.store,jobs.read(self.store,'summary_job:'+job['id'])))
        extra['queue']['blocked']+=1
        self.assertNotEqual(inv.digest(data),inv.digest(extra))

    def test_pending_local_only_event_does_not_replace_model_job(self):
        job=self.ready();event=self.event('5715',3,data={'dstuser':'vm8admin'})
        event['timestamp']=job['payload']['observations'][0]['first_seen']
        with self.store.db:self.store.enqueue(event,canonical(event),'fixture','login_success')
        self.assertEqual(inv.input_data(self.store,self.rid)['queue']['pending'],0)
        self.assertEqual(inv.schedule(self.store,self.rid)['job_id'],job['id'])


class PolicyTests(unittest.TestCase):
    def test_threshold_and_scoped_low_rules(self):
        e={'rule':{'id':'999','level':7}};self.assertTrue(fact_alerts.selected(e))
        e['rule']['level']=6;self.assertFalse(fact_alerts.selected(e))
        e={'rule':{'id':'5715','level':3},'data':{'dstuser':'app_ops'}};self.assertTrue(fact_alerts.selected(e))
        e['data']['dstuser']='labadmin';self.assertFalse(fact_alerts.selected(e))
        e={'rule':{'id':'5402','level':3},'data':{'srcuser':'app_ops'}};self.assertTrue(fact_alerts.selected(e))
        e['data']['srcuser']='vm8admin';self.assertFalse(fact_alerts.selected(e))
        e={'rule':{'id':'554','level':5},'syscheck':{'path':'/lab_backup/example.tar'}};self.assertTrue(fact_alerts.selected(e))
        e['syscheck']['path']='/tmp/test';self.assertFalse(fact_alerts.selected(e))
        self.assertFalse(fact_alerts.selected({'full_log':'backup-integrity-check status=FAILED'}))

    def test_credentials_and_command_arguments_are_not_model_facts(self):
        event={'rule':{'id':'5402','level':3},'data':{'srcuser':'app_ops','command':'bash -c secret-recovered-password'},'full_log':'COMMAND=bash -c secret-recovered-password'}
        record=fact_alerts.record(event,'fixture',now());text=json.dumps(record)
        self.assertNotIn('secret-recovered-password',text);self.assertEqual(record['fields']['command.executable'],'bash')
        self.assertNotIn('sk-abcdefghijklmnop1234',fact_alerts.safe('api_key=sk-abcdefghijklmnop1234'))
        self.assertNotIn('secret',fact_alerts.safe('https://user:secret@example.test/path?token=secret'))


class WriterTests(unittest.TestCase):
    setUp=PostFinishTests.setUp
    ready=PostFinishTests.ready
    event=PostFinishTests.event
    deliver=PostFinishTests.deliver

    def test_timeline_list_omits_raw_so_detail_is_read_for_edit_guard(self):
        detail={'event_id':9,'event_title':'[G5AI:test] 告警','event_raw':'真实引用'}
        self.client.request.side_effect=[{'timeline':[{'event_id':9,'event_title':detail['event_title']}]},detail]
        actual=case_writer.listing(self.client,'timeline')
        self.assertEqual(actual[0]['event_raw'],'真实引用')
        self.assertEqual(self.client.request.call_args.args[0],'case/timeline/events/9?cid=5')

    def test_upload_can_avoid_iris_automatic_duplicate_evidence_registration(self):
        from iris import Iris
        client=Iris.__new__(Iris);client.cid=5;client._evidence_tree={'d-1':{'name':'Evidences'}}
        blob=b'actual facts';digest=hashlib.sha256(blob).hexdigest()
        client.request=Mock(side_effect=[{'file_id':9,'file_sha256':digest},blob])
        self.assertEqual(client.evidence('facts.ndjson',blob,'真实证据',register=False),9)
        self.assertEqual(client.request.call_args_list[0].args[1]['file_is_evidence'],'n')

    def test_repeat_publish_plan_is_idempotent_and_human_edits_conflict(self):
        job=self.ready();result=result_for(job['payload']);objects=case_writer.desired(job,result)
        lists={s:[] for s in case_writer.FIELDS}
        for i,obj in enumerate(objects,1):
            item=dict(obj['body']);item[case_writer.IDS[obj['section']]]=i
            lists[obj['section']].append(item)
            with self.store.db:jobs.write(self.store,'case_object:'+job['run']+':'+obj['section']+':'+obj['key'],
                {'id':i,'section':obj['section'],'hash':case_writer.signature(obj['section'],item)})
        with patch('case_writer.listing',side_effect=lambda c,s:lists[s]):
            plan,conflicts=case_writer.plan(self.store,self.client,job,result)
            self.assertFalse(conflicts);self.assertTrue(all(o['unchanged'] for o in plan))
            lists['notes'][0]['note_content']+='人工备注'
            plan,conflicts=case_writer.plan(self.store,self.client,job,result)
            self.assertIn('notes:analyst_edited',conflicts)

    def test_human_task_disposition_is_not_in_content_fingerprint(self):
        item={'task_title':'AI任务','task_description':'核查','task_status_id':1}
        signature=case_writer.signature('tasks',item);item['task_status_id']=3
        self.assertEqual(signature,case_writer.signature('tasks',item))


if __name__=='__main__':unittest.main()
