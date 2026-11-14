"""Classroom mapping stays explicit and never promotes background activity."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).with_name('monitoring')))
from core import Store,canonical,now
from bridge import send,report
from classroom import snapshot,sync_tasks


class ClassroomTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(self.tmp.name);self.addCleanup(self.store.db.close)
        self.store.presentation_mode='classroom'

    def event(self,kind,selftest=False):
        event={'id':kind,'timestamp':now(),'agent':{'id':'fixture','name':'fixture'},'group5':{'selftest':selftest}}
        with self.store.db:eid=self.store.enqueue(event,canonical(event),'fixture',kind)
        return self.store.db.execute('SELECT * FROM events WHERE id=?',(eid,)).fetchone()

    def test_alert_labels_mapping_and_preserves_observed_time(self):
        row=self.event('sudoedit_activity');client=Mock(customer=1)
        client.alert.return_value=1;client.evidence.return_value=2;client.timeline.return_value=3
        send(self.store,client,row)
        alert=client.alert.call_args.args[1]
        self.assertIn('课堂预设阶段 6',alert['alert_title'])
        self.assertIn('不代表实时攻击进度或攻击成功',alert['alert_description'])
        self.assertEqual(alert['alert_source_content']['classroom_mapping']['stage_ids'],[6])
        self.assertEqual(alert['alert_source_event_time'],row['event_time'])

    def test_cpu_alone_is_support_only_and_selftests_do_not_fill_steps(self):
        self.event('vm3_cpu');self.event('credential_tool',True)
        stage=snapshot(self.store,self.store.current()['id'])['stages'][3]
        self.assertEqual(stage['state'],'仅有辅助记录')
        self.assertEqual(stage['related_event_count'],0)
        self.assertEqual(stage['supporting_event_count'],1)

    def test_unknown_behavior_is_not_forced_into_a_stage(self):
        from classroom import mapped_stages
        self.assertEqual(mapped_stages(['wazuh_detection']),[])

    def test_waiting_case_stays_empty_while_local_report_has_plan(self):
        with self.store.db:self.store.db.execute('INSERT INTO metadata VALUES(?,?)',('case_reset_waiting',self.store.current()['id']))
        client=Mock()
        with patch('bridge.status',return_value={'agent_connection':{'disconnected':0},'remote_deployment':{}}):
            result=report(self.store,client)
        self.assertFalse(client.mock_calls)
        data=json.loads((Path(result['directory'])/'coverage.json').read_text())
        self.assertEqual(data['schema'],'classroom-demo-v1')
        self.assertEqual(len(data['classroom']['stages']),10)
        page=(Path(result['directory'])/'report-draft.html').read_text()
        self.assertIn('课堂预设阶段证据概览',page)
        self.assertIn('不代表实时攻击进度或攻击成功',page)

    def test_tasks_start_open_and_keep_analyst_edits_on_update(self):
        run=self.store.current()['id'];data=snapshot(self.store,run);client=Mock(cid=1)
        client.request.side_effect=[{'tasks':[]}]+[{'id':i} for i in range(1,11)]
        result=sync_tasks(client,run,data)
        self.assertEqual(len(result),10)
        self.assertTrue(all(call.args[1]['task_status_id']==1 for call in client.request.call_args_list[1:]))
        task={'task_id':1,'task_title':'G5DEMO '+run+' S01 课堂预设：保留标题','task_description':'人工补充\n<!-- G5DEMO_BEGIN -->旧快照<!-- G5DEMO_END -->',
              'task_status_id':3,'task_tags':'manual','task_assignees':[{'id':9}],'custom_attributes':{'note':'keep'}}
        client.request.reset_mock();client.request.side_effect=[{'tasks':[task]},{}]
        sync_tasks(client,run,dict(data,stages=data['stages'][:1]))
        sent=client.request.call_args.args[1]
        self.assertEqual(sent['task_status_id'],3);self.assertEqual(sent['task_assignees_id'],[9])
        self.assertIn('人工补充',sent['task_description']);self.assertEqual(sent['custom_attributes'],{'note':'keep'})


if __name__=='__main__':unittest.main()
