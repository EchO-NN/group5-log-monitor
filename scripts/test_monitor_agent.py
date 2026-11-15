import copy
import datetime as dt
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).with_name('monitoring')))
from core import Store,canonical,now
from bridge import send
from case_runs import INITIAL_BLOCK
import investigation as inv
import summary_jobs as jobs
import agent_workflow as agent
import agent_query_guest as guest
import agent_runner
import case_writer
import performance
from test_monitor_summary import worker


class IrisMemory:
    def __init__(self):
        self.cid=5;self.customer=2;self.config={'case_id':5};self.rows={k:[] for k in ('timeline','tasks','assets','notes','evidence')};self.files={};self.description=INITIAL_BLOCK;self.merged=set()
    def alert(self,reference,payload):return 80
    def merge(self,aid,note=''):self.merged.add(aid)
    def evidence(self,name,blob,*args,**kwargs):self.files[name]=blob;return list(self.files).index(name)+1
    def request(self,path,data=None,**kwargs):
        path=path.split('?')[0]
        if path=='case/summary/fetch':return {'case_description':self.description}
        if path=='case/summary/update':self.description=data['case_description'];return {}
        if path=='case/notes/directories/filter':return []
        if path=='case/notes/directories/add':return {'id':1}
        paths={'timeline':'case/timeline/events/','tasks':'case/tasks/','assets':'case/assets/','notes':'case/notes/','evidence':'case/evidences/'}
        for section,prefix in paths.items():
            if not path.startswith(prefix):continue
            action=path[len(prefix):];rows=self.rows[section];key={'timeline':'event_id','tasks':'task_id','assets':'asset_id','notes':'note_id','evidence':'id'}[section]
            if action in ('list','filter','search'):
                if section=='notes':return copy.deepcopy(rows)
                return {('evidences' if section=='evidence' else section):copy.deepcopy(rows)}
            if action=='add':
                row=dict(data);row[key]=len(rows)+1
                if section=='tasks':row['task_assignees']=[]
                rows.append(row);return copy.deepcopy(row)
            if action.startswith('update/'):
                row=next(x for x in rows if x[key]==int(action.split('/')[-1]));row.update(data);return copy.deepcopy(row)
            if action.isdigit():return copy.deepcopy(next(x for x in rows if x[key]==int(action)))
        raise AssertionError(path)


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(self.tmp.name);self.addCleanup(self.store.db.close)
        self.store.presentation_mode='post_finish';self.store.summary_enabled=True;self.store.analysis_engine='agent-v1';self.store.default_case_id=5
        self.store.analysis_settle_seconds=0;self.store.analysis_drain_seconds=0
        self.rid=self.store.begin('实验名称不应作为攻击先验',case_id=5);self.client=IrisMemory()
        event={'id':'fixture','timestamp':now(),'agent':{'id':'7','name':'vm7-backup-srv','ip':'192.168.29.50'},'rule':{'id':'100511','level':12,'description':'Backup validation failed'},'full_log':'backup-integrity-check status=FAILED'}
        with self.store.db:eid=self.store.enqueue(event,canonical(event),'fixture')
        send(self.store,self.client,self.store.db.execute('SELECT * FROM events WHERE id=?',(eid,)).fetchone())
        inv.finish(self.store);self.job=jobs.claim(self.store)
        self.patcher=patch('agent_workflow.for_run',side_effect=lambda s,c,r:c);self.patcher.start();self.addCleanup(self.patcher.stop)
    def call(self,name,arguments,request_id=None):
        state=agent.state_for(self.store,self.job)
        request_id=request_id or 'step_'+str(state['step']+1).zfill(4)
        return agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='action',request_id=request_id,call={'name':name,'arguments':dict(arguments,purpose='执行本次只读调查操作')},usage={'total_tokens':10}))
    def plan(self):return self.call('create_tasks',{'tasks':[{'id':'T01','title':'核查备份当前状态','description':'检查备份文件存在性和摘要，区分当前与历史。','references':['A001']}]})
    def test_performance_archive_tool_is_authorized_for_vm9_only(self):
        self.plan()
        args={'task_id':'T01','host':'VM5','query':'performance_metrics','match':''}
        self.assertIn('tool_error',self.call('query_collected',args))
        result=self.call('query_collected',dict(args,host='VM9'))
        self.assertEqual(result['permit']['request']['role'],9)
        permit=result['permit']
        response=agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='archive_read',query_id=permit['id']))
        self.assertTrue(response['ok']);self.assertEqual(response['coverage'],'no_saved_samples')
    def assert_performance_archive_route(self,query):
        self.plan()
        at=self.job['payload']['observations'][0]['first_seen']
        point=performance.normalized_point('cpu_percent','192.168.29.50:9100',performance.epoch(at),83)
        event=performance.event(point)
        with self.store.db:self.store.enqueue(event,canonical(event),'fixture')
        permit=self.call('query_collected',{'task_id':'T01','host':'VM9','query':query,'match':''})['permit']
        envelope={k:self.job[k] for k in ('id','token')}
        root=Path(self.tmp.name)/'performance-checkpoints';root.mkdir()
        preview=Mock();worker_mock=Mock()
        worker_mock.remote.side_effect=lambda _config,_action,payload:agent.dispatch(self.store,self.client,payload)
        with patch('agent_runner.query_guest',side_effect=AssertionError('unexpected guest query')) as guest_query,patch('agent_runner.query_files',side_effect=AssertionError('unexpected file query')) as file_query:
            result=agent_runner.execute_query(worker_mock,{},envelope,root,permit,preview,lambda:None)
        guest_query.assert_not_called();file_query.assert_not_called()
        self.assertEqual([call.args[2]['operation'] for call in worker_mock.remote.call_args_list],['archive_read','query_result'])
        self.assertEqual(preview.stage.call_args.kwargs['current_action'],'query_collected')
        self.assertTrue(result['ok']);self.assertEqual(result['reference'],'E001')
        self.assertEqual(result['result']['query'],query)
        self.assertEqual(result['result']['scope'],'historical_saved_telemetry')
        self.assertEqual(result['result']['records'][0]['target_host'],'VM7')
        state=agent.state_for(self.store,self.job)
        self.assertIsNone(state['active_query']);self.assertEqual(state['tasks'][0]['query_refs'],['E001'])
        self.assertEqual(state['observations'][-1]['source'],'saved_monitor_telemetry')
    def test_performance_metrics_executor_reads_archive_without_guest_transport(self):
        self.assert_performance_archive_route('performance_metrics')
    def test_performance_correlations_executor_reads_archive_without_guest_transport(self):
        self.assert_performance_archive_route('performance_correlations')
    def query(self):
        result=self.call('query_host',{'task_id':'T01','host':'VM7','query':'backup_inventory','match':''});self.assertIn('permit',result)
        permit=result['permit'];request=permit['request'];data=dict(ok=True,host='VM7',query='backup_inventory',requested_start=request['start'],requested_end=request['end'],collected_at=now(),scope='current_snapshot_not_historical',records=[{'path':'/lab_backup/example.tar.gz','present':True,'size':10}],truncated=False)
        return agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='query_result',query_id=permit['id'],result=data))
    def record(self,section,items):
        if section=='timeline':
            for item in items['items']:item.setdefault('links',[]);item.setdefault('chain_note','当前证据链起点，未建立更早的关联。')
        return self.call('record_case',{'section':section,'record_json':json.dumps(items,ensure_ascii=False)})
    def test_finish_marker_selects_agent_without_changing_legacy_completed_jobs(self):
        self.assertEqual(self.job['payload']['analysis_engine'],'agent-v1')
        with self.store.db:jobs.write(self.store,'analysis_finish:'+self.rid,{'requested_at':now()})
        self.assertNotIn('analysis_engine',inv.input_data(self.store,self.rid))
    def test_case_tasks_exist_before_query_and_replay_does_not_duplicate(self):
        self.plan();self.assertEqual(len(self.client.rows['tasks']),1);self.assertEqual(self.client.rows['tasks'][0]['task_status_id'],1)
        self.call('create_tasks',{'tasks':[{'id':'T01','title':'核查备份当前状态','description':'检查备份文件存在性和摘要，区分当前与历史。','references':['A001']}]},'step_0001')
        self.assertEqual(len(self.client.rows['tasks']),1)
        self.query();self.assertEqual(self.client.rows['tasks'][0]['task_status_id'],2)
    def test_cannot_complete_a_task_without_real_query_evidence(self):
        self.plan();result=self.call('update_task',{'task_id':'T01','state':'completed','conclusion':'仅凭告警就确认完成','references':['A001']})
        self.assertIn('tool_error',result);self.assertEqual(self.client.rows['tasks'][0]['task_status_id'],1)
    def test_unknown_host_command_and_fabricated_evidence_are_denied(self):
        self.plan()
        for key,value in (('host','192.168.1.1'),('query','rm -rf /'),('match','x'*81)):
            args={'task_id':'T01','host':'VM7','query':'backup_inventory','match':''};args[key]=value
            self.assertIn('tool_error',self.call('query_host',args))
        self.assertIn('tool_error',self.record('notes',{'items':[{'key':'N1','title':'伪造记录','content':'没有来源的事件','references':['E999']}]}))
        self.assertFalse(self.client.rows['notes'])
    def test_analyst_task_status_is_not_overwritten(self):
        self.plan();self.query();self.client.rows['tasks'][0]['task_status_id']=5
        result=self.call('update_task',{'task_id':'T01','state':'completed','conclusion':'只读查询已经执行','references':['E001']})
        self.assertIn('tool_error',result);self.assertEqual(self.client.rows['tasks'][0]['task_status_id'],5)
    def test_full_incremental_investigation_references_real_query_and_finishes(self):
        self.plan();result=self.query();self.assertEqual(result['reference'],'E001')
        self.call('update_task',{'task_id':'T01','state':'completed','conclusion':'当前文件可读取，无法仅凭当前状态还原演练当时情况。','references':['E001']})
        self.assertEqual(self.client.rows['tasks'][0]['task_status_id'],4)
        self.record('notes',{'items':[{'key':'N1','title':'调查记录','content':'已执行只读查询，当前快照与历史告警分开判断。','references':['A001','E001']}]})
        at=self.job['payload']['observations'][0]['first_seen']
        self.record('timeline',{'items':[{'key':'L1','at':at,'title':'完整性校验告警','content':'告警记录显示校验失败，原因仍待核实。','references':['A001']}]})
        self.record('assets',{'items':[{'key':'VM7','host':'VM7','description':'告警涉及的备份主机，已执行只读核查。','references':['A001','E001']}]})
        self.record('evidence',{'items':[{'key':'B1','title':'备份告警及只读核查结果','description':'告警为历史事件，查询为当前状态。','references':['A001','E001']}]})
        self.record('summary',{'overview':'备份校验出现告警，已完成只读核查。','observations':[{'text':'存在历史告警与当前文件快照。','references':['A001','E001']}],'assessment':'尚不能判断是否发生未授权操作。','gaps':['缺少历史操作归因。'],'next_steps':['结合审计继续核实。']})
        outcome=self.call('finish_case',{});self.assertEqual(outcome['state'],'done')
        self.assertEqual(self.client.merged,{80});self.assertEqual(len(self.client.rows['evidence']),1)
        self.assertEqual(len(self.client.rows['notes']),1);self.assertIn('Agent',self.client.description)
        self.assertEqual(jobs.read(self.store,'summary_job:'+self.job['id'])['state'],'done')
        self.assertTrue(any(b'agent-readonly-query-v1' in blob for blob in self.client.files.values()))
    def test_query_cannot_claim_another_host_result(self):
        self.plan();permit=self.call('query_host',{'task_id':'T01','host':'VM7','query':'backup_inventory','match':''})['permit']
        with self.assertRaises(ValueError):agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='query_result',query_id=permit['id'],result={'ok':True,'host':'VM1','query':'backup_inventory','records':[]}))
    def test_guest_policy_rejects_arbitrary_paths_and_bad_windows(self):
        request=dict(role=7,query='cat /etc/shadow',start='2026-11-05T01:00:00+00:00',end='2026-11-05T01:01:00+00:00',match='')
        with self.assertRaises(ValueError):guest.run(request)
        request.update(query='backup_inventory',role=1)
        with self.assertRaises(ValueError):guest.run(request)
    def test_guest_journal_uses_portable_time_format_and_filters_exact_window(self):
        row={'__REALTIME_TIMESTAMP':str(int(dt.datetime(2026,11,5,1,0,0,500000,tzinfo=dt.timezone.utc).timestamp()*1e6)),'SYSLOG_IDENTIFIER':'mysqld','MESSAGE':'service ready'}
        process=Mock(stdout=io.BytesIO(json.dumps(row).encode()+b'\n'),returncode=0)
        request=dict(role=5,query='services',start='2026-11-05T01:00:00.100000+00:00',end='2026-11-05T01:01:00.100000+00:00',match='')
        with patch('agent_query_guest.subprocess.Popen',return_value=process) as popen:result=guest.run(request)
        command=popen.call_args.args[0]
        self.assertEqual(command[command.index('--since')+1],'2026-11-05 01:00:00 UTC')
        self.assertEqual(command[command.index('--until')+1],'2026-11-05 01:01:01 UTC')
        self.assertTrue(result['ok']);self.assertEqual(len(result['records']),1)
    def test_guest_withholds_sql_values_connection_passwords_and_sudo_arguments(self):
        for raw,secret in [('mysql://user:HIDDEN@host/db','HIDDEN'),('query SELECT HIDDEN FROM users','HIDDEN'),('COMMAND=/bin/echo HIDDEN','HIDDEN')]:
            self.assertNotIn(secret,guest.clean(raw))
    def test_incremental_writer_does_not_prune_other_sections(self):
        self.plan();state=agent.state_for(self.store,self.job)
        with patch('case_writer.listing',side_effect=lambda c,s:self.client.rows[s]):
            operations,conflicts=case_writer.plan(self.store,self.client,agent.writer_job(self.job,state),state['result'],sections={'notes'},prune=False)
        self.assertEqual(operations,[]);self.assertEqual(conflicts,[])

    def test_query_result_replay_and_lost_receipt_do_not_repeat_query(self):
        self.plan();permit=self.call('query_host',{'task_id':'T01','host':'VM7','query':'backup_inventory','match':''})['permit']
        request=permit['request'];result=dict(ok=True,host='VM7',query='backup_inventory',requested_start=request['start'],requested_end=request['end'],collected_at=now(),records=[],truncated=False)
        root=Path(self.tmp.name)/'checkpoints';root.mkdir()
        envelope={k:self.job[k] for k in ('id','token')}
        preview=Mock();worker_mock=Mock()
        def dispatch(_config,_action,payload):return agent.dispatch(self.store,self.client,payload)
        worker_mock.remote.side_effect=RuntimeError('connection lost before receipt')
        with patch('agent_runner.query_guest',return_value=result) as query:
            with self.assertRaises(RuntimeError):agent_runner.execute_query(worker_mock,{},envelope,root,permit,preview,lambda:None)
            worker_mock.remote.side_effect=dispatch
            one=agent_runner.execute_query(worker_mock,{},envelope,root,permit,preview,lambda:None)
            two=agent_runner.execute_query(worker_mock,{},envelope,root,permit,preview,lambda:None)
        self.assertEqual(query.call_count,1);self.assertEqual(one['reference'],two['reference'])
        self.assertEqual(len(agent.state_for(self.store,self.job)['results']),1)

    def test_later_snapshot_can_reopen_executor_completed_task(self):
        self.plan();self.query()
        self.call('update_task',{'task_id':'T01','state':'completed','conclusion':'实际查询已执行，等待补充历史证据。','references':['E001']})
        later=dict(self.job,id='later-job',token='later-token',state='running')
        with self.store.db:jobs.write(self.store,'summary_job:'+later['id'],later)
        self.job=later;self.plan()
        permit=self.call('query_host',{'task_id':'T01','host':'VM7','query':'backup_inventory','match':''})
        self.assertIn('permit',permit);self.assertEqual(self.client.rows['tasks'][0]['task_status_id'],2)
        self.assertEqual(len(self.client.rows['tasks']),1)

    def test_summary_cannot_precede_task_investigation(self):
        self.plan()
        result=self.record('summary',{'overview':'准备核查备份状态','observations':[],'assessment':'证据不足','gaps':[],'next_steps':[]})
        self.assertIn('tool_error',result);self.assertEqual(self.client.description,INITIAL_BLOCK)

    def test_read_evidence_survives_unrelated_steps_and_can_recover_old_receipts(self):
        self.call('read_evidence',{'references':['A001']})
        self.plan()
        state=agent.state_for(self.store,self.job)
        self.assertIn('A001',agent.context(state,self.job)['already_read_evidence'])
        del state['read_evidence_memory'];agent.save(self.store,state)
        recovered=agent.state_for(self.store,self.job)
        self.assertIn('A001',recovered['read_evidence_memory'])

    def test_operator_budget_extension_is_per_job_and_bounded(self):
        original=agent.limits(self.job)
        extended=agent.limits(dict(self.job,agent_limits={'max_steps':40,'max_total_tokens':500000,'max_queries':999}))
        self.assertEqual(extended['max_steps'],40);self.assertEqual(extended['max_total_tokens'],500000)
        self.assertEqual(extended['max_queries'],original['max_queries'])
        self.assertEqual(agent.limits(dict(self.job,agent_limits={'max_steps':999})),original)

    def test_read_pages_keep_late_evidence_after_other_steps_and_memory_migration(self):
        self.plan()
        permit=self.call('query_host',dict(task_id='T01',host='VM7',query='audit',match='',continue_from=''))['permit']
        request=permit['request'];records=[{'audit_id':str(n),'fields':{'type':'PATH','name':'普通文件' if n<79 else '最后一条关键文件'}} for n in range(80)]
        result=dict(ok=True,host='VM7',query='audit',requested_start=request['start'],requested_end=request['end'],collected_at=now(),records=records,coverage_complete=True)
        agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='query_result',query_id=permit['id'],result=result))
        self.call('read_evidence',{'references':['E001']});self.call('read_evidence',{'references':['A001']})
        state=agent.state_for(self.store,self.job)
        self.assertEqual(agent.context(state,self.job)['already_read_evidence']['E001']['result']['records'],records)
        state['read_evidence_memory']['E001']['result']['records']=records[:12];state['read_evidence_memory_version']=1;agent.save(self.store,state)
        restored=agent.state_for(self.store,self.job)
        self.assertEqual(restored['read_evidence_memory']['E001']['result']['records'],records)

    def test_archived_query_requires_task_permit_and_registers_actual_evidence(self):
        self.plan()
        event={'id':'db-fixture','timestamp':self.job['payload']['run']['start'],'agent':{'name':'group5-vm6'},'location':'/var/log/mysql/lab-general.log','full_log':'1 Query RENAME TABLE lab_orders TO held_orders'}
        with self.store.db:self.store.enqueue(event,canonical(event),'test')
        envelope={k:self.job[k] for k in ('id','token')}
        with self.assertRaises(ValueError):agent.dispatch(self.store,self.client,dict(envelope,operation='archive_read',query_id='Q999'))
        permit=self.call('query_collected',{'task_id':'T01','host':'VM6','query':'database_changes','match':''})['permit']
        actual=agent.dispatch(self.store,self.client,dict(envelope,operation='archive_read',query_id=permit['id']))
        self.assertEqual(actual['records'][0]['operation'],'RENAME TABLE')
        result=agent.dispatch(self.store,self.client,dict(envelope,operation='query_result',query_id=permit['id'],result=actual))
        self.assertEqual(result['reference'],'E001')
        self.assertEqual(agent.state_for(self.store,self.job)['observations'][-1]['source'],'saved_monitor_telemetry')

    def test_audit_continuation_is_scoped_durable_and_does_not_consume_primary_query_budget(self):
        self.plan();args=dict(task_id='T01',host='VM7',query='audit',match='',continue_from='')
        permit=self.call('query_host',args)['permit']
        def register(permit,more,page):
            request=permit['request'];result=dict(ok=True,host='VM7',query='audit',requested_start=request['start'],requested_end=request['end'],collected_at=now(),records=[{'audit_id':str(page)}],truncated=more,has_more=more,coverage_complete=not more,page=page)
            if more:result['continuation']={'page':page+1,'private_cursor':'server maintained'}
            return agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='query_result',query_id=permit['id'],result=result))
        first=register(permit,True,1)
        self.assertEqual(first['next_page_from'],'E001');self.assertNotIn('continuation',first['result'])
        self.assertEqual(first['result']['records'],[{'audit_id':'1'}])
        update=dict(task_id='T01',state='completed',conclusion='已经完成全部分页读取。',references=['E001'])
        self.assertIn('audit coverage incomplete',self.call('update_task',update)['tool_error'])
        self.assertEqual(agent.context(agent.state_for(self.store,self.job),self.job)['pending_audit_pages'][0]['reference'],'E001')
        for bad in (dict(host='VM5'),dict(match='different'),dict(query='services')):
            self.assertIn('tool_error',self.call('query_host',dict(args,continue_from='E001',**bad)))
        state=agent.state_for(self.store,self.job);state['primary_queries']=agent.POLICY['max_queries'];agent.save(self.store,state)
        permit=self.call('query_host',dict(args,continue_from='E001'))['permit']
        self.assertEqual(permit['request']['cursor']['page'],2)
        register(permit,False,2)
        state=agent.state_for(self.store,self.job)
        self.assertEqual(state['primary_queries'],agent.POLICY['max_queries']);self.assertEqual(state['queries'],2)
        self.assertEqual(agent.pending_audits(state),[])
        self.assertIn('tool_error',self.call('query_host',dict(args,continue_from='E001')))
        self.assertEqual(self.call('update_task',dict(update,references=['E001','E002']))['state'],'completed')

    def test_incomplete_audit_may_be_blocked_but_not_falsely_completed(self):
        self.plan();permit=self.call('query_host',dict(task_id='T01',host='VM7',query='audit',match=''))['permit'];request=permit['request']
        result=dict(ok=False,host='VM7',query='audit',requested_start=request['start'],requested_end=request['end'],collected_at=now(),records=[],truncated=True,coverage_complete=False,has_more=False,error='snapshot unavailable')
        agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='query_result',query_id=permit['id'],result=result))
        self.assertEqual(self.call('update_task',dict(task_id='T01',state='blocked',conclusion='日志已轮转移除，本次审计覆盖不完整。',references=['E001']))['state'],'blocked')

    def test_failed_continuation_retries_same_cursor_and_resolves_coverage_chain(self):
        self.plan();args=dict(task_id='T01',host='VM7',query='audit',match='',continue_from='')
        permit=self.call('query_host',args)['permit']
        for n in (1,2,3):
            request=permit['request']
            data=dict(ok=n!=2,host='VM7',query='audit',requested_start=request['start'],requested_end=request['end'],collected_at=now(),records=[],truncated=n!=3,coverage_complete=n==3,has_more=n==1)
            if n==1:data['continuation']={'page':2,'position':'same page after retry'}
            if n==2:data['error']='management_query_unavailable'
            agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='query_result',query_id=permit['id'],result=data))
            if n<3:
                permit=self.call('query_host',dict(args,continue_from=f'E{n:03}'))['permit']
                self.assertEqual(permit['request']['cursor'],{'page':2,'position':'same page after retry'})
        self.assertEqual(agent.pending_audits(agent.state_for(self.store,self.job)),[])
        self.assertEqual(self.call('update_task',dict(task_id='T01',state='completed',conclusion='重试后已读完留存日志快照。',references=['E003']))['state'],'completed')

    def test_files_are_read_only_scoped_queries_and_register_current_snapshot(self):
        self.plan();args=dict(task_id='T01',host='A',operation='read',path=agent.POLICY['local_file_root']+'/reports/evidence.txt',match='',continue_from='')
        self.assertIn('tool_error',self.call('inspect_files',dict(args,operation='write')))
        self.assertIn('tool_error',self.call('inspect_files',dict(args,path='relative')))
        permit=self.call('inspect_files',args)['permit'];request=permit['request']
        result=dict(ok=True,host='A',query='files',requested_start=request['start'],requested_end=request['end'],collected_at=now(),scope='current_file_snapshot',records=[dict(line=1,text='已脱敏文件正文')],has_more=True,continuation={'page':2})
        registered=agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='query_result',query_id=permit['id'],result=result))
        state=agent.state_for(self.store,self.job)
        self.assertEqual(state['observations'][-1]['first_seen'],result['collected_at']);self.assertEqual(state['observations'][-1]['source'],'local_readonly_files')
        self.assertNotIn('continuation',registered['result']);self.assertEqual(state['primary_queries'],0)
        self.assertIn('tool_error',self.call('inspect_files',dict(args,host='VM7',continue_from='E001')))
        self.assertIn('permit',self.call('inspect_files',dict(args,continue_from='E001')))

    def test_timeline_links_are_visible_and_reject_cycles_and_invented_nodes(self):
        at=self.job['payload']['observations'][0]['first_seen']
        first=dict(key='L01',at=at,title='首个可见事件',content='告警证据确认的行为。',references=['A001'])
        self.record('timeline',{'items':[first]})
        link=dict(**{'from':'L01'},relation='temporal',confidence='inferred',basis='同一时间附近出现，但无法确认因果。',references=['A001'])
        second=dict(key='L02',at=at,title='后续观察节点',content='与前一项可能相关的观察。',references=['A001'],links=[link],chain_note='时间相邻，保留未能确认因果的缺口。')
        self.assertEqual(self.record('timeline',{'items':[second]})['count'],2)
        state=agent.state_for(self.store,self.job);rows=case_writer.desired(agent.writer_job(self.job,state),state['result'])
        self.assertIn('时间相邻（推断）',rows[1]['body']['event_content']);self.assertIn('L01',rows[1]['body']['event_raw'])
        bad=dict(first,links=[dict(link,**{'from':'L02'})])
        self.assertIn('cycle',self.record('timeline',{'items':[bad]})['tool_error'])
        bad=dict(second,links=[dict(link,**{'from':'L99'})])
        self.assertIn('tool_error',self.record('timeline',{'items':[bad]}))
        later=(dt.datetime.fromisoformat(at)+dt.timedelta(seconds=1)).isoformat()
        state=agent.state_for(self.store,self.job);state['observations'][0]['last_seen']=later;agent.save(self.store,state)
        self.assertIn('tool_error',self.record('timeline',{'items':[dict(first,at=later,links=[])]}))

    def test_attacker_and_windows_hosts_are_denied_but_vm3_is_readable(self):
        self.plan();args=dict(task_id='T01',host='B',operation='read',path='/etc/passwd',match='',continue_from='')
        for host in ('B','C','VM1'):
            self.assertIn('tool_error',self.call('inspect_files',dict(args,host=host)))
            self.assertIn('tool_error',self.call('query_host',dict(task_id='T01',host=host,query='authentication',match='')))
        for path in ('/etc/passwd',agent.POLICY['local_file_root']+'/../outside',agent.POLICY['local_file_root']+'-other/a'):
            self.assertIn('tool_error',self.call('inspect_files',dict(args,host='A',path=path)))
        permit=self.call('inspect_files',dict(args,host='VM3'))['permit'];request=permit['request']
        self.assertEqual(request['role'],3)
        result=dict(ok=True,host='VM3',query='files',requested_start=request['start'],requested_end=request['end'],collected_at=now(),scope='current_file_snapshot',records=[dict(line=1,text='员工终端调查记录')])
        with self.assertRaises(ValueError):agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='query_result',query_id=permit['id'],result=dict(result,host='VM1')))
        agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='query_result',query_id=permit['id'],result=result))
        self.assertEqual(agent.state_for(self.store,self.job)['observations'][-1]['host'],'VM3')
        self.assertIn('permit',self.call('query_host',dict(task_id='T01',host='VM3',query='authentication',match='')))

    def test_revoked_file_permit_cannot_register_new_evidence(self):
        self.plan();permit=self.call('inspect_files',dict(task_id='T01',host='VM3',operation='read',path='/etc/passwd',match='',continue_from=''))['permit']
        state=agent.state_for(self.store,self.job);state['active_query']['request']['role']=1;agent.save(self.store,state)
        request=permit['request'];result=dict(ok=True,host='VM1',query='files',requested_start=request['start'],requested_end=request['end'],collected_at=now(),records=[])
        with self.assertRaisesRegex(ValueError,'no longer permitted'):
            agent.dispatch(self.store,self.client,dict(id=self.job['id'],token=self.job['token'],operation='query_result',query_id=permit['id'],result=result))

    def test_revision_prunes_only_unchanged_tasks_with_executor_owned_status(self):
        self.plan();state=agent.state_for(self.store,self.job)
        agent.set_task_status(self.store,self.client,self.job,state,state['tasks'][0],4)
        replacement=copy.deepcopy(state['result']);replacement['tasks']=[]
        operations,conflicts=case_writer.plan(self.store,self.client,self.job,replacement,sections={'tasks'})
        self.assertFalse(conflicts);self.assertTrue(operations[0]['delete'])
        # An analyst assignment or independently changed status still prevents deletion.
        row=self.client.rows['tasks'][0];row['task_assignees']=[{'id':8}]
        self.assertTrue(case_writer.plan(self.store,self.client,self.job,replacement,sections={'tasks'})[1])
        row['task_assignees']=[];row['task_status_id']=3
        self.assertTrue(case_writer.plan(self.store,self.client,self.job,replacement,sections={'tasks'})[1])

    def test_operator_can_extend_a_single_investigation_without_removing_limits(self):
        extended={'max_queries':20,'max_steps':192,'max_total_tokens':12000000}
        actual=agent.limits({'agent_limits':extended})
        self.assertTrue(all(actual[k]==v for k,v in extended.items()))
        denied=agent.limits({'agent_limits':{'max_queries':100000,'max_steps':100000,'max_total_tokens':100000000}})
        self.assertEqual(denied['max_queries'],agent.POLICY['max_queries'])
        self.assertEqual(denied['max_steps'],agent.POLICY['max_steps'])

    def test_query_executor_enforces_the_current_job_budget(self):
        self.plan();state=agent.state_for(self.store,self.job)
        state['primary_queries']=agent.POLICY['max_queries'];agent.save(self.store,state)
        args=dict(task_id='T01',host='VM7',query='audit',match='',continue_from='')
        self.assertEqual(self.call('query_host',args)['tool_error'],'query budget exhausted')
        saved_job=jobs.read(self.store,'summary_job:'+self.job['id']);saved_job['agent_limits']={'max_queries':20}
        with self.store.db:jobs.write(self.store,'summary_job:'+self.job['id'],saved_job)
        self.assertIn('permit',self.call('query_host',args))
        state=agent.state_for(self.store,self.job)
        self.assertEqual(state['primary_queries'],agent.POLICY['max_queries']+1)
        state['active_query']=None;state['primary_queries']=20;agent.save(self.store,state)
        self.assertEqual(self.call('query_host',args)['tool_error'],'query budget exhausted')


class ToolStreamTests(unittest.TestCase):
    def test_completed_job_stays_done_when_final_preview_refresh_disconnects(self):
        with tempfile.TemporaryDirectory() as temp:
            state=dict(step=0,complete=False,active_query=None,total_usage={'total_tokens':0},actions=[],tasks=[])
            fake=Mock();fake.remote.side_effect=[state,{'state':'done'},RuntimeError('offline after completion')]
            answer={'call':{'name':'finish_case','arguments':{'purpose':'完成调查'}},'output':[],'call_id':'call1','usage':{}}
            with patch('agent_runner.BASE',Path(temp)),patch('agent_runner.provider_step',return_value=answer):
                result=agent_runner.run({'fetch_local_report':False},dict(id='fixture',token='token',run='run',case_id=5),fake,Mock(),lambda:None)
            self.assertEqual(result['state'],'done')

    def test_tool_arguments_and_associated_items_survive_empty_terminal_output(self):
        args='{"references":["A001"],"purpose":"核查证据"}'
        items=[{'type':'response.output_item.added','output_index':0,'item':{'type':'function_call','id':'fc1','call_id':'call1','name':'read_evidence','arguments':''}},
               {'type':'response.function_call_arguments.delta','output_index':0,'delta':args},
               {'type':'response.function_call_arguments.done','output_index':0,'arguments':args},
               {'type':'response.completed','response':{'status':'completed','model':worker.MODEL,'reasoning':{'effort':worker.EFFORT},'output':[],'usage':{'total_tokens':10}}}]
        stream=io.BytesIO(b''.join(b'data: '+json.dumps(x).encode()+b'\n\n' for x in items))
        result=worker.parse_stream(stream,time.monotonic()+5,tool_mode=True)
        self.assertEqual(result['call']['arguments']['references'],['A001']);self.assertEqual(result['call_id'],'call1')
        self.assertEqual(result['output'][0]['arguments'],args)


if __name__=='__main__':unittest.main()
