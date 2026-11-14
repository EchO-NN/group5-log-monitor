import io
import http.server
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).with_name('monitoring')))
from core import Store,now,canonical
from case_runs import begin,case_id,for_run,INITIAL_BLOCK
from bridge import risk_snapshot,send
import summary_jobs as jobs
spec=importlib.util.spec_from_file_location('summary_worker',Path(__file__).with_name('summary-worker.py'))
worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(self.tmp.name);self.addCleanup(self.store.db.close)
        self.store.default_case_id=1;self.store.summary_enabled=True
        self.run=self.store.begin('test',case_id=42)
        self.client=Mock(cid=42,customer=1,config={'case_id':42})

    def data(self):
        event={'id':'fixture','timestamp':now(),'agent':{'id':'42','name':'vm7-secret-host'},'rule':{'id':'100511','level':12},'full_log':'password=TOP_SECRET','data':{'sql':'TOP_SECRET'}}
        with self.store.db:self.store.enqueue(event,canonical(event),'fixture','backup_integrity_failure')
        snapshot=risk_snapshot(self.store);snapshot['case_id']=42
        return snapshot

    def claimed(self):
        jobs.enqueue(self.store,self.data());return jobs.claim(self.store)

    def answer(self,job):
        return {'id':job['id'],'token':job['token'],'model':'gpt-6.1-sol','effort':'xhigh','usage':{},
            'result':{'overview':'观察到完整性检测告警','observations':[{'text':'需核查备份状态','references':[job['payload']['observations'][0]['reference']]}],
                      'assessment':'不能证明攻击成功','gaps':['未检查原件'],'next_steps':['人工核对']}}

    def client_summary(self,description):
        state={'text':description}
        def request(path,data=None):
            if 'update' in path:state['text']=data['case_description'];return {}
            return {'case_description':state['text']}
        self.client.request.side_effect=request
        return state

    def test_allowlist_omits_raw_secrets_label_and_host_suffix(self):
        data=jobs.payload(self.data());text=json.dumps(data)
        self.assertNotIn('TOP_SECRET',text);self.assertNotIn('secret-host',text)
        self.assertEqual(data['observations'][0]['host'],'VM7');self.assertNotIn('label',data['run'])

    def test_same_evidence_does_not_create_second_job(self):
        data=self.data();one=jobs.enqueue(self.store,data)
        data['generated_at']='later';data['run']['label']='new label'
        two=jobs.enqueue(self.store,data);self.assertEqual(one['job_id'],two['job_id'])
        self.assertIsNotNone(jobs.claim(self.store));self.assertIsNone(jobs.claim(self.store))

    def test_reset_invalidates_pending_model_result(self):
        job=self.claimed()
        with self.store.db:self.store.db.execute('DELETE FROM metadata')
        with self.assertRaises(ValueError):jobs.publish(self.store,self.client,self.answer(job))
        self.client.request.assert_not_called()

    def test_publish_preserves_analyst_text_outside_block(self):
        job=self.claimed();state=self.client_summary('人工开头\n'+INITIAL_BLOCK+'\n人工结尾')
        self.assertEqual(jobs.publish(self.store,self.client,self.answer(job))['state'],'done')
        self.assertTrue(state['text'].startswith('人工开头'));self.assertTrue(state['text'].endswith('人工结尾'))
        self.assertIn('待人工核实',state['text'])
        self.assertTrue((self.store.root/'reports'/self.run/'case-summary.md').exists())

    def test_initial_placeholder_analyst_edit_is_preserved(self):
        job=self.claimed();description=INITIAL_BLOCK.replace('等待本轮证据。','人工已经整理。')
        state=self.client_summary(description)
        self.assertEqual(jobs.publish(self.store,self.client,self.answer(job))['state'],'conflict')
        self.assertEqual(state['text'],description)

    def test_existing_ai_block_edit_is_preserved(self):
        job=self.claimed();state=self.client_summary(INITIAL_BLOCK)
        jobs.publish(self.store,self.client,self.answer(job))
        state['text']=state['text'].replace('观察到完整性检测告警','人工改过的结论')
        data=self.data();data['risk_events'][0]['count']=99
        jobs.enqueue(self.store,data);job2=jobs.claim(self.store)
        self.assertEqual(jobs.publish(self.store,self.client,self.answer(job2))['state'],'conflict')
        self.assertIn('人工改过的结论',state['text'])

    def test_newer_evidence_supersedes_old_claim(self):
        job=self.claimed();data=self.data();data['risk_events'][0]['count']=99
        jobs.enqueue(self.store,data)
        self.assertEqual(jobs.publish(self.store,self.client,self.answer(job))['state'],'superseded')
        self.client.request.assert_not_called()

    def test_failure_is_bounded_and_disabled_worker_does_not_claim(self):
        job=self.claimed()
        for attempt in range(3):
            result=jobs.fail(self.store,dict(job,error='provider_transport'))
            record=jobs.read(self.store,'summary_job:'+job['id']);record['next_try']=0
            with self.store.db:jobs.write(self.store,'summary_job:'+job['id'],record)
            if attempt<2:job=jobs.claim(self.store)
        self.assertEqual(result['state'],'failed');self.assertIsNone(jobs.claim(self.store))
        jobs.enqueue(self.store,self.data(),retry=True);self.store.summary_enabled=False
        self.assertIsNone(jobs.claim(self.store))

    def test_expired_leases_have_retry_limit(self):
        job=self.claimed();record=jobs.read(self.store,'summary_job:'+job['id']);record.update(attempts=3,lease_until=0)
        with self.store.db:jobs.write(self.store,'summary_job:'+job['id'],record)
        self.assertIsNone(jobs.claim(self.store))
        self.assertEqual(jobs.read(self.store,'summary_job:'+job['id'])['state'],'failed')

    def test_failed_iris_write_caches_model_result_for_retry(self):
        job=self.claimed();self.client.request.side_effect=RuntimeError('transport')
        with self.assertRaises(RuntimeError):jobs.publish(self.store,self.client,self.answer(job))
        self.assertIsNotNone(jobs.read(self.store,'summary_job:'+job['id'])['cached_response'])

    def test_recovered_complete_body_keeps_unknown_usage_and_provenance(self):
        job=self.claimed();state=self.client_summary(INITIAL_BLOCK);answer=self.answer(job)
        answer.update(usage=None,response_metadata={'completion_verified':False,'source':'saved_complete_text'})
        result=jobs.publish(self.store,self.client,answer)
        self.assertEqual(result['state'],'done');self.assertIsNone(result['usage'])
        self.assertIn('接口完成帧未取得',state['text'])
        saved=jobs.read(self.store,'summary_job:'+job['id'])
        self.assertFalse(saved['cached_response']['response_metadata']['completion_verified'])
        self.assertIsNone(saved['error'])

    def test_unrecognized_reference_and_model_rejected(self):
        job=self.claimed();answer=self.answer(job);answer['result']['observations'][0]['references']=['invented']
        with self.assertRaises(ValueError):jobs.publish(self.store,self.client,answer)
        answer=self.answer(job);answer['model']='other'
        with self.assertRaises(ValueError):jobs.publish(self.store,self.client,answer)
        self.client.request.assert_not_called()

    def test_late_event_routes_to_original_case(self):
        self.data();row=self.store.db.execute('SELECT * FROM events').fetchone()
        self.store.begin('next',case_id=43)
        self.client.cid=43;target=Mock(cid=42,customer=1)
        target.alert.return_value=2;target.evidence.return_value=3;target.timeline.return_value=4
        with patch('case_runs.Iris',return_value=target) as factory:send(self.store,self.client,row)
        self.assertEqual(factory.call_args.args[0]['case_id'],42)
        target.merge.assert_called_once_with(2);self.client.merge.assert_not_called()

    def test_case_creation_failure_keeps_current_run(self):
        before=self.store.current()['id'];self.client.request.side_effect=[[],RuntimeError('network')]
        with self.assertRaises(RuntimeError):begin(self.store,self.client,'new')
        self.assertEqual(self.store.current()['id'],before)

    def test_distinct_begins_and_request_retry(self):
        cases=[]
        def request(path,data=None):
            if path=='manage/cases/list':return cases
            item=dict(data,case_id=100+len(cases));cases.append(item);return item
        self.client.request.side_effect=request
        a=begin(self.store,self.client,'same','a'*32);b=begin(self.store,self.client,'same','b'*32)
        retry=begin(self.store,self.client,'same','b'*32)
        self.assertNotEqual(a['case_id'],b['case_id']);self.assertEqual(b,retry);self.assertEqual(len(cases),2)
        self.assertEqual(case_id(self.store,a['run']),a['case_id'])

    def test_ambiguous_creation_reconciles_by_soc_reference(self):
        self.client.request.side_effect=[[],RuntimeError('timeout')]
        with self.assertRaises(RuntimeError):begin(self.store,self.client,'new','a'*32)
        self.client.request.side_effect=None;self.client.request.return_value=[{'case_id':50,'case_soc_id':'G5RUN-'+'a'*32}]
        result=begin(self.store,self.client,'new','a'*32)
        self.assertEqual(result['case_id'],50);self.assertEqual(self.client.request.call_args.args[0],'manage/cases/list')

    def reserve_primary(self):
        with self.store.db:
            self.store.db.execute('INSERT INTO metadata VALUES(?,?)',('case_reset_waiting',self.run))
            jobs.write(self.store,'reuse_primary_once',{'run':self.run,'fingerprint':'empty-fingerprint'})

    def test_reserved_primary_is_used_once_then_new_case_is_created(self):
        self.reserve_primary();cases=[{'case_id':1,'case_soc_id':'empty'}]
        def request(path,data=None):
            if path=='manage/cases/list':return cases
            if path=='manage/cases/update/1':cases[0].update(data);return cases[0]
            cases.append(dict(data,case_id=2));return cases[-1]
        self.client.request.side_effect=request
        with patch('primary_case.snapshot',return_value='empty-fingerprint'):
            one=begin(self.store,self.client,'first','a'*32)
            two=begin(self.store,self.client,'second','b'*32)
        self.assertEqual(one['case_id'],1);self.assertEqual(two['case_id'],2)
        self.assertIsNone(jobs.read(self.store,'reuse_primary_once'))
        self.assertEqual(case_id(self.store,one['run']),1)

    def test_changed_primary_case_is_never_overwritten(self):
        self.reserve_primary();self.client.request.return_value=[]
        with patch('primary_case.snapshot',return_value='analyst-edited'),self.assertRaises(ValueError):
            begin(self.store,self.client,'first','a'*32)
        self.assertEqual(self.store.current()['id'],self.run)
        self.assertEqual(self.client.request.call_count,1)

    def test_uncertain_primary_update_reconciles_without_overwriting_again(self):
        self.reserve_primary();cases=[]
        def request(path,data=None):
            if path=='manage/cases/list':return cases
            cases.append(dict(data,case_id=1));raise RuntimeError('timeout after update')
        self.client.request.side_effect=request
        with patch('primary_case.snapshot',return_value='empty-fingerprint') as guard:
            with self.assertRaises(RuntimeError):begin(self.store,self.client,'first','a'*32)
            result=begin(self.store,self.client,'first','a'*32)
        self.assertEqual(result['case_id'],1);self.assertEqual(guard.call_count,1)
        self.assertIsNone(jobs.read(self.store,'reuse_primary_once'))


class ProviderTests(unittest.TestCase):
    def stream(self,model='gpt-6.1-sol',effort='xhigh',complete=True):
        items=[{'type':'response.output_text.delta','delta':'{"ok":true}'}]
        if complete:items.append({'type':'response.completed','response':{'status':'completed','model':model,'reasoning':{'effort':effort},'output':[],'usage':{'total_tokens':12}}})
        return io.BytesIO(b''.join(b'data: '+json.dumps(item).encode()+b'\n\n' for item in items))

    def test_sse_deltas_survive_empty_terminal_output(self):
        result=worker.parse_stream(self.stream(),time.monotonic()+5)
        self.assertEqual(result['result'],{'ok':True});self.assertEqual(result['usage']['total_tokens'],12)

    def test_large_terminal_envelope_does_not_discard_small_complete_output(self):
        padding='x'*(1500*1024)
        items=[{'type':'response.created','opaque_metadata':padding} for _ in range(2)]
        items += [{'type':'response.output_text.delta','delta':'{"ok":true}'},
                  {'type':'response.completed','response':{'status':'completed','model':worker.MODEL,
                    'reasoning':{'effort':worker.EFFORT},'output':[],'opaque_metadata':padding}}]
        stream=io.BytesIO(b''.join(b'data: '+json.dumps(x).encode()+b'\n\n' for x in items))
        result=worker.parse_stream(stream,time.monotonic()+5)
        self.assertEqual(result['result'],{'ok':True})
        self.assertGreater(result['response_metadata']['received_wire_bytes'],4*1024*1024)
        self.assertNotIn('opaque_metadata',json.dumps(result))

    def test_wire_size_guards_remain_bounded_and_distinguish_limits(self):
        with patch.object(worker,'MAX_SSE_LINE',32),self.assertRaisesRegex(worker.SummaryError,'stream_line_too_large'):
            worker.parse_stream(io.BytesIO(b'data: '+b'x'*64),time.monotonic()+5)
        with patch.object(worker,'MAX_SSE_TOTAL',20),self.assertRaisesRegex(worker.SummaryError,'stream_total_too_large'):
            worker.parse_stream(io.BytesIO(b': keepalive\n'*10),time.monotonic()+5)

    def test_wrong_model_effort_or_missing_completion_rejected(self):
        for args in ({'model':'other'},{'effort':'low'},{'complete':False}):
            with self.subTest(args=args),self.assertRaises(worker.SummaryError):worker.parse_stream(self.stream(**args),time.monotonic()+5)

    def test_no_redirect_and_credential_mode(self):
        self.assertIsNone(worker.NoRedirect().redirect_request(None,None,None,None,None,None))
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'secret';path.write_text('{"api_key":"fixture"}');path.chmod(0o644)
            with self.assertRaises(worker.SummaryError):worker.credential(path)
            path.chmod(0o600);self.assertEqual(worker.credential(path),'fixture')

    def test_live_output_continues_past_old_180_second_deadline(self):
        with patch.object(worker.time,'monotonic',return_value=0):budget=worker.StreamBudget(1800,600,180)
        for at in (179,181,300,600,900):
            budget.last_text=at-10
            with patch.object(worker.time,'monotonic',return_value=at):budget.check()
        with patch.object(worker.time,'monotonic',return_value=1080),self.assertRaisesRegex(worker.SummaryError,'output_idle_timeout'):budget.check()

    def test_first_text_gets_longer_wait_and_total_timeout_is_still_bounded(self):
        with patch.object(worker.time,'monotonic',return_value=0):budget=worker.StreamBudget(1800,600,180)
        with patch.object(worker.time,'monotonic',return_value=599):budget.check()
        with patch.object(worker.time,'monotonic',return_value=600),self.assertRaisesRegex(worker.SummaryError,'first_text_timeout'):budget.check()
        budget.last_text=1799
        with patch.object(worker.time,'monotonic',return_value=1800),self.assertRaisesRegex(worker.SummaryError,'total_timeout'):budget.check()

    def test_silent_http_read_does_not_block_deadline_or_lease_heartbeat(self):
        release=threading.Event()
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers();self.wfile.flush()
                release.wait(3)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        heartbeat=Mock();started=time.monotonic()
        try:
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open('http://127.0.0.1:'+str(server.server_port),timeout=5) as response:
                with self.assertRaisesRegex(worker.SummaryError,'first_text_timeout'):
                    worker.parse_stream(response,time.monotonic()+2,first_text_timeout=.25,heartbeat=heartbeat,heartbeat_interval=.05)
            self.assertLess(time.monotonic()-started,1.5)
            self.assertGreaterEqual(heartbeat.call_count,2)
        finally:release.set();server.shutdown();server.server_close();thread.join(timeout=1)

    def test_empty_deltas_and_keepalives_do_not_extend_text_idle_deadline(self):
        class Keepalive:
            def __init__(self):self.first=True
            def readline(self,limit):
                if self.first:self.first=False;return b'data: {"type":"response.output_text.delta","delta":"{"}\n'
                time.sleep(.02)
                return b'data: {"type":"response.output_text.delta","delta":""}\n'
        with self.assertRaisesRegex(worker.SummaryError,'output_idle_timeout'):
            worker.parse_stream(Keepalive(),time.monotonic()+2,output_idle_timeout=.1)


if __name__=='__main__':unittest.main()
