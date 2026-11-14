import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0,str(Path(__file__).with_name('monitoring')))
from summary_preview import Preview,show
spec=importlib.util.spec_from_file_location('preview_worker',Path(__file__).with_name('summary-worker.py'))
worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)


class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'live'
        self.job=dict(id='a'*64,token='attempt1',run='fixture-run',case_id=42)

    def stream(self,items):
        return io.BytesIO(b''.join(b'data: '+json.dumps(item).encode()+b'\n\n' for item in items))

    def test_incomplete_stream_retains_text_without_reasoning(self):
        preview=Preview(self.root,self.job);preview.begin_request()
        items=[{'type':'response.reasoning_text.delta','delta':'PRIVATE_REASONING'},
               {'type':'response.output_text.delta','delta':'{"概况":"待核查'},
               {'type':'response.failed','response':{'error':'UNSAFE_PROVIDER_ERROR'}}]
        with self.assertRaises(worker.SummaryError):worker.parse_stream(self.stream(items),time.monotonic()+5,preview)
        preview.stage('pending',error='provider_incomplete')
        self.assertEqual((preview.directory/'output-1.txt').read_text(),'{"概况":"待核查')
        state=json.loads((preview.directory/'status.json').read_text())
        self.assertEqual(state['state'],'pending');self.assertGreater(state['characters'],0)
        for path in preview.directory.iterdir():
            self.assertNotIn('PRIVATE_REASONING',path.read_text());self.assertNotIn('UNSAFE_PROVIDER_ERROR',path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_attempts_and_requests_preserve_prior_partial_text(self):
        old=Preview(self.root,self.job);old.begin_request();old.event('response.output_text.delta','第一批')
        old.begin_request();old.event('response.output_text.delta','第二批');old.stage('pending')
        new=Preview(self.root,dict(self.job,token='attempt2'));new.begin_request()
        self.assertNotEqual(old.directory,new.directory)
        self.assertEqual((old.directory/'output-1.txt').read_text(),'第一批')
        self.assertEqual((old.directory/'output-2.txt').read_text(),'第二批')
        self.assertEqual(json.loads((self.root/'latest.json').read_text())['attempt'],new.directory.name)

    def test_viewer_shows_waiting_and_strips_terminal_control(self):
        preview=Preview(self.root,self.job);preview.begin_request();preview.event('response.created');preview.save()
        output=io.StringIO()
        with contextlib.redirect_stdout(output):show(self.root)
        self.assertIn('尚未收到正文',output.getvalue())
        preview.event('response.output_text.delta','中文\x1b[2J');preview.save()
        output=io.StringIO()
        with contextlib.redirect_stdout(output):show(self.root,full=True)
        self.assertIn('中文',output.getvalue());self.assertNotIn('\x1b',output.getvalue())

    def test_cached_result_preview_does_not_claim_new_model_output(self):
        preview=Preview(self.root,self.job);preview.use_cached({'result':{'overview':'保存的中文结果'}})
        self.assertEqual(preview.state['request'],0);self.assertIsNone(preview.state['last_text_at'])
        output=io.StringIO()
        with contextlib.redirect_stdout(output):show(self.root)
        self.assertIn('本次未调用模型',output.getvalue());self.assertIn('保存的中文结果',output.getvalue())

    def test_agent_view_shows_actual_tasks_and_tool_progress(self):
        preview=Preview(self.root,self.job)
        preview.stage('investigating',agent=True,agent_step=3,current_action='query_host',purpose='核查备份文件',agent_tasks=[{'id':'T01','state':'investigating','title':'核查备份'}],agent_actions=[{'step':2,'tool':'query_host','purpose':'读取实际日志'}])
        output=io.StringIO()
        with contextlib.redirect_stdout(output):show(self.root)
        for value in ('调查步骤：3','T01 / 调查中','读取实际日志','当前工具调用参数'):self.assertIn(value,output.getvalue())


if __name__=='__main__':unittest.main()
