import datetime as dt
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).with_name('monitoring')))
import performance as perf
import collected_evidence as collected
from core import Store, canonical, now, classify
from fact_alerts import selected


class PerformanceTests(unittest.TestCase):
    def test_range_response_rejects_unknown_targets_nan_and_outside_window(self):
        opener=Mock()
        def opened(*args,**kwargs):
            payload={'status':'success','data':{'resultType':'matrix','result':[
                {'metric':{'instance':'192.168.31.30:9100'},'values':[[100,'1'],[130,'NaN'],[160,'0'],[999,'1']]},
                {'metric':{'instance':'attacker:9100'},'values':[[100,'1']]},
            ]}}
            return io.BytesIO(json.dumps(payload).encode())
        opener.open.side_effect=opened
        r=perf.collect(100,160,opener=opener)
        self.assertTrue(r['complete']);self.assertEqual(len(r['points']),len(perf.METRICS)*2)
        self.assertTrue(all(p['target_host']=='VM5' for p in r['points']))
        self.assertIn('/api/v1/query_range?',opener.open.call_args[0][0])

    def test_failure_and_empty_response_never_generate_zero_samples(self):
        opener=Mock();opener.open.side_effect=OSError('offline')
        r=perf.collect(100,160,opener=opener)
        self.assertFalse(r['complete']);self.assertEqual(r['points'],[])
        opener.open.side_effect=lambda *a,**k:io.BytesIO(b'{"status":"success","data":{"resultType":"matrix","result":[]}}')
        r=perf.collect(100,160,opener=opener)
        self.assertTrue(r['complete']);self.assertEqual(r['points'],[])
        self.assertEqual(set(r['metrics'].values()),{'no_samples'})

    def test_invalid_payload_and_bounds(self):
        self.assertIsNone(perf.normalized_point('cpu_percent','192.168.31.30:9100',100,101))
        self.assertIsNone(perf.normalized_point('cpu_percent','192.168.31.30:9100',100,True))
        self.assertIsNone(perf.normalized_point('target_up','192.168.31.30:9100',100,2))
        with self.assertRaises(ValueError):perf.collect(0,7201)
        with self.assertRaises(ValueError):perf.collect(0,10,base_url='http://user:password@localhost')

    def test_summary_uses_all_points_including_a_peak_after_80_samples(self):
        points=[perf.normalized_point('cpu_percent','192.168.31.30:9100',100+i,99 if i==110 else 5) for i in range(120)]
        r=perf.summarize(points)[0]
        self.assertEqual(r['samples'],120);self.assertEqual(r['maximum'],99)
        self.assertEqual(r['peak_at'],perf.iso(210))

    def test_temporal_join_matches_target_host_and_not_sensor(self):
        p=perf.normalized_point('cpu_percent','192.168.31.30:9100',100,90)
        base={'timestamp':perf.iso(100),'source_event_id':'event1','rule':{'id':'5402'}}
        alerts=[dict(base,agent={'name':'vm5'}),dict(base,agent={'name':'vm9'}),
                dict(base,timestamp=perf.iso(500),agent={'name':'vm5'})]
        rows=perf.correlate([p],alerts)
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['target_host'],'VM5')
        self.assertEqual(rows[0]['relation'],'same_host_temporal_overlap')

    def test_intake_archive_and_correlation_are_scoped_to_run(self):
        with tempfile.TemporaryDirectory() as folder:
            s=Store(folder);s.presentation_mode='post_finish';s.begin('performance',case_id=2)
            try:
                rid=s.current()['id'];at=now();epoch=perf.epoch(at)
                p=perf.normalized_point('cpu_percent','192.168.31.30:9100',epoch,88)
                event=perf.event(p)
                self.assertIn('performance_metric',classify(event)[0]);self.assertFalse(selected(event))
                alert={'id':'alert1','timestamp':at,'agent':{'name':'vm5','ip':'192.168.31.30'},'rule':{'id':'100511','level':12},'full_log':'backup-integrity-check status=FAILED'}
                with s.db:
                    eid=s.enqueue(event,canonical(event),'fixture')
                    s.enqueue(event,canonical(event),'fixture-replay')
                    s.enqueue(alert,canonical(alert),'fixture')
                self.assertIsNotNone(eid)
                req={'role':9,'query':'performance_metrics','start':'2020-01-01T00:00:00+00:00','end':'2040-01-01T00:00:00+00:00','match':''}
                r=collected.query(s,rid,req)
                self.assertEqual(r['unique_samples'],1);self.assertEqual(r['records'][0]['maximum'],88)
                self.assertFalse(r['truncated'])
                r=collected.query(s,rid,dict(req,query='performance_correlations'))
                self.assertEqual(len(r['records']),1);self.assertEqual(r['records'][0]['target_host'],'VM5')
                self.assertEqual(collected.query(s,'missing',req)['coverage'],'no_saved_samples')
                self.assertEqual(collected.query(s,rid,dict(req,match='VM7'))['records'],[])
                with self.assertRaises(ValueError):collected.query(s,rid,dict(req,role=5))
            finally:s.db.close()

    def test_success_probe_keeps_latency_as_supporting_evidence(self):
        event={'timestamp':now(),'agent':{'name':'group5-vm9'},'data':{'group5':{'kind':'business_probe_success'},'endpoint':'orders','http_status':200,'latency_ms':25.5}}
        self.assertIn('business_probe_success',classify(event)[0])
        r=collected.parse('business_probes',event,event['timestamp'])
        self.assertEqual(r['outcome'],'success');self.assertEqual(r['latency_ms'],25.5)


if __name__=='__main__':unittest.main()
