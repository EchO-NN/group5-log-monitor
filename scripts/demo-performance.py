#!/usr/bin/env python3
"""Reproducible offline example; fixture data never enters the live IRIS case."""
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).with_name('monitoring')))
from core import Store,canonical,now
from performance import event,normalized_point,epoch
from collected_evidence import query

with tempfile.TemporaryDirectory(prefix='group5-demo-') as folder:
    store=Store(folder);store.presentation_mode='post_finish'
    store.begin('离线样例',case_id=1);rid=store.current()['id'];at=now()
    sample=event(normalized_point('cpu_percent','192.168.31.30:9100',epoch(at),87.5))
    alert={'id':'example-1','timestamp':at,'agent':{'name':'vm5','ip':'192.168.31.30'},
           'rule':{'id':'5402','level':3,'description':'Successful sudo to ROOT executed'},
           'data':{'srcuser':'app_ops'},'full_log':'sudo session for app_ops'}
    with store.db:
        store.enqueue(sample,canonical(sample),'offline_fixture')
        store.enqueue(alert,canonical(alert),'offline_fixture')
    request={'role':9,'query':'performance_correlations','start':'2020-01-01T00:00:00+00:00',
             'end':'2040-01-01T00:00:00+00:00','match':''}
    result=query(store,rid,request);assert len(result['records'])==1
    result['example']='离线构造数据，展示性能与日志关联接口'
    print(json.dumps(result,ensure_ascii=False,indent=2));store.db.close()
