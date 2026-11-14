#!/usr/bin/env python3
"""Wazuh → durable queue → IRIS, evidence coverage and draft reports."""
import argparse
import base64
import datetime as dt
from contextlib import contextmanager
from functools import wraps
import fcntl
import html
import json
import os
from pathlib import Path
import random
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

from core import Store,KINDS,canonical,sha,now,timestamp,discover,redact
from iris import Iris,RemoteError
from triage import needs_alert,group_key,alert_text,LABELS
from case_runs import for_run,case_id
import fact_alerts

CONFIG=Path('/etc/group5-monitor/config.json')


def atomic(path,blob):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,temp=tempfile.mkstemp(dir=path.parent,prefix='.'+path.name)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(blob);stream.flush();os.fsync(stream.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)


def serial_api(function):
    @wraps(function)
    def protected(store,*args,**kwargs):
        with (store.root/'api.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            return function(store,*args,**kwargs)
    return protected


def delivery_key(store,row):
    existing=store.db.execute('SELECT value FROM metadata WHERE key=?',('alert_group:'+row['id'],)).fetchone()
    return existing['value'] if existing else (fact_alerts.key(row) if fact_alerts.enabled(store) else group_key(row))


def selected(store,row):
    envelope=json.loads(row['payload'])
    return fact_alerts.selected(envelope['event']) if fact_alerts.enabled(store) else needs_alert(envelope,json.loads(row['kinds']))


def grouped_rows(store,row):
    at=dt.datetime.fromisoformat(row['event_time']);start=dt.datetime.fromtimestamp(int(at.timestamp())//300*300,dt.timezone.utc)
    end=start+dt.timedelta(minutes=5);key=delivery_key(store,row)
    candidates=store.db.execute('SELECT * FROM events WHERE run=? AND julianday(event_time)>=julianday(?) AND julianday(event_time)<julianday(?) ORDER BY event_time,id',
                                (row['run'],start.isoformat(),end.isoformat())).fetchall()
    return [r for r in candidates if delivery_key(store,r)==key and selected(store,r)]


@serial_api
def send(store,client,event):
    client=for_run(store,client,event['run'])
    current=store.db.execute('SELECT * FROM events WHERE id=?',(event['id'],)).fetchone()
    if current is not None:
        if current['status'] in ('sent','evidence_only'):return
        event=current
    envelope=json.loads(event['payload']);kinds=json.loads(event['kinds'])
    if not selected(store,event):
        with store.db:
            store.db.execute('UPDATE events SET status="evidence_only",error=NULL WHERE id=? AND payload=?',(event['id'],event['payload']))
            store.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('report_dirty:'+event['run'],'1'))
        return
    rows=grouped_rows(store,event);first=rows[0];key=delivery_key(store,event)
    if fact_alerts.enabled(store):
        reference='G5AUTO:GROUP:'+key;facts=fact_alerts.content(rows,reference)
        title,description=fact_alerts.text(facts);level=max(r['level'] for r in facts['records'])
        aid=client.alert(reference,dict(alert_title=title,alert_description=description,
            alert_source='Wazuh',alert_source_ref=reference,alert_source_link=client.config.get('wazuh_url',''),
            alert_source_content=facts,alert_source_event_time=first['event_time'],
            alert_severity_id=6 if level>=15 else 5 if level>=12 else 4 if level>=7 else 3,
            alert_status_id=2,alert_customer_id=client.customer,alert_tags='WAZUH,FACT'+(',SELFTEST' if first['selftest'] else ''),alert_iocs=[],alert_assets=[]))
        with store.db:
            store.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('fact_alert:'+str(aid),json.dumps(facts,ensure_ascii=False)))
            store.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('report_dirty:'+event['run'],'1'))
            for row in rows:
                store.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('alert_group:'+row['id'],key))
                store.db.execute('UPDATE events SET alert_id=?,status="sent",error=NULL WHERE id=? AND payload=?',(aid,row['id'],row['payload']))
        return
    envelope=json.loads(event['payload']);kinds=sorted({k for r in rows for k in json.loads(r['kinds'])})
    content=dict(envelope,group=dict(count=len(rows),event_ids=[r['id'] for r in rows],window_seconds=300))
    title,description=alert_text(rows)
    if getattr(store,'presentation_mode','risk_timeline')=='classroom':
        from classroom import decorate_alert
        title,description,mapping=decorate_alert(rows,title,description)
        content['classroom_mapping']=mapping
    try: rule_level=int(envelope['event'].get('rule',{}).get('level',0))
    except (ValueError,TypeError): rule_level=0
    severity=6 if rule_level>=15 else 5 if rule_level>=12 or any(x in kinds for x in ('backup_integrity_failure','sql_change','application_log_change','privilege_identity')) else 1
    if first['selftest']:severity=3
    reference='G5AUTO:GROUP:'+key
    alert=dict(alert_title=title,alert_description=description,
        alert_source='G5AUTO Wazuh',alert_source_ref=reference,alert_source_link=client.config.get('wazuh_url',''),
        alert_source_content=content,alert_source_event_time=first['event_time'],alert_severity_id=severity,
        alert_status_id=2,alert_customer_id=client.customer,alert_tags='G5AUTO,'+('SELFTEST' if first['selftest'] else 'OBSERVED'),alert_iocs=[],alert_assets=[])
    aid=client.alert(reference,alert)
    with store.db:
        for row in rows:
            store.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('alert_group:'+row['id'],key))
            store.db.execute('UPDATE events SET alert_id=? WHERE id=?',(aid,row['id']))
    client.merge(aid)
    blob=b''.join(canonical(json.loads(r['payload']))+b'\n' for r in rows)
    fid=client.evidence('G5AUTO-group-'+key[:24]+'-'+sha(blob)[:12]+'.ndjson',blob,
        '合并告警的脱敏日志；原件及哈希保存在 VM8；共 '+str(len(rows))+' 条','G5AUTO,GROUP')
    at=dt.datetime.fromisoformat(first['event_time']).astimezone(dt.timezone.utc)
    marker='[G5AUTO:GROUP:'+key+']'
    tid=client.timeline(marker,dict(event_title=marker+' '+title,event_content=description,
        event_raw=canonical(content).decode(),event_source='G5AUTO grouped',event_assets=[],event_iocs=[],
        event_category_id=1,event_color='#95a5a6' if first['selftest'] else '#e67e22',
        event_date=at.strftime('%Y-%m-%dT%H:%M:%S.%f'),event_tz='+00:00',
        event_tags='G5AUTO,'+('SELFTEST' if first['selftest'] else 'OBSERVED'),
        event_in_graph=True,event_in_summary=True,custom_attributes={}))
    with store.db:
        store.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('report_dirty:'+event['run'],'1'))
        for row in rows:
            store.db.execute('UPDATE events SET alert_id=?,file_id=?,timeline_id=?,status="sent",error=NULL WHERE id=? AND payload=?',
                             (aid,fid,tid,row['id'],row['payload']))


def deliver(store,client,limit=20):
    if store.waiting_for_begin(): return
    client.invalidate_indexes()
    rows=store.db.execute('''SELECT * FROM events WHERE status="pending" AND next_try<=?
      ORDER BY CASE
        WHEN kinds LIKE '%backup_integrity_failure%' OR kinds LIKE '%sql_change%' OR kinds LIKE '%application_log_change%' OR kinds LIKE '%application_sql_error%' OR kinds LIKE '%business_probe_failure%' THEN 0
        WHEN kinds LIKE '%ssh_login%' OR kinds LIKE '%ssh_publickey%' OR kinds LIKE '%ssh_password%' OR kinds LIKE '%smb_access%' OR kinds LIKE '%acl_drop%' THEN 1
        ELSE 2 END, ingest_time LIMIT ?''', (time.time(),limit)).fetchall()
    for row in rows:
        try:send(store,client,row)
        except RemoteError as exc:
            attempts=row['attempts']+1
            delay=min(900,2**min(attempts,9))+random.uniform(0,2)
            with store.db:store.db.execute('UPDATE events SET attempts=?,next_try=?,error=?,status=? WHERE id=? AND payload=?',
                (attempts,time.time()+delay,str(exc.code),'pending' if exc.retryable else 'blocked',row['id'],row['payload']))
        except Exception:
            with store.db:store.db.execute('UPDATE events SET attempts=attempts+1,next_try=?,error="local_processing_error" WHERE id=? AND payload=?',(time.time()+60,row['id'],row['payload']))


def status(store):
    counts={row['status']:row['n'] for row in store.db.execute('SELECT status,count(*) n FROM events GROUP BY status')}
    result=dict(at=now(),run=dict(store.current()),queue=counts,
                selected_events=store.db.execute('SELECT count(*) FROM events').fetchone()[0],
                waiting_for_begin=store.waiting_for_begin())
    result['case_id']=case_id(store,result['run']['id'])
    if getattr(store,'summary_enabled',False):
        from summary_jobs import status as summary_status
        result['summary']=summary_status(store,result['run']['id'])
    agents=subprocess.run(['/var/ossec/bin/agent_control','-l'],capture_output=True,text=True,timeout=15)
    result['agent_connection']=dict(readable=agents.returncode==0,disconnected=agents.stdout.count('Disconnected'))
    result['source_files']=[dict(row) for row in store.db.execute('SELECT path,offset,done FROM cursors')]
    remote=store.root/'remote-deployment.json'
    result['remote_deployment']=json.loads(remote.read_text()) if remote.exists() else {'state':'pending','reason':'远端采集尚未验证部署'}
    return result


def summary_events(coverage,source_case):
    """Bound Word timelines while retaining original event references in the source case."""
    result=[]
    # At most 100 chronological blocks for large-case Word exports. Full list is attached.
    risks=coverage['risk_events'];width=max(1,(len(risks)+99)//100)
    for offset in range(0,len(risks),width):
        block=risks[offset:offset+width]
        at=dt.datetime.fromisoformat(block[0]['event_time']).astimezone(dt.timezone.utc)
        snapshot=dict(source_case_id=source_case,run_id=coverage['run']['id'],risk_events=block)
        marker='[G5REPORT:'+coverage['run']['id']+':T'+str(offset)+']'
        result.append(dict(event_title=marker+' 风险事件时间线',event_content='按事件时间排序；完整记录保留在原案件 #'+str(source_case)+'。',
          event_raw=canonical(redact(snapshot)).decode(),event_source='G5AUTO report snapshot',event_assets=[],event_iocs=[],
          event_category_id=1,event_color='#95a5a6',event_date=at.strftime('%Y-%m-%dT%H:%M:%S.%f'),event_tz='+00:00',
          event_tags='G5AUTO,REPORT_SNAPSHOT',event_in_graph=True,event_in_summary=True,custom_attributes={}))
    return result


def report_view(client,coverage,markdown,references):
    """A separate small report case avoids exporting thousands of raw timeline entries."""
    case=client.request('manage/cases/add',dict(case_name='监控证据概览 / '+coverage['run']['label'][:80],
      case_customer=client.customer,case_soc_id='G5REPORT-'+uuid.uuid4().hex,
      case_description='原案件 #'+str(client.cid)+' 的只读证据引用快照；不代替原始记录，不自动认定攻击或主机失陷。',custom_attributes={}))
    other=Iris(dict(client.config,case_id=case['case_id']))
    for asset in client.request('case/assets/filter?cid='+str(client.cid))['assets']:
        other.request('case/assets/add?cid='+str(other.cid),dict(asset_name=asset['asset_name'],asset_type_id=3,analysis_status_id=2,
          asset_ip=asset.get('asset_ip',''),asset_description='原案件 #'+str(client.cid)+' 资产 '+str(asset['asset_id'])+' 的报告引用；分析结论仍以原案为准。',cid=other.cid))
    for event in summary_events(coverage,client.cid):
        marker=event['event_title'].split(']',1)[0]+']';other.timeline(marker,event)
    pointer=dict(source_case_id=client.cid,run_id=coverage['run']['id'],generated_at=coverage['generated_at'],
                 source_report_artifacts=references,meaning='Full logs and evidence remain in the original case and protected source store')
    other.evidence('source-case-references.json',canonical(pointer)+b'\n','完整证据及原案件报告文件的引用。','G5AUTO,REPORT_SNAPSHOT')
    other.evidence('coverage-draft.md',markdown,'候选证据与缺项说明；不代替正式人工分析。','G5AUTO,REPORT_SNAPSHOT')
    return other


def supporting_summary(store,client,rid):
    rows=[r for r in store.db.execute('SELECT * FROM events WHERE run=? ORDER BY event_time,id',(rid,))
          if not selected(store,r)]
    if not rows:return None
    counts={}
    for row in rows:
        for kind in json.loads(row['kinds']):counts[kind]=counts.get(kind,0)+1
    blob=b''.join(canonical(dict(event_id=r['id'],**json.loads(r['payload'])))+b'\n' for r in rows)
    filename='G5AUTO-support-'+rid+'-'+sha(blob)[:12]+'.ndjson'
    atomic(store.root/'reports'/rid/filename,blob)
    summary=dict(run=rid,count=len(rows),types=counts,sha256=sha(blob),file=filename)
    if client:
        client.evidence(filename,blob,'本轮普通活动的合并证据；按事件时间保留，不逐条创建告警。','G5AUTO,SUPPORT')
        marker='[G5SUPPORT:'+rid+']';at=dt.datetime.fromisoformat(rows[0]['event_time']).astimezone(dt.timezone.utc)
        client.timeline(marker,dict(event_title=marker+' 本轮辅助证据汇总（'+str(len(rows))+'条）',
            event_content='；'.join(LABELS.get(k,k)+' '+str(v)+'条' for k,v in counts.items())+'。详细记录见同名 NDJSON 附件。',
            event_raw=canonical(summary).decode(),event_source='G5AUTO evidence summary',event_assets=[],event_iocs=[],
            event_category_id=1,event_color='#95a5a6',event_date=at.strftime('%Y-%m-%dT%H:%M:%S.%f'),event_tz='+00:00',
            event_tags='G5AUTO,SUPPORT',event_in_graph=False,event_in_summary=True,custom_attributes={}))
    return summary


def risk_snapshot(store,run=None):
    """Build the report from observed events, independent of planned stages/markers."""
    run=dict(store.db.execute('SELECT * FROM runs WHERE id=?',(run,)).fetchone()) if run else dict(store.current())
    groups={};selftests=0;queue={}
    rows=store.db.execute('SELECT * FROM events WHERE run=? ORDER BY julianday(event_time),id',(run['id'],)).fetchall()
    for row in rows:
        queue[row['status']]=queue.get(row['status'],0)+1
        if row['selftest']:
            selftests+=1;continue
        if selected(store,row):
            groups.setdefault(delivery_key(store,row),[]).append(row)
    risks=[]
    for key,members in groups.items():
        first=members[0];event=json.loads(first['payload'])['event'];title,description=alert_text(members)
        if fact_alerts.enabled(store):title,description=fact_alerts.text(fact_alerts.content(members,'G5AUTO:GROUP:'+key))
        risks.append(dict(reference='G5AUTO:GROUP:'+key,event_time=first['event_time'],last_event_time=members[-1]['event_time'],
            kinds=sorted({k for member in members for k in json.loads(member['kinds'])}),
            host=event.get('agent',{}).get('name','未知主机'),title=title,description=description,count=len(members),
            event_ids=[r['id'] for r in members],alert_ids=sorted({r['alert_id'] for r in members if r['alert_id'] is not None}),
            rule=event.get('rule',{}),source=event.get('location',first['source'])))
    risks.sort(key=lambda r:(dt.datetime.fromisoformat(r['event_time']),r['reference']))
    return dict(schema='risk-timeline-v1',run=run,generated_at=now(),risk_events=risks,selftest_events=selftests,queue=queue)


def render_report(snapshot,health):
    """Render the same chronological evidence into readable HTML and Markdown."""
    risks=snapshot['risk_events'];support=snapshot.get('supporting_evidence') or {}
    def local(at):return dt.datetime.fromisoformat(at).astimezone(dt.timezone(dt.timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')
    def cell(value):return str(value).replace('|','\\|').replace('\n',' ')
    columns=['事件时间（北京时间）','主机','风险事件','合并条数','告警 ID']
    rows=[[local(r['event_time']),r['host'],r['title'],str(r['count']),', '.join(map(str,r['alert_ids'])) or '待投递'] for r in risks]
    intro=['run: '+snapshot['run']['id'],'标签：'+snapshot['run']['label'],
           '按日志事件时间从早到晚排列；重复行为在同一主机的 5 分钟窗口内合并。',
           '风险记录表示需要核查的行为；授权性、实际影响和处置结论由分析人员核实。',
           '风险事件组：'+str(len(risks))+'；普通活动记录：'+str(support.get('count',0))+'；链路自测记录：'+str(snapshot['selftest_events']),
           'Agent 当前断线数：'+str(health['agent_connection']['disconnected'])]
    table=['|'+'|'.join(columns)+'|','|'+'|'.join(['---']*len(columns))+'|']+['|'+'|'.join(map(cell,row))+'|' for row in rows]
    detail=[]
    for r in risks:detail+=['','### '+r['title'],r['description'],'证据引用：'+', '.join(r['event_ids'])]
    markdown='\n'.join(['# 风险事件时间线','',*intro,'',*table,*(['本轮未观察到符合当前检测规则的风险事件。'] if not risks else []),*detail,'',
        '## 普通活动证据',json.dumps(support,ensure_ascii=False,indent=2),
        '## 采集状态',json.dumps(health['remote_deployment'],ensure_ascii=False,indent=2),
        '原始证据位于 VM8 保护目录 original/；IRIS 保存脱敏副本及证据引用。',''])
    esc=lambda v:html.escape(str(v))
    html_rows=''.join('<tr>'+''.join('<td>'+esc(c)+'</td>' for c in row)+'</tr>' for row in rows)
    details=''.join('<details><summary>'+esc(local(r['event_time'])+' '+r['title'])+'</summary><pre>'+esc(r['description'])+'</pre><p>证据引用：'+esc(', '.join(r['event_ids']))+'</p></details>' for r in risks)
    page='<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>风险事件时间线</title><style>body{font:16px/1.6 sans-serif;max-width:1200px;margin:32px auto;padding:0 20px;color:#172b4d}table{border-collapse:collapse;width:100%}th,td{padding:10px;border:1px solid #dce1e8;text-align:left}th{background:#edf2f7}pre{white-space:pre-wrap;overflow-wrap:anywhere}details{margin:16px 0}summary{cursor:pointer}</style><h1>风险事件时间线</h1>'+''.join('<p>'+esc(s)+'</p>' for s in intro)+'<table><thead><tr>'+''.join('<th>'+esc(c)+'</th>' for c in columns)+'</tr></thead><tbody>'+html_rows+'</tbody></table>'+('' if risks else '<p>本轮未观察到符合当前检测规则的风险事件。</p>')+details+'<details><summary>普通活动证据</summary><pre>'+esc(json.dumps(support,ensure_ascii=False,indent=2))+'</pre></details><details><summary>采集状态</summary><pre>'+esc(json.dumps(health['remote_deployment'],ensure_ascii=False,indent=2))+'</pre></details></html>'
    if snapshot.get('classroom'):
        from classroom import render
        stage_markdown,stage_html=render(snapshot['classroom'])
        markdown=markdown.replace('# 风险事件时间线','# 课堂演练证据报告',1)
        markdown=markdown.replace('\n|事件时间', '\n'+stage_markdown+'\n\n## 风险事件时间线\n\n|事件时间',1)
        page=page.replace('<title>风险事件时间线</title>','<title>课堂演练证据报告</title>')
        page=page.replace('<h1>风险事件时间线</h1>','<h1>课堂演练证据报告</h1>')
        page=page.replace('<table>',stage_html+'<h2>风险事件时间线</h2><table>',1)
    if snapshot.get('ai_summary'):
        summary=snapshot['ai_summary']['markdown']
        markdown+='\n\n'+summary+'\n'
        page=page.replace('</html>','<section><h2>AI 案件摘要（待人工核实）</h2><pre>'+html.escape(summary)+'</pre></section></html>')
    return markdown,page


@serial_api
def report(store,client=None,docx=False,run=None,summary_retry=False):
    if store.waiting_for_begin(): client=None
    if client is not None:client.invalidate_indexes()
    coverage=risk_snapshot(store,run);health=status(store)
    if client is not None:client=for_run(store,client,coverage['run']['id'])
    coverage['case_id']=case_id(store,coverage['run']['id'])
    if fact_alerts.enabled(store):
        coverage['schema']='wazuh-facts-v1'
        # Until the model publishes a finished-run assessment, IRIS contains only Alerts.
        from summary_jobs import read
        if not read(store,'summary_written:'+coverage['run']['id']):client=None;docx=False
    if getattr(store,'summary_validation_only',False):coverage['summary_validation_only']=True
    if getattr(store,'presentation_mode','risk_timeline')=='classroom':
        from classroom import snapshot
        coverage['classroom']=snapshot(store,coverage['run']['id'])
        coverage['schema']='classroom-demo-v1'
    coverage['health']=health
    coverage['supporting_evidence']=supporting_summary(store,None if fact_alerts.enabled(store) else client,coverage['run']['id'])
    if getattr(store,'summary_enabled',False):
        from summary_jobs import enqueue,read
        coverage['summary_job']=enqueue(store,coverage,retry=summary_retry)
        coverage['ai_summary']=read(store,'summary_written:'+coverage['run']['id'])
    manifest=[dict(row) for row in store.db.execute('SELECT p.* FROM provenance p JOIN events e ON p.event=e.id WHERE e.run=?',(coverage['run']['id'],))]
    coverage['evidence_manifest']=manifest
    directory=store.root/'reports'/coverage['run']['id']
    markdown,page=render_report(coverage,health)
    blobs={'coverage.json':canonical(coverage)+b'\n','report-draft.md':markdown.encode(),
           'evidence-manifest.json':canonical(manifest)+b'\n',
           'report-draft.html':page.encode()}
    for name,blob in blobs.items():atomic(directory/name,blob)
    if coverage['run']['id']==store.current()['id']:
        atomic(store.root/'latest-report.json',canonical({'directory':str(directory),'run':coverage['run']['id'],'at':now(),'case_id':coverage['case_id']})+b'\n')
    if client:
        if coverage.get('classroom'):
            from classroom import sync_tasks
            tasks=sync_tasks(client,coverage['run']['id'],coverage['classroom'])
            with store.db:store.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('tasks:'+coverage['run']['id'],json.dumps(tasks)))
        references={}
        for name in ('report-draft.md','coverage.json','evidence-manifest.json'):
            blob=blobs[name]
            fid=client.evidence('G5AUTO-'+coverage['run']['id']+'-'+sha(blob)[:12]+'-'+name,blob,'自动生成草稿/覆盖清单；不等于完成演练。','G5AUTO,DRAFT',register=not fact_alerts.enabled(store))
            references[name]={'file_id':fid,'sha256':sha(blob)}
        if docx:
            selected=client
            if store.db.execute('SELECT count(DISTINCT timeline_id) FROM events WHERE run=?',(coverage['run']['id'],)).fetchone()[0]>500:selected=report_view(client,coverage,blobs['report-draft.md'],references)
            blob=selected.request(f'case/report/generate-investigation/1?cid={selected.cid}',raw=True,timeout=120)
            if not blob.startswith(b'PK'):raise RemoteError('invalid_docx',False)
            atomic(directory/'IRIS-investigation-DRAFT.docx',blob)
            selected.evidence('G5AUTO-'+coverage['run']['id']+'-'+sha(blob)[:12]+'-DRAFT.docx',blob,'IRIS生成的调查报告草稿；原案件 #'+str(client.cid)+'；覆盖缺口另见coverage.json。','G5AUTO,DRAFT',register=not fact_alerts.enabled(store))
            metadata=dict(directory=str(directory),run=coverage['run']['id'],at=now(),source_case_id=client.cid,docx_case_id=selected.cid,summary_case=selected is not client)
            if coverage['run']['id']==store.current()['id']:atomic(store.root/'latest-report.json',canonical(metadata)+b'\n')
            with store.db:store.db.execute('DELETE FROM metadata WHERE key=?',('report_dirty:'+coverage['run']['id'],))
            return dict(directory=str(directory),run=coverage['run']['id'],risk_events=len(coverage['risk_events']),selftest_events=coverage['selftest_events'],source_case_id=client.cid,docx_case_id=selected.cid,summary_case=selected is not client,summary=coverage.get('summary_job'))
    with store.db:store.db.execute('DELETE FROM metadata WHERE key=?',('report_dirty:'+coverage['run']['id'],))
    return dict(directory=str(directory),run=coverage['run']['id'],case_id=coverage['case_id'],summary=coverage.get('summary_job'),risk_events=len(coverage['risk_events']),selftest_events=coverage['selftest_events'])


def setup(config):
    client=Iris(config)
    secrets=[client.key,client.credentials.get('password','')]
    store=Store(config['state_dir'],secrets)
    store.default_case_id=int(config['case_id'])
    store.summary_enabled=bool(config.get('summary_enabled',False))
    store.analysis_engine=config.get('analysis_engine','single_response')
    store.summary_validation_only=bool(config.get('summary_validation_only',False))
    store.analysis_settle_seconds=int(config.get('analysis_settle_seconds',60))
    store.analysis_drain_seconds=int(config.get('analysis_drain_seconds',300))
    store.presentation_mode=config.get('presentation_mode','risk_timeline')
    if store.presentation_mode not in ('classroom','risk_timeline','post_finish'):raise ValueError('unknown presentation mode')
    return store,for_run(store,client,store.current()['id'])


@serial_api
def begin_case(store,client,label,request_id=None):
    from case_runs import begin
    return begin(store,client,label,request_id)


@serial_api
def summary_action(store,client,action,payload=None):
    import summary_jobs
    if action=='agent-call':
        from agent_workflow import dispatch
        return dispatch(store,client,payload)
    if action=='summary-claim':return summary_jobs.claim(store,client)
    if action=='summary-publish':return summary_jobs.publish(store,client,payload)
    if action=='summary-fail':return summary_jobs.fail(store,payload)
    if action=='summary-heartbeat':
        job=summary_jobs.active_job(store,payload);job['lease_until']=time.time()+600
        with store.db:summary_jobs.write(store,'summary_job:'+job['id'],job)
        return {'state':'running'}
    raise ValueError('unknown summary operation')


def append_selftest(config):
    path=Path('/var/log/group5-monitor/selftest.json')
    event=dict(group5_monitor_event='pipeline_selftest',timestamp=now(),selftest_id=uuid.uuid4().hex,
               group5=dict(selftest=True,kind='backup_integrity_failure'),message='TEST_SELFTEST monitoring pipeline only; no attack or file deletion')
    with path.open('ab') as stream:stream.write(canonical(event)+b'\n');stream.flush();os.fsync(stream.fileno())
    return event['selftest_id']


def add_attachment(store,path,kind,at,note):
    path=Path(path)
    if kind not in KINDS:raise ValueError('unknown evidence kind')
    if re.search(r'(?i)(password|credential|id_rsa|id_ed25519|client\.keys|\.env$|\.(key|pem)$)',path.name):raise ValueError('secret file rejected')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        import stat
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>20*1024*1024:raise ValueError('file type or size')
        blob=stream.read()
    if timestamp(at) is None:raise ValueError('event time requires timezone')
    digest=store.blob('attachments-original',blob)
    # Arbitrary binary/archives are represented by hash metadata, never unpacked or executed.
    try:preview=redact(blob.decode('utf-8'),store.secrets) if len(blob)<1024*1024 else '[large attachment: hash only]'
    except UnicodeError:preview='[binary attachment: hash only]'
    event=dict(id='attachment:'+digest+':'+kind,timestamp=at,manager={'name':'operator'},agent={'id':'operator','name':'operator'},
               group5={'kind':kind},attachment={'name':path.name,'original_sha256':digest,'size':len(blob),'note':note,'preview':preview})
    with store.db:eid=store.enqueue(event,canonical(event),'operator_attachment',kind)
    return dict(event_id=eid,original_sha256=digest)


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',type=Path,default=CONFIG)
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('daemon');sub.add_parser('status');sub.add_parser('cycle');sub.add_parser('selftest')
    p=sub.add_parser('report');p.add_argument('--docx',action='store_true')
    p=sub.add_parser('begin');p.add_argument('--label',default='课堂攻防演练');p.add_argument('--request-id')
    p=sub.add_parser('finish');p.add_argument('--run')
    sub.add_parser('summary');sub.add_parser('summary-claim')
    for command in ('summary-publish','summary-fail','summary-heartbeat','agent-call'):
        p=sub.add_parser(command);p.add_argument('--payload-b64',required=True)
    p=sub.add_parser('mark');p.add_argument('stage',type=int,choices=range(1,11));p.add_argument('action',choices=['start','end'])
    p=sub.add_parser('confirm');p.add_argument('stage',type=int,choices=range(1,11));p.add_argument('--analyst',required=True);p.add_argument('--note',required=True)
    p=sub.add_parser('attach');p.add_argument('file',type=Path);p.add_argument('--kind',required=True,choices=sorted(KINDS));p.add_argument('--at',required=True);p.add_argument('--note',default='operator supplied evidence')
    sub.add_parser('retry')
    args=parser.parse_args();config=json.loads(args.config.read_text());store,client=setup(config)
    if args.command=='begin':result=begin_case(store,client,args.label,args.request_id)
    elif args.command=='status':result=status(store)
    elif args.command=='selftest':result={'selftest_id':append_selftest(config),'excluded_from_real_coverage':True}
    elif args.command=='report':result=report(store,client,args.docx)
    elif args.command=='summary':result=report(store,client,summary_retry=True)
    elif args.command in ('summary-claim','summary-publish','summary-fail','summary-heartbeat','agent-call'):
        payload=json.loads(base64.b64decode(args.payload_b64,validate=True)) if hasattr(args,'payload_b64') else None
        result=summary_action(store,client,args.command,payload)
        if args.command in ('summary-publish','agent-call') and result.get('state')=='done':
            run=store.db.execute('SELECT * FROM runs WHERE id=?',(result['run'],)).fetchone()
            # Refresh report/Word after writing the case summary, outside the API lock.
            try:report(store,client,docx=run['state']=='finished',run=result['run'])
            except Exception:result['report_refresh']='failed_use_report_command'
    elif args.command=='attach':result=add_attachment(store,args.file,args.kind,args.at,args.note)
    elif args.command=='retry':
        with store.db:store.db.execute('UPDATE events SET status="pending",next_try=0 WHERE status="blocked"')
        result={'retry_queued':True}
    elif args.command=='mark':
        with store.db:
            store.db.execute('INSERT INTO markers VALUES(?,?,?,?)',(store.current()['id'],args.stage,args.action,now()))
            event=dict(id='operator-marker:'+uuid.uuid4().hex,timestamp=now(),manager={'name':'operator'},agent={'id':'operator','name':'operator'},
                       stage=args.stage,action=args.action)
            store.enqueue(event,canonical(event),'operator_stage_marker','stage_marker')
        result={'stage':args.stage,'action':args.action,'at':now()}
    elif args.command=='confirm':
        with store.db:
            store.db.execute('INSERT OR REPLACE INTO confirmations VALUES(?,?,?,?,?)',(store.current()['id'],args.stage,args.analyst,args.note,now()))
            event=dict(id='operator-confirmation:'+uuid.uuid4().hex,timestamp=now(),manager={'name':'operator'},agent={'id':'operator','name':'operator'},
                       stage=args.stage,analyst=args.analyst,note=args.note,meaning='explicit_human_confirmation')
            store.enqueue(event,canonical(event),'operator_confirmation','analyst_confirmation')
        result={'stage':args.stage,'confirmed_by':args.analyst,'at':now()}
    elif args.command=='finish':
        if fact_alerts.enabled(store):
            from investigation import finish
            with (store.root/'api.lock').open('a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX);rid=finish(store,args.run)
            result=report(store,client,run=rid,summary_retry=True)
        else:
            with store.db:store.db.execute('UPDATE runs SET end=COALESCE(end,?),state="finished" WHERE id=?',(now(),store.current()['id']))
            result=report(store,client,True)
    else:
        with (store.root/'worker.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            last_report=0;last_run=''
            while True:
                try:
                    for source in discover(config['log_roots']):
                        try:store.ingest(source)
                        except (OSError,EOFError,ValueError):
                            with store.db:store.issue('source_unreadable',str(source),'本源读取失败，已保留其他源采集')
                    deliver(store,client,config.get('batch_size',20))
                    if store.current()['id']!=last_run or time.time()-last_report>=config.get('report_seconds',300):
                        last_report=time.time()
                        published=report(store,client);last_run=published['run']
                        dirty=store.db.execute("SELECT key FROM metadata WHERE key LIKE 'report_dirty:%'").fetchall()
                        for row in dirty:report(store,client,run=row['key'].split(':',1)[1])
                    atomic(store.root/'status.json',canonical(status(store))+b'\n')
                except Exception:
                    with store.db:store.issue('worker_cycle','pipeline','周期失败；原日志/队列保留，下次重试')
                    print(json.dumps({'at':now(),'status':'cycle_error_no_sensitive_details'}),flush=True)
                if args.command=='cycle':break
                time.sleep(config.get('poll_seconds',5))
        result=status(store)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':
    try:main()
    except KeyboardInterrupt:raise SystemExit(130)
    except Exception:
        print(json.dumps({'status':'error','detail':'操作失败；请检查服务日志、配置权限、队列与证据覆盖状态。'}))
        raise SystemExit(2)
