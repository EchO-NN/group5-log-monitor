"""Read bounded, structured facts from saved defensive telemetry; never execute SQL."""
import hashlib
import json
import re
from core import canonical,now,timestamp
import performance

SOURCES={
    'database_changes':(6,'/var/log/mysql/lab-general.log'),
    'application_errors':(5,'/var/log/test-web/application.log'),
    'business_probes':(9,'business_probe'),
    'performance_metrics':(9,performance.SOURCE),
    'performance_correlations':(9,performance.SOURCE),
}
IDENT=r'`?[A-Za-z_][A-Za-z0-9_$]*`?(?:\.`?[A-Za-z_][A-Za-z0-9_$]*`?)?'


def host_matches(event,role):
    return (event.get('agent') or {}).get('name') in ('group5-vm'+str(role),'vm'+str(role))


def catalog(store,rid):
    result=[]
    for query,(role,source) in SOURCES.items():
        count=store.db.execute("SELECT count(*) FROM events WHERE run=? AND selftest=0 AND json_extract(payload,'$.event.location')=? AND json_extract(payload,'$.event.agent.name') IN (?,?)",(rid,source,'group5-vm'+str(role),'vm'+str(role))).fetchone()[0]
        if count:result.append(dict(host='VM'+str(role),query=query,source=source,saved_records=count))
    return result


def parse(query,event,at):
    raw=str(event.get('full_log',''));data=event.get('data') or {}
    if query=='database_changes':
        match=re.search(r'\bQuery\s+(.+)',raw,re.S)
        if not match:return None
        sql=match[1].strip();start=re.match(r'\s*(\d{4}-\d\d-\d\dT\S+)',raw)
        if start:at=timestamp(start[1]) or at
        if re.match(r'RENAME\s+TABLE\b',sql,re.I):
            pairs=re.findall('('+IDENT+r')\s+TO\s+('+IDENT+')',sql,re.I)
            if not pairs:return None
            return dict(at=at,operation='RENAME TABLE',renames=[{'from':a.replace('`',''),'to':b.replace('`','')} for a,b in pairs[:20]],execution_result='query_received; verify effect with independent evidence')
        match=re.match(r'(DROP\s+(?:TABLE|DATABASE)|TRUNCATE(?:\s+TABLE)?|ALTER\s+TABLE|DELETE\s+FROM|UPDATE)\s+(?:IF\s+EXISTS\s+)?('+IDENT+r')\b',sql,re.I)
        if match:return dict(at=at,operation=' '.join(match[1].upper().split()),object=match[2].replace('`',''),execution_result='query_received; verify effect with independent evidence')
        return None
    if query=='application_errors':
        match=re.search(r'(?:Error|ERROR).*?\((\d{3,5})\s*,',raw)
        if not match:return None
        record=dict(at=at,error_code=int(match[1]))
        missing=re.search(r"Table\s+['\"]("+IDENT+r")[ '\"]+doesn't exist",raw,re.I)
        if missing:record.update(error='table_not_found',table=missing[1].replace('`',''))
        else:record['error']='database_application_error'
        return record
    if query=='business_probes':
        endpoint=data.get('endpoint');status=data.get('http_status');kind=(data.get('group5') or {}).get('kind','')
        if not isinstance(endpoint,str) or not re.fullmatch('[A-Za-z0-9_/-]{1,80}',endpoint):return None
        status=status if type(status) is int and 100<=status<=599 else None
        result=dict(at=at,endpoint=endpoint,http_status=status,outcome='failure' if kind=='business_probe_failure' else ('success' if status is not None and status<400 else 'unknown'))
        latency=data.get('latency_ms')
        if type(latency) in (int,float) and 0<=latency<=300000:result['latency_ms']=latency
        return result
    if query in ('performance_metrics','performance_correlations'):
        return performance.parse(event,at)
    raise ValueError('archived query denied')


def query(store,rid,request):
    kind=request['query'];role,source=SOURCES[kind]
    if request['role']!=role:raise ValueError('archived host denied')
    if kind in ('performance_metrics','performance_correlations'):
        return performance_query(store,rid,request)
    records={};scanned=0;eligible=0;limit=10000
    rows=store.db.execute("SELECT id,event_time,payload FROM events WHERE run=? AND selftest=0 AND json_extract(payload,'$.event.location')=? AND json_extract(payload,'$.event.agent.name') IN (?,?) ORDER BY event_time LIMIT ?",(rid,source,'group5-vm'+str(role),'vm'+str(role),limit+1))
    for row in rows:
        scanned+=1
        if scanned>limit:break
        payload=json.loads(row['payload']);event=payload['event']
        fact=parse(kind,event,row['event_time'])
        if not fact or not request['start']<=fact['at']<=request['end']:continue
        if request['match'] and request['match'] not in canonical(fact).decode():continue
        eligible+=1;key=hashlib.sha256(canonical(fact)).hexdigest()
        if key not in records:records[key]=dict(fact,source=source,source_event_ids=[],raw_sha256=[])
        item=records[key];item['source_event_ids'].append(row['id'])
        if payload.get('raw_sha256') not in item['raw_sha256']:item['raw_sha256'].append(payload.get('raw_sha256'))
    result=sorted(records.values(),key=lambda x:x['at'])
    return dict(ok=True,host='VM'+str(role),query=kind,requested_start=request['start'],requested_end=request['end'],collected_at=now(),
        scope='historical_saved_telemetry',records=result[:80],truncated=scanned>limit or len(result)>80,source_records_scanned=min(scanned,limit),matched_source_records=eligible,
        unique_records=len(result),duplicate_captures_merged=eligible-len(result),note='从本轮已保存原始记录提取；可能未形成Wazuh告警。SQL只保留操作与对象，不返回字面值、密码或执行任何语句。HTTP状态为空时不可推定具体错误码或TCP端口关闭。')


def performance_query(store,rid,request):
    from fact_alerts import selected
    points={};scanned=0;scan_limit=100000
    rows=store.db.execute("SELECT id,event_time,payload FROM events WHERE run=? AND selftest=0 AND julianday(event_time) BETWEEN julianday(?) AND julianday(?) AND json_extract(payload,'$.event.location')=? AND json_extract(payload,'$.event.agent.name') IN ('group5-vm9','vm9') ORDER BY event_time LIMIT ?",(rid,request['start'],request['end'],performance.SOURCE,scan_limit+1))
    for row in rows:
        scanned+=1
        if scanned>scan_limit:break
        payload=json.loads(row['payload']);point=performance.parse(payload['event'],row['event_time'])
        if not point:continue
        key=(point['instance'],point['metric'],point['at'])
        if key not in points:points[key]=dict(point,source_event_ids=[])
        points[key]['source_event_ids'].append(row['id'])
    facts=list(points.values());alert_truncated=False
    if request['query']=='performance_metrics':records=performance.summarize(facts)
    else:
        alerts=[]
        rows=store.db.execute("SELECT id,event_time,payload FROM events WHERE run=? AND selftest=0 AND julianday(event_time) BETWEEN julianday(?) AND julianday(?) AND json_extract(payload,'$.event.rule.id') IS NOT NULL ORDER BY event_time LIMIT 10001",(rid,request['start'],request['end']))
        for n,row in enumerate(rows):
            if n>=10000:alert_truncated=True;break
            event=json.loads(row['payload'])['event']
            if selected(event):alerts.append(dict(event,timestamp=row['event_time'],source_event_id=row['id']))
        records=performance.correlate(facts,alerts)
        for record in records:
            record['metrics']=[{k:v for k,v in m.items() if k in ('metric','unit','samples','minimum','maximum','average','peak_at','source_digest')} for m in record['metrics']]
    if request['match']:records=[r for r in records if request['match'] in canonical(r).decode()]
    total=len(records);kept=[];size=0
    for record in records:
        length=len(canonical(record))
        if len(kept)>=80 or size+length>100000:break
        kept.append(record);size+=length
    return dict(ok=True,host='VM9',query=request['query'],requested_start=request['start'],requested_end=request['end'],
                collected_at=now(),scope='historical_saved_telemetry',records=kept,
                truncated=scanned>scan_limit or alert_truncated or len(kept)<total,
                source_records_scanned=min(scanned,scan_limit),unique_samples=len(facts),total_records=total,
                coverage='samples_available' if facts else 'no_saved_samples',
                note='VM9保存的Prometheus历史采样。按被监控主机而非采集节点关联Wazuh事件；时间相邻不自动证明因果。无采样表示数据缺口，不表示指标为零或机器健康。')
