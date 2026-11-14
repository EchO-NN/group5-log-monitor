"""Finish-only, evidence-bound case investigation. No exercise plan in model input."""
import datetime as dt
import hashlib
import json
import re
import time
import uuid
from core import canonical,now,timestamp
from case_runs import case_id
from fact_alerts import indicators,selected

SCHEMA='finished-case-investigation-v1'
BASE_FIELDS={'overview','observations','assessment','gaps','next_steps'}
SECTIONS={'timeline','tasks','assets','notes','evidence'}


def finish(store,rid=None):
    from summary_jobs import write
    rid=rid or store.current()['id']
    run=store.db.execute('SELECT * FROM runs WHERE id=?',(rid,)).fetchone()
    if not run or run['state']=='prepared' or store.waiting_for_begin():raise ValueError('begin a run before finish')
    at=now()
    with store.db:
        store.db.execute('UPDATE runs SET end=COALESCE(end,?),state="finished" WHERE id=?',(at,rid))
        previous=__import__('summary_jobs').read(store,'analysis_finish:'+rid) or {}
        write(store,'analysis_finish:'+rid,dict(previous,requested_at=at,engine=previous.get('engine',getattr(store,'analysis_engine','single_response'))))
    return rid


def input_data(store,rid):
    from summary_jobs import read
    run=dict(store.db.execute('SELECT * FROM runs WHERE id=?',(rid,)).fetchone())
    rows=store.db.execute('SELECT DISTINCT alert_id FROM events WHERE run=? AND selftest=0 AND alert_id IS NOT NULL ORDER BY alert_id',(rid,)).fetchall()
    observations=[];allowed=[]
    for row in rows:
        facts=read(store,'fact_alert:'+str(row['alert_id']))
        if not facts or facts.get('schema')!='wazuh-facts-v1':raise ValueError('missing fact alert snapshot')
        r=facts['records'][0]
        observations.append(dict(reference=facts['reference'],alert_ids=[row['alert_id']],first_seen=facts['first_seen'],last_seen=facts['last_seen'],count=facts['count'],
            host=r['host'],host_ip=r['host_ip'],rule_id=r['rule_id'],level=r['level'],rule_description=r['rule_description'],source=r['source'],fields=r['fields'],message=r['message']))
        allowed.extend(dict(item,reference=facts['reference']) for item in indicators(facts))
    observations.sort(key=lambda item:(item['first_seen'],item['reference']))
    queue={state:0 for state in ('pending','blocked','sent','evidence_only')}
    queue.update({row['status']:row['n'] for row in store.db.execute('SELECT status,count(*) n FROM events WHERE run=? AND selftest=0 GROUP BY status',(rid,))})
    # Only records eligible for Alerts can make the model's Alert input incomplete.
    queue['pending']=queue['blocked']=0
    for row in store.db.execute("SELECT status,payload FROM events WHERE run=? AND selftest=0 AND status IN ('pending','blocked')",(rid,)):
        if selected(json.loads(row['payload'])['event']):queue[row['status']]+=1
    # Deliberately omit run label, prior tasks, phase markers and human stage confirmations.
    payload={'schema':SCHEMA,'run':{k:run[k] for k in ('id','start','end','state')},'case_id':case_id(store,rid),
        'observations':observations,'allowed_indicators':allowed,'queue':queue,
        'total_risk_groups':len(observations),'omitted_risk_groups':0,
        'evidence_scope':'synthetic_integration_test' if getattr(store,'summary_validation_only',False) else 'observed_wazuh_alerts',
        'input_note':'每项为已生成 Alert 的固定事实摘要；首末时间和计数保留全部合并记录范围。原始事件及命令参数保存在本地，不提供演练计划。'}
    marker=read(store,'analysis_finish:'+rid) or {}
    if marker.get('engine')=='agent-v1':payload['analysis_engine']='agent-v1'
    return payload


def digest(data):
    # Local-only sampling counts are not new Alert evidence and must not replace a running job.
    data=dict(data,queue={k:v for k,v in data['queue'].items() if k not in ('evidence_only','sent')})
    return hashlib.sha256(canonical(data)).hexdigest()


def request_revision(store,rid,instructions,agent_limits=None):
    """Operator-only fresh investigation; retain earlier jobs, outputs and case ownership."""
    from summary_jobs import read,write
    marker=read(store,'analysis_finish:'+rid)
    run=store.db.execute('SELECT state FROM runs WHERE id=?',(rid,)).fetchone()
    if not marker or not run or run['state']!='finished':raise ValueError('revision requires a finished authorized run')
    current=read(store,'summary_requested:'+rid)
    previous=read(store,'summary_job:'+current) if current else None
    if previous and previous['state'] in ('running','pending'):raise ValueError('investigation still active')
    if not isinstance(instructions,str) or not 1<=len(instructions)<=4000:raise ValueError('revision instructions invalid')
    overrides=agent_limits or {}
    for key,value in overrides.items():
        ceiling={'max_steps':192,'max_queries':32,'max_total_tokens':12000000}.get(key)
        if ceiling is None or type(value) is not int or not 1<=value<=ceiling:raise ValueError('revision limits invalid')
    marker.update(revision_id=uuid.uuid4().hex,revision_request=instructions,agent_limits=overrides,revision_at=now(),engine='agent-v1')
    with store.db:write(store,'analysis_finish:'+rid,marker)
    return schedule(store,rid)


def schedule(store,rid,retry=False):
    from summary_jobs import read,write
    if not getattr(store,'summary_enabled',False):return {'state':'disabled'}
    marker=read(store,'analysis_finish:'+rid)
    if not marker:return {'state':'waiting_for_finish'}
    elapsed=time.time()-dt.datetime.fromisoformat(marker['requested_at']).timestamp()
    settle=getattr(store,'analysis_settle_seconds',60)
    if elapsed<settle:return {'state':'waiting_for_delivery','remaining_seconds':int(settle-elapsed)+1}
    data=input_data(store,rid)
    if data['run']['state']!='finished':return {'state':'waiting_for_finish'}
    if data['queue']['pending'] and elapsed<getattr(store,'analysis_drain_seconds',300):return {'state':'waiting_for_delivery','pending':data['queue']['pending']}
    fingerprint=digest(data);cid=data['case_id'];job_id=hashlib.sha256((SCHEMA+rid+str(cid)+fingerprint+marker.get('revision_id','')).encode()).hexdigest()
    key='summary_job:'+job_id;job=read(store,key)
    with store.db:
        if job is None:
            job=dict(id=job_id,run=rid,case_id=cid,input_hash=fingerprint,payload=data,state='pending',attempts=0,next_try=0,created_at=now())
            if marker.get('revision_id'):
                job.update(analysis_revision=marker['revision_id'],revision_request=marker['revision_request'],agent_limits=marker.get('agent_limits',{}))
            write(store,key,job)
        elif retry and job['state']=='failed':
            job.update(state='pending',attempts=0,next_try=0);write(store,key,job)
        write(store,'summary_requested:'+rid,job_id)
    return {'state':job['state'],'job_id':job_id,'case_id':cid,'alert_groups':len(data['observations'])}


def before_claim(store):
    rows=store.db.execute("SELECT key FROM metadata WHERE key LIKE 'analysis_finish:%'").fetchall()
    for row in rows:schedule(store,row['key'].split(':',1)[1])


def publish_current(store,job):
    from summary_jobs import read
    marker=read(store,'analysis_finish:'+job['run'])
    return bool(marker) and job.get('analysis_revision')==marker.get('revision_id') and digest(input_data(store,job['run']))==job['input_hash']


def validate(result,data):
    from summary_jobs import validate_summary
    if not isinstance(result,dict) or set(result)!=BASE_FIELDS|SECTIONS:raise ValueError('invalid investigation schema')
    validate_summary({k:result[k] for k in BASE_FIELDS},data)
    for key in ('overview','assessment'):
        if not re.search('[\u4e00-\u9fff]',result[key]):raise ValueError('Chinese analysis required')
    for text in [o['text'] for o in result['observations']]+result['gaps']+result['next_steps']:
        if not re.search('[\u4e00-\u9fff]',text):raise ValueError('Chinese analysis required')
    by_ref={o['reference']:o for o in data['observations']}
    allowed={(i['type'],i['value'],i['reference']) for i in data['allowed_indicators']}
    shapes={'timeline':{'at','title','content','references'},'tasks':{'title','description','references'},
            'assets':{'host','description','references'},
            'notes':{'title','content','references'},'evidence':{'title','description','references'}}
    limits={'timeline':100,'tasks':30,'assets':40,'notes':10,'evidence':30}
    for section,shape in shapes.items():
        items=result[section]
        if not isinstance(items,list) or len(items)>limits[section]:raise ValueError('invalid section length')
        for item in items:
            if not isinstance(item,dict) or set(item)!=shape:raise ValueError('invalid section object')
            refs=item['references']
            if not isinstance(refs,list) or len(refs)>100 or any(not isinstance(r,str) or r not in by_ref for r in refs):raise ValueError('unknown evidence reference')
            if not refs and not (section in ('notes','tasks') and not by_ref):raise ValueError('missing references')
            for key,value in item.items():
                if key!='references' and (not isinstance(value,str) or not value or len(value)>(180 if key=='title' else 5000)):
                    raise ValueError('invalid section text')
                if key in ('title','content','description') and not re.search('[\u4e00-\u9fff]',value):raise ValueError('Chinese case content required')
            if section=='timeline':
                at=timestamp(item['at'])
                if at is None or not any(timestamp(by_ref[r]['first_seen'])<=at<=timestamp(by_ref[r]['last_seen']) for r in refs):raise ValueError('timeline time not evidenced')
            if section=='assets' and not any(by_ref[r]['host']==item['host'] for r in refs):raise ValueError('asset not evidenced')
            if section=='iocs' and not any((item['type'],item['value'],r) in allowed for r in refs):raise ValueError('indicator not evidenced')
    if by_ref and (not result['timeline'] or not result['assets'] or not result['evidence']):raise ValueError('missing case sections')
    hosts=[a['host'] for a in result['assets']]
    if len(hosts)!=len(set(hosts)):raise ValueError('duplicate assets')
    if not result['notes']:raise ValueError('missing investigation notes')
    # Every imported Alert must be traceable in the evidence catalogue, even if assessed benign.
    covered={r for e in result['evidence'] for r in e['references']}
    if covered!=set(by_ref):raise ValueError('evidence catalogue incomplete')
    return result
