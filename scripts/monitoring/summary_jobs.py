"""Durable, bounded summary jobs; never send raw logs or credentials to the model."""
import datetime as dt
import hashlib
import html
import json
import re
import time
import uuid

from core import canonical,now
from triage import LABELS
from case_runs import case_id,for_run,INITIAL_BLOCK

BEGIN='<!-- G5AI_BEGIN -->'
END='<!-- G5AI_END -->'


def read(store,key):
    row=store.db.execute('SELECT value FROM metadata WHERE key=?',(key,)).fetchone()
    return json.loads(row['value']) if row else None


def write(store,key,value):
    store.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',(key,json.dumps(value,ensure_ascii=False)))


def payload(snapshot):
    risks=snapshot['risk_events']
    chosen=risks if len(risks)<=200 else risks[:100]+risks[-100:]
    observations=[]
    for risk in chosen:
        host=re.search(r'(?i)vm([1-9])(?:\b|[-_])',str(risk['host']))
        host='VM'+host[1] if host else 'host-'+hashlib.sha256(str(risk['host']).encode()).hexdigest()[:8]
        rule_id=str(risk.get('rule',{}).get('id',''))
        observations.append(dict(reference=risk['reference'],first_seen=risk['event_time'],last_seen=risk['last_event_time'],
            host=host,behaviors=[LABELS[k] for k in risk.get('kinds',[]) if k in LABELS],count=risk['count'],
            rule_id=rule_id if re.fullmatch(r'\d{1,10}',rule_id) else None,alert_ids=risk['alert_ids']))
    stages=[dict(id=s['id'],related_event_count=s['related_event_count'],supporting_event_count=s['supporting_event_count'],
        missing_types=s['missing'],has_human_confirmation=bool(s['analyst_confirmation'])) for s in snapshot.get('classroom',{}).get('stages',[])]
    return dict(run={k:snapshot['run'][k] for k in ('id','start','end','state')},case_id=snapshot['case_id'],
        observations=observations,total_risk_groups=len(risks),omitted_risk_groups=len(risks)-len(chosen),
        background_counts=(snapshot.get('supporting_evidence') or {}).get('types',{}),
        preset_stage_mapping=stages,preset_mapping_is_not_progress=True,queue=snapshot['queue'],
        evidence_scope='synthetic_integration_test' if snapshot.get('summary_validation_only') else 'observed_logs')


def enqueue(store,snapshot,retry=False):
    if getattr(store,'presentation_mode','')=='post_finish':
        from investigation import schedule
        return schedule(store,snapshot['run']['id'],retry)
    if not getattr(store,'summary_enabled',False):return {'state':'disabled'}
    if store.waiting_for_begin() or not snapshot['risk_events']:return {'state':'waiting_for_evidence'}
    data=payload(snapshot);rid=data['run']['id'];cid=case_id(store,rid)
    if cid is None or cid!=data['case_id']:raise ValueError('summary case not bound')
    digest=hashlib.sha256(canonical(data)).hexdigest();job_id=hashlib.sha256((rid+':'+str(cid)+':'+digest).encode()).hexdigest()
    key='summary_job:'+job_id;job=read(store,key)
    with store.db:
        if job is None:
            job=dict(id=job_id,run=rid,case_id=cid,input_hash=digest,payload=data,state='pending',attempts=0,next_try=0,created_at=now())
            write(store,key,job)
        elif retry and job['state']=='failed':
            job.update(state='pending',attempts=0,next_try=0);write(store,key,job)
        write(store,'summary_requested:'+rid,job_id)
    return {'state':job['state'],'job_id':job_id,'case_id':cid}


def claim(store,client=None):
    if not getattr(store,'summary_enabled',False) or store.waiting_for_begin():return None
    post_finish=getattr(store,'presentation_mode','')=='post_finish'
    if post_finish:
        from investigation import before_claim
        before_claim(store)
    rows=store.db.execute("SELECT value FROM metadata WHERE key LIKE 'summary_job:%'").fetchall()
    for job in sorted((json.loads(r['value']) for r in rows),key=lambda j:j['created_at']):
        if post_finish and job['payload'].get('schema')!='finished-case-investigation-v1':continue
        if read(store,'summary_requested:'+job['run'])!=job['id']:continue
        if job['state']=='running' and job.get('lease_until',0)>time.time():continue
        if job['state'] not in ('pending','running') or job.get('next_try',0)>time.time():continue
        if case_id(store,job['run'])!=job['case_id']:continue
        if job['attempts']>=3:
            job.update(state='failed',error='retry_limit')
            with store.db:write(store,'summary_job:'+job['id'],job)
            continue
        job.update(state='running',token=uuid.uuid4().hex,lease_until=time.time()+600,attempts=job['attempts']+1)
        with store.db:write(store,'summary_job:'+job['id'],job)
        return dict({k:job[k] for k in ('id','run','case_id','token','payload')},cached_response=job.get('cached_response'))
    return None


def active_job(store,request):
    job=read(store,'summary_job:'+request['id'])
    if not job or job.get('token')!=request.get('token') or job['state']!='running':raise ValueError('expired summary job')
    return job


def fail(store,request):
    job=active_job(store,request)
    code=str(request.get('error','summary_failed'))
    if not re.fullmatch(r'[a-z0-9_]{1,80}',code):code='summary_failed'
    job.update(state='failed' if job['attempts']>=3 else 'pending',error=code,next_try=time.time()+min(900,60*3**(job['attempts']-1)))
    with store.db:write(store,'summary_job:'+job['id'],job)
    return {'state':job['state'],'error':code}


def validate_summary(result,data):
    if not isinstance(result,dict) or set(result)!={'overview','observations','assessment','gaps','next_steps'}:raise ValueError('invalid summary schema')
    for key in ('overview','assessment'):
        if not isinstance(result[key],str) or len(result[key])>2500:raise ValueError('invalid summary text')
    refs={r['reference'] for r in data['observations']}
    if not isinstance(result['observations'],list) or not (1 if data['observations'] else 0)<=len(result['observations'])<=30:raise ValueError('invalid observations')
    for entry in result['observations']:
        if not isinstance(entry,dict) or set(entry)!={'text','references'}:raise ValueError('invalid observation')
        if not isinstance(entry['text'],str) or not 1<=len(entry['text'])<=1500:raise ValueError('invalid observation text')
        if not isinstance(entry['references'],list) or not entry['references'] or any(not isinstance(r,str) or r not in refs for r in entry['references']):raise ValueError('unknown evidence reference')
    for key in ('gaps','next_steps'):
        if not isinstance(result[key],list) or len(result[key])>20 or any(not isinstance(v,str) or len(v)>1500 for v in result[key]):raise ValueError('invalid summary list')
    return result


def validate(result,data):
    if data.get('schema')=='finished-case-investigation-v1':
        from investigation import validate as validate_investigation
        return validate_investigation(result,data)
    return validate_summary(result,data)


def markdown(job,result):
    safe=lambda text:html.escape(text,quote=False)
    is_agent=job['payload'].get('analysis_engine')=='agent-v1'
    rows=['### 事件研判摘要' if is_agent else '### AI 案件摘要（待人工核实）','',
        '模型：gpt-6.1-sol；推理强度：xhigh。运行：'+job['run']+'。',
        ('根据本轮 Wazuh Alert 及实际只读查询研判；当前快照与历史日志分开判断。' if job['payload'].get('analysis_engine')=='agent-v1' else ('仅根据本轮 Wazuh Alert 事实研判；结论及证据缺口由模型说明。' if job['payload'].get('schema')=='finished-case-investigation-v1' else '仅根据本轮脱敏证据生成；预设阶段不表示实际进度或攻击成功。')),'',
        '**事件定性**' if is_agent else '**概况**',safe(result['overview']),'','**主要证据**' if is_agent else '**已观察记录**']
    for item in result['observations']:rows+=['- '+safe(item['text'])+'（证据：'+', '.join(item['references'])+'）']
    rows+=['','**攻击性质、手段与影响**' if is_agent else '**分析与不确定性**',safe(result['assessment']),'','**证据缺口**']+['- '+safe(x) for x in result['gaps']]
    rows+=['','**后续核查建议**']+['- '+safe(x) for x in result['next_steps']]
    if job['payload']['omitted_risk_groups']:rows+=['','输入仅包含部分事件组；另有 '+str(job['payload']['omitted_risk_groups'])+' 组未发送模型，请查看完整时间线。']
    metadata=(job.get('cached_response') or {}).get('response_metadata') or {}
    if metadata.get('completion_verified') is False:
        rows+=['','生成记录：从本次请求保存的完整正文恢复，结构及证据引用已校验。接口完成帧未取得；上方模型与推理强度为请求配置，未再次核验返回模型标识，Token 用量未知。']
    return '\n'.join(rows)


def publish(store,client,request):
    job=active_job(store,request)
    if read(store,'summary_requested:'+job['run'])!=job['id']:
        job['state']='superseded'
        with store.db:write(store,'summary_job:'+job['id'],job)
        return {'state':'superseded'}
    if case_id(store,job['run'])!=job['case_id']:raise ValueError('summary case changed')
    investigation=job['payload'].get('schema')=='finished-case-investigation-v1'
    if investigation:
        from investigation import publish_current
        if not publish_current(store,job):
            job['state']='superseded'
            with store.db:write(store,'summary_job:'+job['id'],job)
            return {'state':'superseded'}
    result=validate(request['result'],job['payload'])
    if request.get('model')!='gpt-6.1-sol' or request.get('effort')!='xhigh':raise ValueError('unexpected model')
    # Persist validated model output before IRIS I/O so transport retries do not bill again.
    job['cached_response']={k:request[k] for k in ('result','model','effort','usage','response_metadata') if k in request}
    with store.db:write(store,'summary_job:'+job['id'],job)
    text=markdown(job,result);block=BEGIN+'\n'+text+'\n'+END
    client=for_run(store,client,job['run'])
    if investigation:
        for observation in job['payload']['observations']:
            for aid in observation['alert_ids']:client.merge(aid,note='关联本轮 Wazuh 原始告警；案件研判由 finish 后的 AI 分析提供。')
    old=client.request('case/summary/fetch?cid='+str(client.cid))
    previous=read(store,'summary_written:'+job['run'])
    description=old.get('case_description') or ''
    match=re.search(re.escape(BEGIN)+r'.*?'+re.escape(END),description,re.S)
    # An analyst edit to the generated block must not be overwritten automatically.
    expected_hash=previous['block_hash'] if previous else hashlib.sha256(INITIAL_BLOCK.encode()).hexdigest()
    if not match or (match[0]!=block and hashlib.sha256(match[0].encode()).hexdigest()!=expected_hash):
        job.update(state='conflict',error='analyst_edited_summary',result=result)
        with store.db:write(store,'summary_job:'+job['id'],job)
        return {'state':'conflict','case_id':client.cid}
    updated=description[:match.start()]+block+description[match.end():] if match else description+'\n\n'+block
    sections=None
    if investigation:
        from case_writer import plan,apply
        operations,conflicts=plan(store,client,job,result)
        if conflicts:
            job.update(state='conflict',error='analyst_edited_case_content',conflicts=conflicts,result=result)
            with store.db:write(store,'summary_job:'+job['id'],job)
            return {'state':'conflict','case_id':client.cid,'sections':conflicts}
        sections=apply(store,client,job,result,operations)
    latest=client.request('case/summary/fetch?cid='+str(client.cid))
    if latest.get('case_description')!=old.get('case_description'):raise ValueError('summary changed concurrently')
    client.request('case/summary/update?cid='+str(client.cid),{'case_description':updated})
    actual=client.request('case/summary/fetch?cid='+str(client.cid))
    if actual.get('case_description')!=updated:raise ValueError('summary write not verified')
    usage=None if request.get('usage') is None else {k:int(request['usage'].get(k,0) or 0) for k in ('input_tokens','output_tokens','total_tokens')}
    job.update(state='done',result=result,completed_at=now(),usage=usage,error=None)
    with store.db:
        write(store,'summary_job:'+job['id'],job)
        write(store,'summary_written:'+job['run'],{'job_id':job['id'],'block_hash':hashlib.sha256(block.encode()).hexdigest(),'markdown':text,'at':now(),'case_id':client.cid})
    path=store.root/'reports'/job['run'];path.mkdir(mode=0o700,parents=True,exist_ok=True)
    file=path/'case-summary.md';temp=path/'.case-summary.tmp';temp.write_text(text+'\n');temp.chmod(0o600);temp.replace(file)
    return {'state':'done','run':job['run'],'case_id':client.cid,'usage':usage,'sections':sections}


def status(store,run):
    requested=read(store,'summary_requested:'+run)
    job=read(store,'summary_job:'+requested) if requested else None
    if job:
        result={k:job.get(k) for k in ('id','state','case_id','error','completed_at','usage')}
        if job['payload'].get('analysis_engine')=='agent-v1':
            state=read(store,'agent_state:'+job['id']) or {}
            result['agent']={'step':state.get('step',0),'queries':state.get('queries',0),'tasks':[{k:t[k] for k in ('id','title','state')} for t in state.get('tasks',[])],'last_action':(state.get('actions') or [None])[-1]}
        return result
    if getattr(store,'presentation_mode','')=='post_finish':return {'state':'waiting_for_delivery' if read(store,'analysis_finish:'+run) else 'waiting_for_finish'}
    return {'state':'waiting_for_evidence'}
