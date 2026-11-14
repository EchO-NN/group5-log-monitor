"""Durable investigation tools, scoped to one finish-authorized IRIS case."""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import posixpath
import re
import time
from core import canonical,now,timestamp
from case_runs import for_run
from summary_jobs import read,write,BEGIN,END
import case_writer

POLICY=json.loads(Path(__file__).with_name('agent_policy.json').read_text())
HOSTS={h['id']:h for h in POLICY['hosts'] if h.get('active_query',True)}
FILE_HOSTS=dict(HOSTS,A=dict(id='A',role=0,address='100.74.217.99',description='仅监控项目目录内的Agent代码与调查报告'))
SCHEMA='agent-v1'


def error(code):raise ValueError(code)


def limits(job):
    value={k:POLICY[k] for k in ('max_steps','max_queries','max_tasks','max_total_tokens')}
    # Trusted operator metadata can extend a specific interrupted investigation.
    # This field is not exposed as a model tool argument.
    for key,ceiling in (('max_steps',192),('max_queries',32),('max_total_tokens',12000000)):
        override=job.get('agent_limits',{}).get(key)
        if type(override) is int and value[key]<=override<=ceiling:value[key]=override
    return value


def text(value,limit=1000):
    if not isinstance(value,str) or not 1<=len(value)<=limit or not re.search('[\u4e00-\u9fff]',value):error('Chinese text required')
    if any(ord(c)<32 and c not in '\n\t' for c in value):error('control characters denied')
    return value


def initial(job):
    observations=[]
    for n,o in enumerate(job['payload']['observations'],1):
        item=copy.deepcopy(o);item['source_reference']=item['reference'];item['reference']='A'+str(n).zfill(3);observations.append(item)
        identity=next((h['id'] for h in POLICY['hosts'] if h['address']==item.get('host_ip')),None)
        if identity:item['source_host']=item['host'];item['host']=identity
    return dict(version=1,job_id=job['id'],run=job['run'],case_id=job['case_id'],step=0,queries=0,observations=observations,tasks=[],results=[],active_query=None,
        result=dict(overview='',observations=[],assessment='',gaps=[],next_steps=[],timeline=[],tasks=[],assets=[],notes=[],evidence=[]),
        keys={s:[] for s in ('timeline','assets','notes','evidence')},actions=[],complete=False,timeline_chain_required=True,total_usage={'input_tokens':0,'output_tokens':0,'total_tokens':0})


def save(store,state):
    with store.db:write(store,'agent_state:'+state['job_id'],state)


def state_for(store,job):
    state=read(store,'agent_state:'+job['id'])
    if state is None:state=initial(job);save(store,state)
    if 'read_evidence_memory' not in state or state.get('read_evidence_memory_version')!=2:
        state['read_evidence_memory']={}
        for row in store.db.execute('SELECT value FROM metadata WHERE key LIKE ?',('agent_receipt:'+job['id']+':%',)):
            for entry in json.loads(row['value']).get('result',{}).get('evidence',[]):remember_evidence(state,entry)
        state['read_evidence_memory_version']=2
        save(store,state)
    if 'saved_telemetry_catalog' not in state:
        from collected_evidence import catalog
        state['saved_telemetry_catalog']=catalog(store,job['run']);save(store,state)
    return state


def remember_evidence(state,entry):
    value=model_evidence(entry['data'])
    # Retain the bounded page actually returned by read_evidence. Truncating it
    # again erased late-page facts between steps and caused repeated rereads.
    state.setdefault('read_evidence_memory',{})[entry['reference']]=value


def references(state,refs,allow_empty=False):
    known={o['reference'] for o in state['observations']}
    if not isinstance(refs,list) or len(refs)>100 or (not refs and not allow_empty) or any(not isinstance(r,str) or r not in known for r in refs):error('unknown evidence references')
    return list(dict.fromkeys(refs))


def writer_job(job,state):return dict(job,payload=dict(job['payload'],observations=state['observations']))


def model_evidence(value):
    """Keep continuation internals in durable storage, not model context."""
    if isinstance(value,list):return [model_evidence(v) for v in value]
    if isinstance(value,dict):return {k:model_evidence(v) for k,v in value.items() if k not in ('cursor','continuation')}
    return value


def pending_audits(state,task_id=None):
    continued={r.get('continued_from') for r in state['results']}
    return [dict(reference=r['reference'],task_id=r['task_id'],host=r['result']['host'],page=r['result'].get('page'),
                 has_more=r['result'].get('has_more',False),next_page_from=r['reference'] if r['result'].get('continuation') else None,retry_from=r['reference'] if not r['result']['ok'] or ('page' not in r['result'] and r['result'].get('truncated')) else None,
                 error=r['result'].get('error'),coverage_complete=False)
            for r in state['results'] if r['result']['query']=='audit' and r['reference'] not in continued
            and (task_id is None or r['task_id']==task_id) and not r['result'].get('coverage_complete',not r['result'].get('truncated',False) and r['result']['ok'])]


def context(state,job):
    alerts=[{k:o[k] for k in ('reference','first_seen','last_seen','count','host','host_ip','rule_id','level','rule_description') if k in o} for o in state['observations'] if o['reference'].startswith('A')]
    summaries=[]
    for record in state['results'][-4:]:
        result=record['result'];summaries.append(dict(reference=record['reference'],task_id=record['task_id'],host=result['host'],query=result['query'],ok=result['ok'],truncated=result.get('truncated',False),scope=result.get('scope','historical_window'),record_count=len(result.get('records',[])),records=result.get('records',[])[:12],error=result.get('error'),page=result.get('page'),has_more=result.get('has_more',False),coverage_complete=result.get('coverage_complete'),next_page_from=record['reference'] if result.get('continuation') else None))
    return dict(job_id=job['id'],case_id=state['case_id'],run=job['payload']['run'],evidence_scope=job['payload'].get('evidence_scope'),step=state['step'],complete=state['complete'],
        hosts=POLICY['hosts'],file_hosts=[{k:h[k] for k in ('id','address','description')} for h in FILE_HOSTS.values()],file_access='VM2至VM9普通文件只读；A仅限'+POLICY['local_file_root']+'；VM1及B/C宿主机禁止主动查询；凭据正文过滤，无通用命令执行',limits=limits(job),queries_used=state.get('primary_queries',state['queries']),query_pages=state['queries'],pending_audit_pages=pending_audits(state),
        alerts=alerts,tasks=state['tasks'],recent_query_results=summaries,recorded_sections={k:len(state['result'][k]) for k in state['keys']},
        summary_written=bool(state['result']['overview']),actions=state['actions'][-6:],active_query=state['active_query'],total_usage=state['total_usage'],
        evidence_coverage=sorted({r for e in state['result']['evidence'] for r in e['references']}),written_records=state['result'],
        already_read_evidence=model_evidence(state.get('read_evidence_memory',{})),
        record_keys=state['keys'],saved_telemetry_catalog=state.get('saved_telemetry_catalog',[]),revision_request=job.get('revision_request'),
        memory_note='already_read_evidence 持久保留此前read_evidence实际返回的完整页，不再二次截取页首。preview_truncated仍表示原工具自身的有界子集。请直接利用已读页的全部记录，尤其核对页末字段，推进任务与案件写入，勿反复原样重读。')


def sync_section(store,client,job,state,section):
    result=state['result'];selected={'timeline','tasks','assets','notes'} & {section}
    operations,conflicts=case_writer.plan(store,client,writer_job(job,state),result,sections=selected,prune=False)
    if conflicts:error('analyst_content_conflict')
    counts=case_writer.apply(store,client,writer_job(job,state),result,operations,finalize=section=='evidence')
    if section=='evidence':
        saved=read(store,'case_sections:'+job['run']);saved['counts']={k:len(result[k]) for k in ('timeline','tasks','assets','notes','evidence')}
        with store.db:write(store,'case_sections:'+job['run'],saved)
    return counts


def sync_summary(store,client,job,state):
    from summary_jobs import markdown
    from case_runs import INITIAL_BLOCK
    result=state['result'];report_job=writer_job(job,state)
    body=markdown(report_job,result)+'\n\n调查方式：Agent 根据任务调用白名单只读工具；查询结果、当前状态与历史事实分开记录。'
    block=BEGIN+'\n'+body+'\n'+END
    current=client.request('case/summary/fetch?cid='+str(client.cid))['case_description'] or ''
    match=re.search(re.escape(BEGIN)+r'.*?'+re.escape(END),current,re.S)
    previous=read(store,'summary_written:'+job['run'])
    expected=previous['block_hash'] if previous else hashlib.sha256(INITIAL_BLOCK.encode()).hexdigest()
    if not match or (match[0]!=block and hashlib.sha256(match[0].encode()).hexdigest()!=expected):error('analyst_summary_conflict')
    updated=current[:match.start()]+block+current[match.end():]
    if updated!=current:client.request('case/summary/update?cid='+str(client.cid),{'case_description':updated})
    if client.request('case/summary/fetch?cid='+str(client.cid))['case_description']!=updated:error('summary_verification_failed')
    with store.db:write(store,'summary_written:'+job['run'],{'job_id':job['id'],'block_hash':hashlib.sha256(block.encode()).hexdigest(),'markdown':body,'at':now(),'case_id':client.cid})
    from bridge import atomic
    atomic(store.root/'reports'/job['run']/'case-summary.md',body.encode())


def record_case(store,client,job,state,args):
    if set(args)!={'section','record_json','purpose'}:error('record arguments')
    section=args['section'];payload=json.loads(args['record_json'])
    if len(args['record_json'])>10000:error('record too large')
    if section=='summary':
        if state['active_query'] or any(t['state'] not in ('completed','blocked') for t in state['tasks']):error('finish investigation tasks before summary')
        if set(payload)!={'overview','observations','assessment','gaps','next_steps'}:error('summary fields')
        for key in ('overview','assessment'):text(payload[key],1500)
        for key in ('gaps','next_steps'):
            if not isinstance(payload[key],list) or len(payload[key])>6:error('summary list')
            for value in payload[key]:text(value,400)
        if not isinstance(payload['observations'],list) or len(payload['observations'])>8:error('summary observations')
        for o in payload['observations']:
            if set(o)!={'text','references'}:error('observation fields')
            text(o['text'],600);references(state,o['references'])
        state['result'].update(payload);save(store,state);sync_summary(store,client,job,state)
        return {'written':'summary'}
    shapes={'notes':{'key','title','content','references'},'timeline':{'key','at','title','content','references'},'assets':{'key','host','description','references'},'evidence':{'key','title','description','references'}}
    limits={'notes':6,'timeline':15,'assets':9,'evidence':10}
    if section not in shapes or set(payload)!={'items'} or not isinstance(payload['items'],list) or not 1<=len(payload['items'])<=3:error('record section')
    by_ref={o['reference']:o for o in state['observations']}
    for supplied in payload['items']:
        item=dict(supplied)
        optional={'links','chain_note'} if section=='timeline' else set()
        if set(item)-optional!=shapes[section] or not re.fullmatch('[A-Za-z0-9_-]{1,24}',str(item['key'])):error('record fields')
        key=item.pop('key');refs=references(state,item['references'],allow_empty=not by_ref and section=='notes')
        for field in ('title','content','description'):
            if field in item:text(item[field],120 if field=='title' else 1000)
        if section=='assets' and not any(by_ref[r]['host']==item['host'] for r in refs):error('asset not evidenced')
        if section=='timeline':
            at=timestamp(item['at'])
            if at is None or not any(by_ref[r]['first_seen']<=at<=by_ref[r]['last_seen'] for r in refs):error('timeline not evidenced')
            if state.get('timeline_chain_required') and not {'links','chain_note'}<=set(item):error('timeline chain links and chain_note required')
            if 'links' in item or 'chain_note' in item:
                validate_links(state,item,key,at);item['chain_key']=key
        keys=state['keys'][section]
        if key in keys:state['result'][section][keys.index(key)]=item
        else:
            if len(keys)>=limits[section]:error('section limit')
            keys.append(key);state['result'][section].append(item)
    if section=='assets' and len({x['host'] for x in state['result']['assets']})!=len(state['result']['assets']):error('duplicate asset')
    save(store,state);sync_section(store,client,job,state,section)
    return {'written':section,'count':len(state['result'][section])}


def validate_links(state,item,key,at):
    text(item.get('chain_note'),500)
    links=item.get('links')
    if not isinstance(links,list) or len(links)>4:error('timeline links required')
    seen=set()
    for link in links:
        if not isinstance(link,dict) or set(link)!={'from','relation','confidence','basis','references'}:error('timeline link fields')
        previous=link['from']
        if previous==key or previous in seen or previous not in state['keys']['timeline']:error('timeline predecessor missing or cyclic')
        seen.add(previous);source=state['result']['timeline'][state['keys']['timeline'].index(previous)]
        frontier=[previous];visited=set()
        while frontier:
            ancestor=frontier.pop()
            if ancestor==key:error('timeline link cycle')
            if ancestor in visited:continue
            visited.add(ancestor)
            node=state['result']['timeline'][state['keys']['timeline'].index(ancestor)]
            frontier.extend(edge['from'] for edge in node.get('links',[]))
        if timestamp(source['at'])>at:error('timeline predecessor occurs later')
        if link['relation'] not in ('causal','enables','continuation','temporal') or link['confidence'] not in ('confirmed','inferred'):error('timeline link classification')
        text(link['basis'],500);references(state,link['references'])
        if not set(link['references'])<=set(item['references']):error('timeline link evidence not in event references')
    # Updating an existing node must not reverse an existing edge's time order.
    for target in state['result']['timeline']:
        if any(link['from']==key for link in target.get('links',[])) and at>timestamp(target['at']):error('timeline successor occurs earlier')


def prepare_file_query(store,client,job,state,args,request_id):
    fields={'task_id','host','operation','path','match','continue_from','purpose'}
    if set(args)!=fields:error('file query fields')
    host=FILE_HOSTS.get(args['host']);task=next((t for t in state['tasks'] if t['id']==args['task_id']),None)
    if not host or not task or task['state'] in ('completed','blocked'):error('file query requires an open task')
    if args['operation'] not in ('list','stat','read','search'):error('file operation denied')
    if not isinstance(args['path'],str) or not args['path'].startswith('/') or len(args['path'])>4096 or any(ord(c)<32 for c in args['path']):error('absolute file path required')
    if host['role']==0 and not Path(posixpath.normpath(args['path'])).is_relative_to(POLICY['local_file_root']):error('local files limited to monitoring project')
    if not isinstance(args['match'],str) or len(args['match'])>160 or any(ord(c)<32 for c in args['match']):error('file match denied')
    if state['active_query']:
        if state['active_query']['source_step']==request_id:return {'permit':state['active_query']}
        error('query already pending')
    old=next((r for r in state['results'] if r.get('source_step')==request_id),None)
    if old:return {'already_executed':old['reference']}
    run=job['payload']['run'];request=dict(role=host['role'],query='files',start=run['start'],end=run['end'],operation=args['operation'],path=args['path'],match=args['match'])
    previous=args['continue_from']
    if not isinstance(previous,str):error('file continuation reference')
    if previous:
        parent=next((r for r in state['results'] if r['reference']==previous),None)
        if not parent or parent['task_id']!=task['id']:error('file continuation task mismatch')
        evidence=read(store,'agent_evidence:'+job['id']+':'+previous)
        if {k:v for k,v in evidence['query'].items() if k!='cursor'}!=request:error('file continuation scope mismatch')
        if any(r.get('continued_from')==previous for r in state['results']):error('file page already continued use latest reference')
        if parent['result'].get('continuation'):request['cursor']=copy.deepcopy(parent['result']['continuation'])
        elif not parent['result']['ok']:
            if parent['result'].get('error')!='file_unavailable_or_changed' and evidence['query'].get('cursor'):request['cursor']=copy.deepcopy(evidence['query']['cursor'])
        else:error('file query has no next page')
    # File discovery is iterative: count it separately from the 10 fixed telemetry queries.
    state.setdefault('primary_queries',state['queries']);state['queries']+=1;state['file_queries']=state.get('file_queries',0)+1
    permit=dict(id='Q'+str(state['queries']).zfill(3),reference='E'+str(state['queries']).zfill(3),task_id=task['id'],purpose=args['purpose'],request=request,source_step=request_id,continued_from=previous or None)
    set_task_status(store,client,job,state,task,2);state['active_query']=permit;task['state']='investigating';save(store,state)
    return {'permit':permit}


def plan_tasks(store,client,job,state,args):
    if set(args)!={'tasks','purpose'} or not isinstance(args['tasks'],list) or not 1<=len(args['tasks'])<=POLICY['max_tasks']:error('tasks shape')
    for task in args['tasks']:
        if set(task)!={'id','title','description','references'} or not re.fullmatch('T[0-9]{2}',str(task['id'])):error('task fields')
        text(task['title'],120);text(task['description'],800);references(state,task['references'])
        existing=next((t for t in state['tasks'] if t['id']==task['id']),None)
        if existing:
            if any(existing[k]!=task[k] for k in task):error('task already exists with different content')
            continue
        if len(state['tasks'])>=POLICY['max_tasks']:error('task limit')
        state['tasks'].append(dict(task,state='open',query_refs=[],conclusion=''))
        state['result']['tasks'].append({k:task[k] for k in ('title','description','references')})
    # A later evidence snapshot can revise the same run. Carry only task status
    # previously written by this executor, so the next query can reopen it safely.
    for index,task in enumerate(state['tasks']):
        saved_status=read(store,'agent_task_status:'+job['run']+':'+str(index+1).zfill(3))
        if saved_status and 'native_status' not in task:task['native_status']=saved_status['status']
    save(store,state);sync_section(store,client,job,state,'tasks')
    return {'tasks':state['tasks']}


def set_task_status(store,client,job,state,task,target):
    index=state['tasks'].index(task);obj=read(store,'case_object:'+job['run']+':tasks:'+str(index+1).zfill(3))
    if not obj:error('task not registered')
    current=next(t for t in case_writer.listing(client,'tasks') if t['task_id']==obj['id'])
    if current['task_status_id'] not in (task.get('native_status',1),target):error('analyst_task_state_conflict')
    body={k:current[k] for k in ('task_title','task_description')};body.update(task_status_id=target,task_assignees_id=[a['id'] for a in current.get('task_assignees',[])],task_tags=current.get('task_tags','G5AI'),custom_attributes=current.get('custom_attributes') or {})
    client.request('case/tasks/update/'+str(obj['id'])+'?cid='+str(client.cid),body)
    actual=next(t for t in case_writer.listing(client,'tasks') if t['task_id']==obj['id'])
    if actual['task_status_id']!=target:error('task status write not verified')
    task['native_status']=target;save(store,state)
    with store.db:write(store,'agent_task_status:'+job['run']+':'+str(index+1).zfill(3),{'status':target})


def prepare_query(store,client,job,state,args,request_id):
    if set(args)-{'continue_from'}!={'task_id','host','query','match','purpose'}:error('query fields')
    task=next((t for t in state['tasks'] if t['id']==args['task_id']),None)
    if not task or task['state'] in ('completed','blocked'):error('task not open')
    host=HOSTS.get(args['host'])
    if not host or args['query'] not in host['queries']:error('query host or capability denied')
    if not isinstance(args['match'],str) or len(args['match'])>80 or any(ord(c)<32 for c in args['match']):error('query match denied')
    if state['active_query']:
        if state['active_query']['source_step']==request_id:return {'permit':state['active_query']}
        error('query already pending')
    previous=next((r for r in state['results'] if r.get('source_step')==request_id),None)
    if previous:return {'already_executed':previous['reference']}
    run=job['payload']['run'];start=dt.datetime.fromisoformat(run['start']);end=dt.datetime.fromisoformat(run['end'])
    if not 0<(end-start).total_seconds()<=POLICY['max_window_seconds']:error('run window exceeds query policy')
    padding=dt.timedelta(seconds=POLICY['window_padding_seconds'])
    request={'role':host['role'],'query':args['query'],'start':(start-padding).isoformat(),'end':(end+padding).isoformat(),'match':args['match']}
    continuation=args.get('continue_from','')
    if not isinstance(continuation,str):error('continuation reference required')
    if continuation:
        parent=next((r for r in state['results'] if r['reference']==continuation),None)
        if args['query']!='audit' or not parent or parent['task_id']!=task['id']:error('audit continuation task mismatch')
        if any(r.get('continued_from')==continuation for r in state['results']):error('audit page already continued use latest reference')
        cursor=parent['result'].get('continuation')
        old_request=read(store,'agent_evidence:'+job['id']+':'+continuation)['query']
        if {k:v for k,v in old_request.items() if k!='cursor'}!=request:error('audit continuation scope mismatch')
        if parent['result'].get('has_more') and cursor:request['cursor']=copy.deepcopy(cursor)
        elif not parent['result']['ok']:
            # Transport retry keeps the same cursor. A lost snapshot must be reread.
            if parent['result'].get('error')!='audit_snapshot_unavailable_restart_query' and old_request.get('cursor'):request['cursor']=copy.deepcopy(old_request['cursor'])
        elif 'page' not in parent['result'] and parent['result'].get('truncated'):
            pass # Legacy tail-only result: explicitly restart from retained logs.
        else:error('audit continuation unavailable record coverage gap')
    state.setdefault('primary_queries',state['queries'])
    if not continuation and state['primary_queries']>=limits(job)['max_queries']:error('query budget exhausted')
    if not continuation:state['primary_queries']+=1
    state['queries']+=1
    permit={'id':'Q'+str(state['queries']).zfill(3),'reference':'E'+str(state['queries']).zfill(3),'task_id':task['id'],'purpose':args['purpose'],
        'request':request,'source_step':request_id,'continued_from':continuation or None}
    set_task_status(store,client,job,state,task,2)
    state['active_query']=permit;task['state']='investigating';save(store,state)
    return {'permit':permit}


def record_query(store,job,state,payload):
    permit=state['active_query']
    if permit is None:
        existing=next((r for r in state['results'] if r['query_id']==payload.get('query_id')),None)
        if existing:return dict(reference=existing['reference'],result=model_evidence(existing['result']),ok=existing['result']['ok'])
        error('no query pending')
    result=payload['result'];request=permit['request']
    if payload['query_id']!=permit['id'] or len(canonical(result))>128000:error('query result mismatch')
    if request['role'] not in (0,*range(2,10)):error('query host no longer permitted')
    if result.get('host')!={0:'A'}.get(request['role'],'VM'+str(request['role'])) or result.get('query')!=request['query'] or type(result.get('ok')) is not bool:error('query origin mismatch')
    if not isinstance(result.get('records'),list) or len(result['records'])>100:error('query records invalid')
    if result.get('requested_start')!=request['start'] or result.get('requested_end')!=request['end']:error('query window mismatch')
    if timestamp(result.get('collected_at')) is None:error('query collection timestamp')
    from core import redact
    from fact_alerts import safe
    # The executor only sends the fixed script's output; redact known lab credentials again before storage/model exposure.
    result=redact(result,getattr(store,'secrets',()))
    result=json.loads(re.sub(r'\bsk-[A-Za-z0-9_-]{12,}\b','[REDACTED]',json.dumps(result,ensure_ascii=False)))
    ref=permit['reference'];key='agent_evidence:'+job['id']+':'+ref
    evidence={'schema':'agent-readonly-query-v1','reference':ref,'task_id':permit['task_id'],'purpose':permit['purpose'],'query':request,'result':result}
    with store.db:write(store,key,evidence)
    blob=canonical(evidence);digest=store.blob('agent-query',blob)
    at=result['collected_at'];first=request['start'];last=request['end']
    if result.get('scope') in ('current_snapshot_not_historical','current_file_snapshot'):first=last=at
    host=FILE_HOSTS[result['host']]
    source='saved_monitor_telemetry' if result.get('scope')=='historical_saved_telemetry' else 'local_readonly_files' if request['role']==0 else 'pinned_management_ssh'
    state['observations'].append(dict(reference=ref,first_seen=first,last_seen=last,count=len(result['records']),host=host['id'],host_ip=host['address'],rule_id='readonly-query',level=0,rule_description=permit['purpose'],source=source,fields={},message='',alert_ids=[],evidence_key=key))
    state['results'].append(dict(query_id=permit['id'],reference=ref,task_id=permit['task_id'],source_step=permit['source_step'],sha256=digest,result=result,continued_from=permit.get('continued_from')))
    task=next(t for t in state['tasks'] if t['id']==permit['task_id']);task['query_refs'].append(ref)
    state['active_query']=None;save(store,state)
    return {'reference':ref,'ok':result['ok'],'record_count':len(result['records']),'sha256':digest,'result':model_evidence(result),'next_page_from':ref if result.get('continuation') else None}


def update_task(store,client,job,state,args):
    if set(args)!={'task_id','state','conclusion','references','purpose'} or args['state'] not in ('completed','blocked'):error('task update fields')
    task=next((t for t in state['tasks'] if t['id']==args['task_id']),None)
    if not task:error('task missing')
    refs=references(state,args['references']);text(args['conclusion'],1000)
    results=[r for r in state['results'] if r['task_id']==task['id'] and r['reference'] in refs]
    if args['state']=='completed' and not any(r['result']['ok'] for r in results):error('task completion requires actual successful query')
    if args['state']=='completed' and pending_audits(state,task['id']):error('audit coverage incomplete continue pages or mark task blocked with coverage gap')
    index=state['tasks'].index(task);obj=read(store,'case_object:'+job['run']+':tasks:'+str(index+1).zfill(3))
    if not obj:error('task not registered')
    current=next(t for t in case_writer.listing(client,'tasks') if t['task_id']==obj['id'])
    expected=task.get('native_status',1)
    target=4 if args['state']=='completed' else 3
    if current['task_status_id'] not in (expected,target):error('analyst_task_state_conflict')
    task.update(state=args['state'],conclusion=args['conclusion'])
    state['result']['tasks'][index]['description']=task['description']+'\n\n调查结论：'+args['conclusion']+'\n状态：'+('只读调查已执行，不等于已执行处置。' if target==4 else '调查受阻，仍待处理。')
    state['result']['tasks'][index]['references']=list(dict.fromkeys(task['references']+refs));save(store,state);sync_section(store,client,job,state,'tasks')
    set_task_status(store,client,job,state,task,target)
    return {'task_id':task['id'],'state':task['state']}


def finish_case(store,client,job,state,args):
    if set(args)!={'purpose'}:error('finish fields')
    original={o['reference'] for o in state['observations'] if o['reference'].startswith('A')}
    if state['active_query'] or any(t['state'] not in ('completed','blocked') for t in state['tasks']):error('investigation tasks unfinished')
    if original and (not state['tasks'] or not state['results']):error('actual investigation required')
    if not state['result']['overview'] or not state['result']['notes']:error('summary and notes required')
    if original and (not state['result']['timeline'] or not state['result']['assets']):error('timeline and assets required')
    if state.get('timeline_chain_required') and any(not {'links','chain_note','chain_key'}<=set(e) for e in state['result']['timeline']):error('timeline chain annotations incomplete')
    covered={r for e in state['result']['evidence'] for r in e['references']}
    if not {o['reference'] for o in state['observations']}<=covered:error('evidence coverage incomplete')
    from investigation import publish_current
    if not publish_current(store,job):
        job.update(state='superseded',error='new_alerts_require_revision')
        with store.db:write(store,'summary_job:'+job['id'],job)
        return {'state':'superseded','run':job['run'],'case_id':job['case_id'],'reason':'new_alerts_require_revision'}
    # A fresh revision may contain fewer nodes/tasks. Prune only unchanged,
    # executor-owned records after the replacement investigation is complete.
    operations,conflicts=case_writer.plan(store,client,writer_job(job,state),state['result'],prune=True)
    if conflicts:error('analyst_content_conflict')
    case_writer.apply(store,client,writer_job(job,state),state['result'],operations,finalize=False)
    for o in job['payload']['observations']:
        for aid in o['alert_ids']:client.merge(aid,note='关联本轮原始告警；调查任务及只读查询记录见 Case。')
    sync_section(store,client,job,state,'evidence');sync_summary(store,client,job,state)
    state['complete']=True;save(store,state)
    job.update(state='done',result=state['result'],completed_at=now(),usage=state['total_usage'],error=None)
    with store.db:write(store,'summary_job:'+job['id'],job)
    return {'state':'done','run':job['run'],'case_id':job['case_id'],'sections':{k:len(state['result'][k]) for k in ('timeline','tasks','assets','notes','evidence')},'queries':state['queries'],'usage':state['total_usage']}


def _dispatch(store,client,payload):
    job=read(store,'summary_job:'+payload['id'])
    if not job or job.get('token')!=payload.get('token') or job['payload'].get('analysis_engine')!=SCHEMA:error('agent job authorization')
    state=state_for(store,job);op=payload['operation'];client=for_run(store,client,job['run'])
    if op=='state':return context(state,job)
    if job['state'] not in ('running','done'):error('agent not running')
    if op=='archive_read':
        from collected_evidence import SOURCES,query
        permit=state['active_query']
        if not permit or permit['id']!=payload.get('query_id') or permit['request']['query'] not in SOURCES:error('archived query authorization')
        return query(store,job['run'],permit['request'])
    if op=='query_result':return record_query(store,job,state,payload)
    if op!='action':error('unknown agent operation')
    call=payload['call'];request_id=payload['request_id']
    if not re.fullmatch('step_[0-9]{4}',request_id):error('request identifier')
    digest=hashlib.sha256(canonical(call)).hexdigest();receipt_key='agent_receipt:'+job['id']+':'+request_id
    receipt=read(store,receipt_key)
    if receipt:
        if receipt['digest']!=digest:error('request reuse mismatch')
        return receipt['result']
    if job['state']!='running' or state['complete']:error('agent completed')
    budget=limits(job)
    if state['step']>=budget['max_steps']:error('agent step budget exhausted')
    if state['total_usage']['total_tokens']>=budget['max_total_tokens']:error('agent token budget exhausted')
    name=call['name'];args=call['arguments'];text(args.get('purpose'),300)
    if name=='create_tasks':result=plan_tasks(store,client,job,state,args)
    elif name=='query_host':result=prepare_query(store,client,job,state,args,request_id)
    elif name=='inspect_files':result=prepare_file_query(store,client,job,state,args,request_id)
    elif name=='query_collected':
        from collected_evidence import SOURCES
        if args.get('query') not in SOURCES:error('archived query denied')
        result=prepare_query(store,client,job,state,args,request_id)
    elif name=='read_evidence':
        if set(args)!={'references','purpose'} or len(args['references'])>4:error('read evidence arguments')
        refs=references(state,args['references']);result={'evidence':[]}
        for ref in refs:
            o=next(o for o in state['observations'] if o['reference']==ref)
            if o.get('evidence_key'):value=read(store,o['evidence_key'])
            else:value=read(store,'fact_alert:'+str(o['alert_ids'][0]))
            value=model_evidence(value)
            if isinstance(value,dict) and 'records' in value and len(value['records'])>20:value['records']=value['records'][:20];value['preview_truncated']=True
            result['evidence'].append({'reference':ref,'data':value})
            remember_evidence(state,result['evidence'][-1])
    elif name=='record_case':result=record_case(store,client,job,state,args)
    elif name=='update_task':result=update_task(store,client,job,state,args)
    elif name=='finish_case':result=finish_case(store,client,job,state,args)
    else:error('tool not allowed')
    state['step']+=1
    for key in state['total_usage']:state['total_usage'][key]+=max(0,int(payload.get('usage',{}).get(key,0) or 0))
    state['actions'].append({'step':state['step'],'tool':name,'purpose':args['purpose'],'at':now()})
    state['actions']=state['actions'][-40:];save(store,state)
    if name=='finish_case':
        job=read(store,'summary_job:'+job['id']);job['usage']=state['total_usage']
        with store.db:write(store,'summary_job:'+job['id'],job)
        result['usage']=state['total_usage']
        from bridge import atomic
        atomic(store.root/'reports'/job['run']/'agent-investigation.json',canonical(state)+b'\n')
    with store.db:write(store,receipt_key,{'digest':digest,'result':result})
    return result


def dispatch(store,client,payload):
    try:return _dispatch(store,client,payload)
    except (ValueError,KeyError,TypeError) as exc:
        job=read(store,'summary_job:'+str(payload.get('id','')))
        if not job or job.get('token')!=payload.get('token') or payload.get('operation')!='action':raise
        request_id=payload.get('request_id','');key='agent_receipt:'+job['id']+':'+request_id
        if not re.fullmatch('step_[0-9]{4}',request_id) or read(store,key):raise
        state=state_for(store,job);call=payload.get('call',{})
        message=str(exc) if isinstance(exc,ValueError) and re.fullmatch('[A-Za-z0-9 _-]{1,100}',str(exc)) else 'invalid tool arguments'
        result={'tool_error':message};state['step']+=1
        for name in state['total_usage']:state['total_usage'][name]+=max(0,int(payload.get('usage',{}).get(name,0) or 0))
        state['actions'].append({'step':state['step'],'tool':call.get('name','unknown'),'purpose':'工具请求未执行完成：'+message,'at':now()});save(store,state)
        with store.db:write(store,key,{'digest':hashlib.sha256(canonical(call)).hexdigest(),'result':result})
        return result
