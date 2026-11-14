"""Apply validated model annotations to one bound Case, preserving analyst edits."""
import datetime as dt
import hashlib
import html
import json
import urllib.parse
from core import canonical,now
from summary_jobs import read,write

FIELDS={'timeline':('event_title','event_content','event_raw','event_date'),
        'tasks':('task_title','task_description'),'assets':('asset_name','asset_description','asset_ip'),
        'notes':('note_title','note_content')}
IDS={'timeline':'event_id','tasks':'task_id','assets':'asset_id','notes':'note_id'}
PATHS={'timeline':'case/timeline/events/','tasks':'case/tasks/','assets':'case/assets/','notes':'case/notes/'}


def safe(value):return html.escape(value,quote=False)


def listing(client,section):
    suffix='?cid='+str(client.cid)
    if section=='timeline':
        rows=client.request('case/timeline/events/list'+suffix)['timeline']
        # The list endpoint omits event_raw; fetch our events before edit comparison.
        return [client.request('case/timeline/events/'+str(r['event_id'])+suffix) if str(r.get('event_title','')).startswith('[G5AI:') else r for r in rows]
    if section=='tasks':return client.request('case/tasks/list'+suffix)['tasks']
    if section=='assets':return client.request('case/assets/filter'+suffix)['assets']
    return client.request('case/notes/search'+suffix+'&search_input=G5AI')


def signature(section,item):
    values={k:item.get(k) or '' for k in FIELDS[section]}
    if section=='timeline':
        at=dt.datetime.fromisoformat(values['event_date'].replace('Z','+00:00'))
        if at.tzinfo is None:at=at.replace(tzinfo=dt.timezone.utc)
        values['event_date']=at.astimezone(dt.timezone.utc).isoformat()
    return hashlib.sha256(canonical(values)).hexdigest()


def marker(rid,section,key):return '[G5AI:'+rid+':'+section+':'+key+']'


def desired(job,result):
    rid=job['run'];by_ref={o['reference']:o for o in job['payload']['observations']};objects=[]
    for section in ('timeline','tasks','assets','notes'):
        for index,item in enumerate(result[section]):
            key=(hashlib.sha256(item['host'].encode()).hexdigest()[:12] if section=='assets' else str(index+1).zfill(3))
            mark=marker(rid,section,key)
            is_agent=job['payload'].get('analysis_engine')=='agent-v1'
            references=('\n\n证据引用：' if is_agent else '\n\n告警引用：')+', '.join(item['references'])
            if section=='timeline':
                at=dt.datetime.fromisoformat(item['at'].replace('Z','+00:00')).astimezone(dt.timezone.utc)
                chain='';raw={'references':item['references'],'model':'gpt-6.1-sol','effort':'xhigh'}
                if 'chain_key' in item:
                    raw.update(chain_key=item['chain_key'],chain_note=item['chain_note'],links=item['links'])
                    labels={'causal':'因果关联','enables':'提供后续条件','continuation':'活动延续','temporal':'时间相邻'}
                    chain='\n\n链节点 '+safe(item['chain_key'])+'：'+safe(item['chain_note'])
                    for link in item['links']:
                        source=next((e for e in result['timeline'] if e.get('chain_key')==link['from']),{})
                        chain+='\n前置 '+safe(link['from'])+' '+safe(source.get('title',''))+' → '+labels[link['relation']]+'（'+('已证实' if link['confidence']=='confirmed' else '推断')+'）：'+safe(link['basis'])+'；证据 '+', '.join(link['references'])
                    if not item['links']:chain+='\n上游关联：起点或尚无可支持的前置证据。'
                body=dict(event_title=mark+' '+safe(item['title']),event_content='AI 研判：'+safe(item['content'])+chain+references,
                    event_raw=canonical(raw).decode(),
                    event_source='AI case investigation',event_assets=[],event_iocs=[],event_category_id=1,event_color='#3498db',
                    event_date=at.strftime('%Y-%m-%dT%H:%M:%S.%f'),event_tz='+00:00',event_tags='G5AI',event_in_graph=True,event_in_summary=True,custom_attributes={})
            elif section=='tasks':
                body=dict(task_title=mark+' '+safe(item['title']),task_description=('Agent 只读调查任务：' if is_agent else 'AI 建议，尚未执行：')+safe(item['description'])+references,
                    task_status_id=1,task_assignees_id=[],task_tags='G5AI',custom_attributes={})
            elif section=='assets':
                evidence=next(by_ref[r] for r in item['references'] if by_ref[r]['host']==item['host'])
                body=dict(asset_name=item['host'],asset_type_id=3,analysis_status_id=2,asset_ip=evidence['host_ip'],
                    asset_description=mark+'\nAI 资产研判：'+safe(item['description'])+references,asset_tags='G5AI',custom_attributes={})
            else:
                body=dict(note_title=mark+' '+safe(item['title']),note_content='AI 研判记录\n\n'+safe(item['content'])+references,custom_attributes={})
            objects.append(dict(section=section,key=key,marker=mark,body=body))
    return objects


def plan(store,client,job,result,sections=None,prune=True):
    """Read and check the entire annotation plan before applying any mutation."""
    sections=set(FIELDS if sections is None else sections)
    lists={section:listing(client,section) for section in sections}
    operations=[];conflicts=[];wanted=set()
    for obj in desired(job,result):
        if obj['section'] not in sections:continue
        section=obj['section'];key='case_object:'+job['run']+':'+section+':'+obj['key'];wanted.add(key)
        saved=read(store,key)
        matches=[r for r in lists[section] if obj['marker'] in str(r.get(FIELDS[section][0],'')) or (section=='assets' and r.get('asset_name')==obj['body']['asset_name'])]
        if saved:
            existing=next((r for r in lists[section] if r.get(IDS[section])==saved['id']),None)
            if existing is None:conflicts.append(section+':analyst_deleted');continue
        else:existing=matches[0] if len(matches)==1 else None
        if len(matches)>1:conflicts.append(section+':ambiguous');continue
        if existing:
            actual=signature(section,existing);expected=signature(section,obj['body'])
            if actual!=expected and (not saved or actual!=saved['hash']):conflicts.append(section+':analyst_edited');continue
            obj.update(existing=existing,previous_hash=actual,unchanged=actual==expected)
        else:obj.update(existing=None,unchanged=False)
        obj['metadata_key']=key;operations.append(obj)
    # Remove only our obsolete, unchanged annotations. Human-owned records are untouched.
    rows=store.db.execute("SELECT key,value FROM metadata WHERE key LIKE ?",('case_object:'+job['run']+':%',)).fetchall()
    for row in rows:
        if not prune:break
        if row['key'] in wanted:continue
        saved=json.loads(row['value']);section=saved['section']
        if section not in sections:continue
        old=next((r for r in lists[section] if r.get(IDS[section])==saved['id']),None)
        if not old:continue
        agent_status=read(store,'agent_task_status:'+job['run']+':'+row['key'].rsplit(':',1)[1]) if section=='tasks' else None
        own_status=agent_status and old.get('task_status_id')==agent_status.get('status')
        human_state=section=='tasks' and ((old.get('task_status_id')!=1 and not own_status) or old.get('task_assignees'))
        human_state=human_state or (section=='assets' and old.get('analysis_status_id')!=2)
        if signature(section,old)!=saved['hash'] or human_state:conflicts.append(section+':obsolete_with_human_work');continue
        operations.append(dict(section=section,delete=True,existing=old,previous_hash=saved['hash'],metadata_key=row['key']))
    return operations,conflicts


def note_directory(client,run):
    name='AI 研判 '+run
    folders=client.request('case/notes/directories/filter?cid='+str(client.cid))
    from iris import walk
    existing=[f for f in walk(folders) if f.get('name')==name and 'id' in f]
    if existing:return int(existing[0]['id'])
    created=client.request('case/notes/directories/add?cid='+str(client.cid),{'name':name,'parent_id':None})
    return int(created['id'])


def apply(store,client,job,result,operations,finalize=True):
    counts={s:0 for s in FIELDS};suffix='?cid='+str(client.cid);directory=None
    for obj in operations:
        section=obj['section'];old=obj.get('existing');path=PATHS[section]
        if old:
            # Re-read immediately before mutation; the IRIS API has no atomic CAS.
            current=client.request(path+str(old['event_id'])+suffix) if section=='timeline' else next((r for r in listing(client,section) if r.get(IDS[section])==old[IDS[section]]),None)
            if current is None or signature(section,current)!=obj['previous_hash']:raise ValueError('case annotation changed concurrently')
            old=current
        if obj.get('delete'):
            client.request(path+'delete/'+str(old[IDS[section]])+suffix,{})
            with store.db:store.db.execute('DELETE FROM metadata WHERE key=?',(obj['metadata_key'],))
            continue
        body=dict(obj['body'])
        created=None
        if not obj['unchanged']:
            if old:
                body['custom_attributes']=old.get('custom_attributes') or {}
                if section=='tasks':
                    body.update(task_status_id=old['task_status_id'],task_assignees_id=[a['id'] for a in old.get('task_assignees',[])],task_tags=old.get('task_tags','G5AI'))
                if section=='assets':
                    body.update(analysis_status_id=old.get('analysis_status_id'),asset_compromise_status_id=old.get('asset_compromise_status_id'),asset_tags=old.get('asset_tags','G5AI'))
                if section=='timeline':
                    for key in ('event_category_id','event_color','event_tags','event_in_graph','event_in_summary','event_is_flagged'):
                        if key in old:body[key]=old[key]
                    for key,identifier in (('event_assets','asset_id'),('event_iocs','ioc_id')):
                        body[key]=[v if isinstance(v,int) else v[identifier] for v in old.get(key,[])]
                if section=='notes':body['directory_id']=old.get('directory_id') or (old.get('directory') or {}).get('id')
                client.request(path+'update/'+str(old[IDS[section]])+suffix,body)
            else:
                if section=='notes':
                    if directory is None:directory=note_directory(client,job['run'])
                    body['directory_id']=directory
                created=client.request(path+'add'+suffix,body)
        if section=='timeline' and (old or (created and created.get('event_id'))):
            actual=client.request(path+str(old['event_id'] if old else created['event_id'])+suffix)
        else:actual=next((r for r in listing(client,section) if obj['marker'] in str(r.get(FIELDS[section][0],'')) or (section=='assets' and r.get('asset_name')==body['asset_name'])),None)
        if actual is None or signature(section,actual)!=signature(section,body):raise ValueError('case annotation write not verified')
        with store.db:write(store,obj['metadata_key'],{'id':actual[IDS[section]],'hash':signature(section,actual),'section':section,'job':job['id']})
        counts[section]+=1
    if not finalize:return counts
    # Evidence contents are generated from stored facts, never from model-written log text.
    by_ref={o['reference']:o for o in job['payload']['observations']};evidence=[]
    for index,item in enumerate(result['evidence']):
        facts=[read(store,by_ref[ref]['evidence_key']) if by_ref[ref].get('evidence_key') else read(store,'fact_alert:'+str(by_ref[ref]['alert_ids'][0])) for ref in item['references']]
        blob=b''.join(canonical(f)+b'\n' for f in facts)
        name='G5AI-'+job['run']+'-evidence-'+hashlib.sha256(blob).hexdigest()[:16]+'.ndjson'
        description=safe(item['title'])+'\n'+safe(item['description'])+'\n告警引用：'+', '.join(item['references'])
        fid=client.evidence(name,blob,description,'G5AI,EVIDENCE',register=False)
        digest=hashlib.sha256(blob).hexdigest();mark='[G5AI_EVIDENCE:'+job['run']+':'+digest+']'
        registered=client.request('case/evidences/list'+suffix)['evidences']
        existing=next((e for e in registered if mark in (e.get('file_description') or '')),None)
        if existing is None:
            body=dict(filename=safe(item['title'])[:160]+' · '+digest[:12]+'.ndjson',file_hash=digest,file_size=len(blob),type_id=48,
                file_description=mark+'\n'+description+'\n\n[下载证据附件](https://192.168.248.2:8443/datastore/file/view/'+str(fid)+suffix+')',
                acquisition_date=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat(),custom_attributes={})
            client.request('case/evidences/add'+suffix,body)
            registered=client.request('case/evidences/list'+suffix)['evidences']
            existing=next((e for e in registered if mark in (e.get('file_description') or '')),None)
        if existing is None or existing.get('file_hash')!=digest or existing.get('file_size')!=len(blob):raise ValueError('evidence registration not verified')
        evidence.append({'file_id':fid,'evidence_id':existing['id'],'name':name,'sha256':digest,'references':item['references']})
    manifest=[dict(r) for r in store.db.execute('SELECT p.* FROM provenance p JOIN events e ON p.event=e.id WHERE e.run=?',(job['run'],))]
    artifacts={'investigation-input.json':job['payload'],'investigation-result.json':result,'evidence-manifest.json':manifest}
    response_metadata=(job.get('cached_response') or {}).get('response_metadata')
    if response_metadata:artifacts['provider-response-metadata.json']=response_metadata
    root=store.root/'reports'/job['run'];root.mkdir(parents=True,exist_ok=True,mode=0o700)
    from bridge import atomic
    for name,data in artifacts.items():
        blob=canonical(data)+b'\n';atomic(root/name,blob)
        client.evidence('G5AI-'+job['run']+'-'+hashlib.sha256(blob).hexdigest()[:12]+'-'+name,blob,
            'AI 研判输入、结果或原始证据哈希清单；由系统从本轮实际记录生成。','G5AI,EVIDENCE',register=False)
    with store.db:write(store,'case_sections:'+job['run'],{'job':job['id'],'counts':dict(counts,evidence=len(evidence)),'evidence':evidence,'at':now()})
    return dict(counts,evidence=len(evidence))
