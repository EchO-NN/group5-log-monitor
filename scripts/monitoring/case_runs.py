"""Persist run-to-case ownership; recover ambiguous case creation by SOC reference."""
import datetime as dt
import json
import uuid
from iris import Iris

INITIAL_BLOCK='<!-- G5AI_BEGIN -->\n### AI 案件摘要（待生成）\n等待本轮证据。\n<!-- G5AI_END -->'


def case_id(store,run):
    row=store.db.execute('SELECT value FROM metadata WHERE key=?',('case:'+run,)).fetchone()
    return int(row['value']) if row else getattr(store,'default_case_id',None)


def for_run(store,client,run):
    cid=case_id(store,run)
    if cid is None or cid==client.cid:return client
    return Iris(dict(client.config,case_id=cid))


def begin(store,client,label,request_id=None):
    request_id=request_id or uuid.uuid4().hex
    if len(request_id)!=32 or any(c not in '0123456789abcdef' for c in request_id):raise ValueError('invalid begin request')
    existing=store.db.execute('SELECT value FROM metadata WHERE key=?',('begin_request:'+request_id,)).fetchone()
    if existing:
        result=json.loads(existing['value'])
        result['case_url']=client.config.get('iris_url','https://iris.example.invalid').rstrip('/')+'/case?cid='+str(result['case_id'])
        return result
    pending=store.db.execute('SELECT value FROM metadata WHERE key="begin_pending"').fetchone()
    if pending:
        intent=json.loads(pending['value'])
        if intent['label']!=label[:120]:raise ValueError('retry unresolved begin with original label')
        request_id=intent['request_id']
    else:
        intent={'request_id':request_id,'label':label[:120],'soc_id':'G5RUN-'+request_id}
        with store.db:store.db.execute('INSERT INTO metadata VALUES(?,?)',('begin_pending',json.dumps(intent)))
    matches=[c for c in client.request('manage/cases/list') if c.get('case_soc_id')==intent['soc_id']]
    if len(matches)>1:raise ValueError('ambiguous case reference')
    if matches:cid=int(matches[0]['case_id'])
    else:
        stamp=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime('%m-%d %H:%M:%S')
        fields=dict(case_name=intent['label']+' · '+stamp,
            case_customer=client.customer,case_soc_id=intent['soc_id'],
            case_description='本案件对应独立的一轮演练。课堂阶段为预设证据映射，不代表攻击成功。\n\n'+INITIAL_BLOCK+'\n\n### 人工分析\n',custom_attributes={})
        if getattr(store,'presentation_mode','')=='post_finish':
            fields['case_description']='本轮 Wazuh 告警案件。finish 后根据本轮告警生成 AI 研判。\n\n'+INITIAL_BLOCK+'\n\n### 人工分析\n'
        reuse=store.db.execute('SELECT value FROM metadata WHERE key="reuse_primary_once"').fetchone()
        if reuse:
            from primary_case import snapshot
            reserved=json.loads(reuse['value'])
            if not store.waiting_for_begin() or reserved['run']!=store.current()['id'] or snapshot()!=reserved['fingerprint']:
                raise ValueError('reserved empty primary case changed; no data overwritten')
            client.request('manage/cases/update/1',dict(fields,case_tags=''))
            cid=1
        else:
            created=client.request('manage/cases/add',fields)
            cid=int(created['case_id'])
    previous=store.current()
    rid=store.begin(intent['label'],case_id=cid,request_id=request_id)
    if previous and previous['state']!='prepared':
        with store.db:store.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('report_dirty:'+previous['id'],'1'))
    return dict(run=rid,case_id=cid,case_url=client.config.get('iris_url','https://iris.example.invalid').rstrip('/')+'/case?cid='+str(cid))
