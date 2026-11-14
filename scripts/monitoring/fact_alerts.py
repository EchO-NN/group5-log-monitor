"""Deterministic Wazuh -> IRIS facts. No stages, inferred behavior or verdicts."""
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import urllib.parse

POLICY=json.loads(Path(__file__).with_name('alert_policy.json').read_text())


def enabled(store):return getattr(store,'presentation_mode','')=='post_finish'


def safe(value,limit=1000):
    from core import redact
    text=redact(str(value))
    text=re.sub(r'\bsk-[A-Za-z0-9_-]{12,}\b','[REDACTED]',text)
    text=re.sub(r'(?i)(?:https?://)[^\s<>]+',lambda m:clean_url(m[0]),text)
    return text[:limit]


def clean_url(value):
    try:
        p=urllib.parse.urlsplit(value)
        return urllib.parse.urlunsplit((p.scheme,p.hostname or '',p.path,'',''))
    except ValueError:return '[invalid URL]'


def selected(event):
    rule=event.get('rule') or {}
    if not re.fullmatch(r'\d{1,10}',str(rule.get('id',''))):return False
    try:level=int(rule.get('level',-1))
    except (ValueError,TypeError):return False
    if not 0<=level<=16:return False
    if level>=POLICY['min_level']:return True
    rid=str(rule['id']);data=event.get('data') or {};accounts=set(POLICY['critical_accounts'])
    if rid in POLICY['authentication_rules']:return data.get('dstuser',data.get('user')) in accounts
    if rid in POLICY['sudo_rules']:return data.get('srcuser',data.get('user')) in accounts
    if rid in POLICY['file_rules']:
        path=str((event.get('syscheck') or {}).get('path',''))
        return any(path==prefix.rstrip('/') or path.startswith(prefix) for prefix in POLICY['file_prefixes'])
    if rid in POLICY['execution_rules']:
        auid=str((data.get('audit') or {}).get('auid',''))
        return auid not in ('','0','1000','4294967295','unset','-1')
    return False


def fields(event):
    data=event.get('data') or {};result={}
    for key in ('srcip','dstip','srcport','dstport','srcuser','dstuser','user','protocol','action','status'):
        if key in data:result[key]=safe(data[key],200)
    audit=data.get('audit') or {}
    for key in ('exe','comm','syscall','auid','uid','euid','success','key'):
        if key in audit:result['audit.'+key]=safe(audit[key],300)
    check=event.get('syscheck') or {}
    for key in ('path','event','sha256_before','sha256_after','size_before','size_after','uname_after'):
        if key in check:result['file.'+key]=safe(check[key],500)
    # Executable is useful evidence; command arguments may contain recovered passwords.
    command=str(data.get('command','')).strip()
    if command:result['command.executable']=safe(command.split()[0],300)
    return result


def record(event,event_id,at):
    rule=event['rule'];agent=event.get('agent') or {};detail=fields(event)
    # Retain general syslog text, but exclude audit arguments, SQL values and arbitrary JSON bodies.
    raw=str(event.get('full_log',''))
    if any(x in raw.lower() for x in ('execve','proctitle','type=syscall','type=path','command=','query\t',' query ','password=','token=')) or 'command' in (event.get('data') or {}):
        raw='[原始命令参数/查询值留存在本地证据；此处仅展示解码字段]'
    if raw.lstrip().startswith(('{','[')):raw='[结构化原始日志留存在本地证据]'
    return dict(event_id=event_id,timestamp=at,host=safe(agent.get('name','unknown'),120),host_ip=safe(agent.get('ip',''),80),
                rule_id=str(rule['id']),level=int(rule['level']),rule_description=safe(rule.get('description',''),500),
                source=safe(event.get('location',''),300),fields=detail,message=safe(raw,1200))


def key(row):
    event=json.loads(row['payload'])['event'];f=fields(event)
    window=int(dt.datetime.fromisoformat(row['event_time']).timestamp())//POLICY['group_window_seconds']
    parts=[row['run'],event.get('agent'),event.get('rule',{}).get('id'),f,window,bool(row['selftest'])]
    return hashlib.sha256(json.dumps(parts,sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def content(rows,reference):
    records=[record(json.loads(r['payload'])['event'],r['id'],r['event_time']) for r in rows]
    records.sort(key=lambda r:(r['timestamp'],r['event_id']))
    return {'schema':'wazuh-facts-v1','reference':reference,'count':len(records),'first_seen':records[0]['timestamp'],
            'last_seen':records[-1]['timestamp'],'records':records,'selftest':bool(rows[0]['selftest'])}


def text(facts):
    first=facts['records'][0];field=first['fields']
    title=('TEST | ' if facts['selftest'] else '')+'Wazuh L'+str(first['level'])+' / '+first['rule_id']+' | '+first['host']+' | '+first['rule_description']
    lines=['首次时间（UTC）：'+facts['first_seen'],'末次时间（UTC）：'+facts['last_seen'],
        '主机：'+first['host'],'Wazuh 规则：'+first['rule_id'],'Wazuh 原始等级：'+str(first['level']),
        '规则描述：'+first['rule_description'],'日志来源：'+first['source'],'合并记录数：'+str(facts['count'])]
    lines+=['字段 '+k+'：'+v for k,v in field.items()]
    lines+=['日志摘录：'+first['message']]
    return title[:240],'\n'.join(lines)


def indicators(facts):
    values=set()
    for record in facts['records']:
        for value in [record['host_ip'],record['fields'].get('srcip',''),record['fields'].get('dstip','')]:
            try:values.add(('ip',str(ipaddress.ip_address(value))))
            except ValueError:pass
        for key in ('file.sha256_before','file.sha256_after'):
            value=record['fields'].get(key,'')
            if re.fullmatch('[a-fA-F0-9]{64}',value):values.add(('sha256',value.lower()))
    return [dict(type=k,value=v) for k,v in sorted(values)]
