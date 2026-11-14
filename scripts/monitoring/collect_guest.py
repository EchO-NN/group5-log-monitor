"""Read-only management telemetry. REQUEST and ROLE are supplied by pinned host SSH."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import time
import urllib.parse
import urllib.request

ROLE=globals().get('ROLE',7)
REQUEST=globals().get('REQUEST',{})
UTC=dt.timezone.utc
events=[];cursor=dict(REQUEST);capabilities={}
host=socket.gethostname()


def journal_message(value):
    """Keep non-string journal values intact while providing searchable text."""
    if isinstance(value,str):return value,{}
    data={'journal_message_raw':value}
    if isinstance(value,list) and all(type(v) is int and 0<=v<=255 for v in value):
        return bytes(value).decode('utf-8',errors='replace'),data
    if isinstance(value,list) and all(isinstance(v,str) for v in value):
        return '\n'.join(value),data
    return json.dumps(value,ensure_ascii=False,sort_keys=True),data


def emit(identifier,at,text,location,data=None):
    data=data or {}
    if 'audit' in text.lower():
        fields=dict(re.findall(r'(?:^|\s)(auid|uid|euid|pid|ppid)=([^\s]+)',text))
        correlation=re.search(r'audit\(([^)]+)\)',text)
        if correlation:fields['correlation_id']=correlation[1]
        if fields:data['audit']=fields
    events.append(dict(id='management:'+host+':'+identifier,timestamp=at,
        manager={'name':'pinned-management-relay'},agent={'id':'management-vm'+str(ROLE),'name':'group5-vm'+str(ROLE)},
        full_log=text,location=location,data=data,provenance={'channel':'management_ssh','hostname':host,'role':ROLE}))


def parsed_time(line):
    audit=re.search(r'audit\((\d+(?:\.\d+)?):',line)
    if audit:return dt.datetime.fromtimestamp(float(audit[1]),UTC).isoformat()
    web=re.search(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]',line)
    if web:
        try:return dt.datetime.strptime(web[1],'%d/%b/%Y:%H:%M:%S %z').astimezone(UTC).isoformat()
        except ValueError:return None
    match=re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?',line)
    if match:
        try:
            value=dt.datetime.fromisoformat(match[0].replace(',','.').replace('Z','+00:00'))
            return (value if value.tzinfo else value.replace(tzinfo=dt.datetime.now().astimezone().tzinfo)).astimezone(UTC).isoformat()
        except ValueError:pass
    return None


since=REQUEST.get('since') or (dt.datetime.now(UTC)-dt.timedelta(minutes=3)).isoformat()
command=['journalctl','--no-pager','-o','json']
command+=['--after-cursor',REQUEST['journal']] if REQUEST.get('journal') else ['--since',since]
process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
try:
    for _ in range(300):
        line=process.stdout.readline()
        if not line:break
        try:
            item=json.loads(line)
            at=dt.datetime.fromtimestamp(int(item['__REALTIME_TIMESTAMP'])/1e6,UTC).isoformat()
            message,extra=journal_message(item.get('MESSAGE',''))
            emit('journal:'+item['__CURSOR'],at,message,'journald',
                 dict(extra,program=item.get('SYSLOG_IDENTIFIER',item.get('_COMM',''))))
            cursor['journal']=item['__CURSOR']
        except (ValueError,KeyError):continue
finally:
    process.terminate()
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:process.kill();process.wait()
capabilities['journald']=True
paths=['/var/log/audit/audit.log']
if ROLE==4:paths+=['/var/log/samba/group5-full-audit.log']
if ROLE==5:paths+=['/var/log/test-web/application.log','/var/log/group5-drill/TEST_application.log']
if ROLE==6:paths+=['/var/log/mysql/lab-general.log']
positions=cursor.setdefault('files',{})
for name in paths:
    path=Path(name)
    if not path.is_file():capabilities[name]='missing';continue
    info=path.stat();old=positions.get(name,{})
    offset=old.get('offset',0) if old.get('inode')==info.st_ino and old.get('offset',0)<=info.st_size else 0
    if not old:offset=max(0,info.st_size-256*1024)
    with path.open('rb') as stream:
        stream.seek(offset)
        if offset and not old:stream.readline()
        previous=old.get('time')
        for _ in range(300):
            start=stream.tell();raw=stream.readline(1024*1024)
            if not raw:break
            if not raw.endswith(b'\n'):stream.seek(start);break
            line=raw.decode('utf-8',errors='replace');at=parsed_time(line) or previous
            if at:
                data={}
                if ROLE==5 and '/group5-drill/' in name:
                    data={'group5':{'kind':'central_log_received','source_file':name}}
                emit('file:'+str(info.st_ino)+':'+str(start),at,line.rstrip('\n'),name,data)
                previous=at
        positions[name]={'inode':info.st_ino,'offset':stream.tell(),'time':previous}
    capabilities[name]='readable'
if ROLE==3:
    visits=cursor.get('browser_visit',0)
    for pattern in ['/home/*/.mozilla/firefox/*/places.sqlite','/home/*/snap/firefox/common/.mozilla/firefox/*/places.sqlite']:
        import glob
        for filename in glob.glob(pattern):
            try:
                db=sqlite3.connect('file:'+urllib.parse.quote(filename)+'?mode=ro',uri=True,timeout=2)
                rows=db.execute('SELECT p.url,h.visit_date FROM moz_historyvisits h JOIN moz_places p ON p.id=h.place_id WHERE h.visit_date>? AND p.url LIKE ? ORDER BY h.visit_date LIMIT 100',(visits,'http://192.168.34.5/%')).fetchall();db.close()
                for url,when in rows:
                    emit('browser:'+str(when),dt.datetime.fromtimestamp(when/1e6,UTC).isoformat(),'演练站点浏览器访问','firefox_history',{'group5':{'kind':'browser_record'},'url':url})
                    visits=max(visits,when)
                capabilities['browser_history']='readable_lab_urls_only'
            except sqlite3.Error:capabilities['browser_history']='unavailable_or_locked'
    cursor['browser_visit']=visits
if ROLE==5:
    path=Path('/var/log/group5-drill/TEST_application.log')
    if path.is_file():
        digest=hashlib.sha256(path.read_bytes()).hexdigest();previous=cursor.get('test_log_hash')
        if previous and previous!=digest:
            emit('loghash:'+digest,dt.datetime.fromtimestamp(path.stat().st_mtime,UTC).isoformat(),'专用日志哈希发生变化；原因待确认','TEST_log_hash',
                {'group5':{'kind':'log_hash_comparison'},'before_sha256':previous,'after_sha256':digest})
        if previous!=digest and path.stat().st_size<=1024*1024:
            emit('logsnapshot:'+digest,dt.datetime.now(UTC).isoformat(),'专用日志只读快照','TEST_log_snapshot',
                 {'group5':{'kind':'application_log_snapshot'},'snapshot_sha256':digest,'snapshot_text':path.read_text(errors='replace')})
        cursor['test_log_hash']=digest
if ROLE==7:
    baseline=Path('/var/lib/group5-backup-integrity/sha256.list')
    if baseline.is_file():
        inventory=[]
        for row in baseline.read_text().splitlines():
            expected,name=row.split('  ',1);p=Path(name)
            inventory.append({'name':p.name,'present':p.is_file(),'expected_sha256':expected,
                'current_sha256':hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not p.is_symlink() else None})
        digest=hashlib.sha256(json.dumps(inventory,sort_keys=True).encode()).hexdigest()
        if cursor.get('backup_inventory')!=digest or time.time()-cursor.get('inventory_at',0)>3600:
            emit('inventory:'+str(int(time.time())),dt.datetime.now(UTC).isoformat(),'备份清单只读采集','backup_inventory',{'group5':{'kind':'backup_inventory'},'files':inventory})
        cursor.update(backup_inventory=digest,inventory_at=time.time())
if ROLE==9:
    from performance import collect as collect_performance, event as performance_event
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    performance_end=int(time.time()//30)*30
    performance_start=max(performance_end-7200,int(cursor.get('performance_end',performance_end-150))+30)
    if performance_start<=performance_end:
        performance=collect_performance(performance_start,performance_end,opener=opener)
        events.extend(performance_event(point) for point in performance['points'])
        capabilities['performance']=dict(metrics=performance['metrics'],samples=len(performance['points']),
            complete=performance['complete'],start=performance['start'],end=performance['end'])
        if performance['complete']:cursor['performance_end']=performance_end
        capabilities['vm3_cpu']='available' if any(p['target_host']=='VM3' and p['metric']=='cpu_percent' for p in performance['points']) else 'no_samples'
    for endpoint in ['orders','tickets']:
        healthy=False;code=None;probe_started=time.monotonic()
        try:
            with opener.open('http://192.168.31.30/api/'+endpoint,timeout=12) as response:
                code=response.status;body=json.load(response)
                healthy=code==200 and isinstance(body,(dict,list)) and not (isinstance(body,dict) and (body.get('success') is False or body.get('status')=='error' or body.get('error')))
        except urllib.error.HTTPError as exc:code=exc.code
        except Exception:pass
        emit('probe:'+endpoint+':'+str(int(time.time()//60)),dt.datetime.now(UTC).isoformat(),
             '业务接口探测成功' if healthy else '业务接口探测失败','business_probe',
             {'group5':{'kind':'business_probe_success' if healthy else 'business_probe_failure'},
              'endpoint':endpoint,'http_status':code,'latency_ms':round((time.monotonic()-probe_started)*1000,3)})
        capabilities['api_'+endpoint]='healthy' if healthy else 'failed'
print(json.dumps(dict(kind='g5_collection_result',role=ROLE,hostname=host,events=events,cursor=cursor,capabilities=capabilities),ensure_ascii=False))
