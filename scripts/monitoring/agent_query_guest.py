"""Fixed read-only guest queries. No model supplied shell, paths, URLs or SQL."""
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess

AUDIT_ROOT=Path('/var/log/audit')
AUDIT_PAGE_SIZE=80
AUDIT_SCAN_BYTES=8*1024*1024
AUDIT_NAME=re.compile(r'audit\.log(?:\.[1-9][0-9]*(?:\.gz)?)?')


def audit_files():
    files=[]
    for path in AUDIT_ROOT.iterdir():
        if not AUDIT_NAME.fullmatch(path.name):continue
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode):raise OSError('audit file is not regular')
        files.append(dict(name=path.name,dev=info.st_dev,ino=info.st_ino,size=info.st_size,mtime=info.st_mtime_ns))
    return sorted(files,key=lambda f:int(f['name'].split('.')[2]) if f['name']!='audit.log' else 0,reverse=True)


def audit_page(request,result,start,end,match):
    """Snapshot retained logs; bounded pages have no total record/tail limit."""
    binding=hashlib.sha256(json.dumps({k:request[k] for k in ('role','query','start','end','match')},sort_keys=True).encode()).hexdigest()
    cursor=request.get('cursor')
    try:
        available=audit_files()
        if cursor is None:
            if not available:raise OSError('no audit logs')
            cursor=dict(version=1,binding=binding,files=available,index=0,offset=0,page=1,skip_line=False,skipped_long_lines=0,records_seen=0)
        else:
            cursor=json.loads(json.dumps(cursor))
            if not isinstance(cursor,dict) or set(cursor)!={'version','binding','files','index','offset','page','skip_line','skipped_long_lines','records_seen'}:raise ValueError('audit cursor shape')
            if cursor['version']!=1 or cursor['binding']!=binding:raise ValueError('audit cursor scope')
            if not isinstance(cursor['files'],list) or not cursor['files']:raise ValueError('audit cursor files')
            for f in cursor['files']:
                if not isinstance(f,dict) or set(f)!={'name','dev','ino','size','mtime'} or not AUDIT_NAME.fullmatch(f.get('name','')):raise ValueError('audit cursor file')
                if any(type(f[k]) is not int or f[k]<0 for k in ('dev','ino','size','mtime')):raise ValueError('audit cursor identity')
            if any(type(cursor[k]) is not int or cursor[k]<0 for k in ('index','offset','page','skipped_long_lines','records_seen')) or type(cursor['skip_line']) is not bool:raise ValueError('audit cursor position')
            if cursor['index']>=len(cursor['files']) or cursor['page']<2:raise ValueError('audit cursor end')
        result.update(scope='retained_audit_snapshot',page=cursor['page'],page_size=AUDIT_PAGE_SIZE,snapshot_files=len(cursor['files']))
        scanned=0
        while cursor['index']<len(cursor['files']) and len(result['records'])<AUDIT_PAGE_SIZE and scanned<AUDIT_SCAN_BYTES:
            saved=cursor['files'][cursor['index']]
            current=next((f for f in available if (f['dev'],f['ino'])==(saved['dev'],saved['ino'])),None)
            if current is None:raise OSError('snapshot log rotated away')
            compressed=saved['name'].endswith('.gz')
            fd=os.open(AUDIT_ROOT/current['name'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as raw_stream:
                info=os.fstat(raw_stream.fileno())
                if not stat.S_ISREG(info.st_mode) or (info.st_dev,info.st_ino)!=(saved['dev'],saved['ino']) or info.st_size<saved['size']:raise OSError('snapshot log changed')
                if info.st_size==saved['size'] and info.st_mtime_ns!=saved['mtime']:raise OSError('snapshot rewritten')
                if compressed and (info.st_size!=saved['size'] or info.st_mtime_ns!=saved['mtime']):raise OSError('compressed snapshot changed')
                # Appends beyond the captured size belong to a later query, not this snapshot.
                if not compressed and cursor['offset']>saved['size']:raise ValueError('audit cursor offset')
                stream=gzip.GzipFile(fileobj=raw_stream) if compressed else raw_stream
                try:
                    stream.seek(cursor['offset'])
                    while len(result['records'])<AUDIT_PAGE_SIZE and scanned<AUDIT_SCAN_BYTES:
                        remaining=65536 if compressed else min(65536,saved['size']-stream.tell())
                        raw=stream.readline(remaining) if remaining else b''
                        if not raw:
                            cursor.update(index=cursor['index']+1,offset=0,skip_line=False);break
                        scanned+=len(raw);cursor['offset']=stream.tell()
                        if cursor['skip_line']:
                            cursor['skip_line']=not raw.endswith(b'\n');continue
                        if len(raw)>=65536 and not raw.endswith(b'\n'):
                            cursor['skipped_long_lines']+=1;cursor['skip_line']=True;continue
                        line=raw.decode(errors='replace');m=re.search(r'audit\((\d+(?:\.\d+)?):(\d+)\)',line)
                        if not m:continue
                        at=dt.datetime.fromtimestamp(float(m[1]),dt.timezone.utc)
                        if not start<=at<=end or (match and match not in line):continue
                        fields=dict(re.findall(r'\b(type|auid|uid|euid|pid|ppid|syscall|success|exe|comm|name)=("[^"]*"|\S+)',line))
                        if fields.get('type') in ('EXECVE','PROCTITLE'):continue
                        result['records'].append({'at':at.isoformat(),'audit_id':m[2],'fields':{k:clean(v) for k,v in fields.items()}})
                finally:
                    if compressed:stream.close()
        more=cursor['index']<len(cursor['files']);cursor['records_seen']+=len(result['records'])
        result.update(has_more=more,coverage_complete=not more and cursor['skipped_long_lines']==0,truncated=more or cursor['skipped_long_lines']>0,
                      scanned_bytes=scanned,records_seen=cursor['records_seen'],skipped_long_lines=cursor['skipped_long_lines'],
                      coverage_note='仅覆盖首次查询时仍留存的日志快照及允许返回的字段；不证明已轮转删除的历史日志完整。')
        if more:cursor['page']+=1;result['continuation']=cursor
    except (OSError,EOFError):
        result.update(ok=False,error='audit_snapshot_unavailable_restart_query',has_more=False,coverage_complete=False,truncated=True)
    return result


def when(value):
    at=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if at.tzinfo is None:raise ValueError('timezone required')
    return at.astimezone(dt.timezone.utc)


def clean(text):
    text=re.sub(r'(?i)((?:password|passwd|token|api[_-]?key|authorization|secret)\s*[=:]\s*)("[^"]*"|\S+)',r'\1[REDACTED]',str(text))
    text=re.sub(r'\bsk-[A-Za-z0-9_-]{12,}\b','[REDACTED]',text)
    text=re.sub(r'(?i)(Bearer\s+)\S+',r'\1[REDACTED]',text)
    text=re.sub(r'(://[^\s/:@]+:)[^\s/@]+@',r'\1[REDACTED]@',text)
    text=re.sub(r'(?i)\b(select|insert\s+into|update\s+\S+\s+set|delete\s+from|grant)\s+.*',r'\1 [SQL values withheld]',text)
    text=re.sub(r'(COMMAND=)(\S+).*',r'\1\2 [arguments withheld]',text)
    return text[:700]


def run(request):
    if set(request)-{'cursor'}!={'role','query','start','end','match'}:raise ValueError('query shape')
    role=request['role'];kind=request['query'];start=when(request['start']);end=when(request['end']);match=request['match']
    if type(role) is not int or role not in range(2,10):raise ValueError('host denied')
    if kind not in ('authentication','audit','services','backup_inventory'):raise ValueError('query denied')
    if 'cursor' in request and kind!='audit':raise ValueError('cursor only for audit')
    if not 0<(end-start).total_seconds()<=7440 or not isinstance(match,str) or len(match)>80:raise ValueError('window or match denied')
    result=dict(ok=True,host='VM'+str(role),hostname=socket.gethostname(),query=kind,requested_start=start.isoformat(),requested_end=end.isoformat(),collected_at=dt.datetime.now(dt.timezone.utc).isoformat(),records=[],truncated=False)
    if kind=='backup_inventory':
        if role!=7:raise ValueError('backup query host denied')
        result['scope']='current_snapshot_not_historical';root=Path('/lab_backup');baseline=Path('/var/lib/group5-backup-integrity/sha256.list');expected={}
        if baseline.is_file() and not baseline.is_symlink() and baseline.stat().st_size<65536:
            for line in baseline.read_text().splitlines():
                pair=line.split('  ',1)
                if len(pair)==2 and re.fullmatch('[a-fA-F0-9]{64}',pair[0]) and Path(pair[1]).parent==root:expected[pair[1]]=pair[0].lower()
        files=set(expected)
        if root.is_dir() and not root.is_symlink():files.update(str(p) for p in list(root.iterdir())[:100] if p.name.endswith(('.tar.gz','.sha256','.sql.gz')))
        remaining=64*1024*1024
        for name in sorted(files)[:100]:
            p=Path(name);item={'path':name,'expected_sha256':expected.get(name)}
            try:
                fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as stream:
                    info=os.fstat(stream.fileno());item.update(present=True,size=info.st_size,mtime=dt.datetime.fromtimestamp(info.st_mtime,dt.timezone.utc).isoformat())
                    if stat.S_ISREG(info.st_mode) and info.st_size<=min(32*1024*1024,remaining):
                        h=hashlib.sha256();count=0
                        while count<=info.st_size:
                            blob=stream.read(min(65536,info.st_size+1-count))
                            if not blob:break
                            h.update(blob);count+=len(blob)
                        remaining-=count
                        stable=os.fstat(stream.fileno()).st_mtime_ns==info.st_mtime_ns and count==info.st_size
                        item['sha256']=h.hexdigest() if stable else None;item['stable_during_read']=stable
                    else:item['hash_status']='not_hashed_size_or_type_limit'
            except FileNotFoundError:item['present']=False
            except OSError:item['read_status']='unavailable_or_symlink'
            result['records'].append(item)
        result['truncated']=len(files)>100
        return result
    if kind=='audit':
        return audit_page(request,result,start,end,match)
    # Older systemd on C guests cannot parse ISO timestamps with fractional seconds.
    # Read a slightly wider whole-second window, then apply exact timestamps below.
    floor=start.replace(microsecond=0);ceil=end.replace(microsecond=0)+dt.timedelta(seconds=1)
    command=['journalctl','--no-pager','-o','json','--since',floor.strftime('%Y-%m-%d %H:%M:%S UTC'),'--until',ceil.strftime('%Y-%m-%d %H:%M:%S UTC'),'-n','1500']
    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    try:
        scanned=0
        while True:
            raw=process.stdout.readline(65537)
            if not raw:break
            if len(raw)>65536:result['truncated']=True;break
            scanned+=1
            try:
                row=json.loads(raw);message=row.get('MESSAGE','');message=message if isinstance(message,str) else '[non-text journal message]'
                program=str(row.get('SYSLOG_IDENTIFIER',row.get('_COMM','')));unit=str(row.get('_SYSTEMD_UNIT',''))
                allowed=any(x in (program+' '+unit).lower() for x in (('sshd','ssh.service','sudo') if kind=='authentication' else ('nginx','apache','mysql','mariadb','wazuh','group5','backup')))
                if not allowed or (match and match not in message):continue
                at=dt.datetime.fromtimestamp(int(row['__REALTIME_TIMESTAMP'])/1e6,dt.timezone.utc)
                if not start<=at<=end:continue
                if 'PRIVATE KEY' in message:message='[private-key material withheld]'
                result['records'].append({'at':at.isoformat(),'program':clean(program),'unit':clean(unit),'message':clean(message)})
                if len(result['records'])>=60:result['truncated']=True;break
            except (ValueError,KeyError,TypeError):continue
        if scanned>=1500:result['truncated']=True
    finally:
        process.terminate()
        try:process.wait(timeout=3)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        process.stdout.close()
    if process.returncode not in (0,-15):result.update(ok=False,error='journal_unavailable')
    return result


if __name__=='__main__':print(json.dumps(run(REQUEST),ensure_ascii=False))
