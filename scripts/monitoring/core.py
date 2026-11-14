"""Durable defensive evidence intake. No attack execution or automatic incident verdicts."""
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid
from triage import audit_arguments,LABELS,SUPPORT

UTC = dt.timezone.utc
MAX_LINE = 8 * 1024 * 1024
KINDS = set(LABELS) | SUPPORT


def now():
    return dt.datetime.now(UTC).isoformat()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def timestamp(value):
    try:
        result = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return result.astimezone(UTC).isoformat() if result.tzinfo else None
    except (ValueError, TypeError):
        return None


def redact(value, secrets=()):
    if isinstance(value, dict):
        return {k: '[REDACTED]' if re.search(r'(?i)pass(word|phrase)?|token|secret|authorization|api.?key|private.?key', k) else redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, '[REDACTED]')
        value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', '[PRIVATE KEY REDACTED]', value, flags=re.S)
        value = re.sub(r'(?i)((?:password|passwd|token|api[_-]?key|authorization|secret)\s*[=:]\s*)("[^"]*"|\S+)', r'\1[REDACTED]', value)
        value = re.sub(r'(?i)(Bearer\s+)\S+', r'\1[REDACTED]', value)
        value = re.sub(r'(?i)(mysql[^\n]*?\s-p)\S+', r'\1[REDACTED]', value)
    return value


def role_of(event):
    name = str(event.get('agent', {}).get('name', '')).lower()
    match = re.search(r'vm([1-9])(?:\b|[-_])', name)
    if match:
        return int(match[1])
    return 2 if 'vm2-gateway' in str(event.get('full_log', '')) else None


def classify(event):
    """Rules identify candidate observations, never successful compromise."""
    text = (canonical(event).decode()+' '+audit_arguments(event)).lower()
    role = role_of(event)
    kinds = set()
    rule = str(event.get('rule', {}).get('id', ''))
    data = event.get('data', {})
    meta = data.get('group5', event.get('group5', {}))
    is_test = 'test_selftest' in text or rule == '100519' or bool(meta.get('selftest'))
    permitted={1:{'web_request'},3:{'browser_record'},5:{'log_hash_comparison','application_log_snapshot'},7:{'backup_inventory'},9:{'vm3_cpu','business_probe_failure','business_probe_success','performance_metric'}}
    if meta.get('kind') in permitted.get(role,set()):
        kinds.add(meta['kind'])
    if role == 5 and meta.get('kind') == 'log_hash_comparison':
        before,after=data.get('before_sha256'),data.get('after_sha256')
        if all(isinstance(x,str) and re.fullmatch('[0-9a-f]{64}',x) for x in (before,after)) and before!=after:
            kinds.add('application_log_change')
    audit = any(x in text for x in ('audit', 'execve', 'proctitle'))
    ad = data.get('audit', {})
    execution = 'execve' in text or str(ad.get('syscall')) in ('59', '322', 'execve', 'execveat')
    path_access = 'type=path' in text or bool(ad.get('file'))
    file_change = 'syscheck' in event or (audit and any(x in text for x in ('nametype=delete', 'nametype=create')))
    if 'vm2-acl drop' in text or rule == '100510': kinds.add('acl_drop')
    routine_allow=('src=192.168.50.11 ' in text or re.search(r'\bdpt=151[45]\b',text))
    if 'vm2-acl allow' in text and not routine_allow: kinds.add('acl_allow')
    if role == 1 and re.search(r'\bpost\s+/login\b', text): kinds.add('web_request')
    management_login=(role==3 and re.search(r'\bfor empuser\b',text)) or (role==5 and re.search(r'\bfor labadmin\b',text))
    if role in (3, 5) and not management_login and re.search(r'(accepted|partial) (publickey|password)', text):
        if role == 3: kinds.add('ssh_login')
        else:
            if 'publickey' in text: kinds.add('ssh_publickey')
            if 'password' in text: kinds.add('ssh_password')
    audit_uid=str(ad.get('auid',''))
    if not audit_uid:
        match=re.search(r'\bauid=(\S+)',str(event.get('full_log','')))
        if match:audit_uid=match[1]
    management_identity=audit_uid in ('1000','empuser','labadmin')
    if role == 3 and execution and not management_identity:
        kinds.add('command_execution')
        if re.search(r'\b(nmap|arp-scan|masscan)\b', text): kinds.add('discovery_process')
        if re.search(r'\bgit\b', text): kinds.add('git_execution')
    if role == 3 and path_access and any(x in text for x in ('course-phase04', '.bash_history', '.ssh/config', '交接归档')): kinds.add('sensitive_file_access')
    if role in (1, 3) and execution and re.search(r'\b(john|zip2john|ssh2john|hashcat)\b', text): kinds.add('credential_tool')
    if role == 4 and any(x in text for x in ('smbd_audit', 'full_audit', 'release_share|')): kinds.add('smb_access')
    if role == 5:
        if execution and ('sudoedit' in text or re.search(r'\bsudo\b.*(?:-e\b|--edit\b)',text)): kinds.add('sudoedit_activity')
        ad = data.get('audit', {})
        if audit and not management_identity and str(ad.get('euid')) == '0' and str(ad.get('auid')) not in ('0', 'None', '4294967295', 'unset', '-1'): kinds.add('privilege_identity')
        if path_access and any(x in text for x in ('application.yml', 'crypt_util.py', 'sync_backup.sh')): kinds.add('sensitive_config_access')
        if any(x in text for x in ('sql error', 'pymysql.err', 'sqlalchemy.exc', "doesn't exist", 'unknown table')): kinds.add('application_sql_error')
        if file_change and '/var/log/group5-drill/' in text: kinds.add('application_log_change')
        if 'syscheck' in event and event['syscheck'].get('sha256_before') and event['syscheck'].get('sha256_after') and '/var/log/group5-drill/' in text:kinds.add('log_hash_comparison')
        if execution and re.search(r'\bmysqldump\b', text): kinds.add('sql_export')
    if role == 6 and ('lab-general.log' in text or isinstance(data.get('mysql'), dict)):
        query = data.get('mysql', {}).get('query', '')
        if not query:
            match = re.search(r'\bQuery\s+(.+)', str(event.get('full_log', '')), re.I | re.S)
            query = match.group(1) if match else ''
        query = str(query).strip().lower()
        course_read=re.search(r'\b(?:from|join)\s+(?:`?lab_business`?\s*\.\s*)?`?(?:lab_customers|lab_orders|lab_tickets|lab_contacts|lab_release)`?(?=\s|,|;|$)',query)
        if re.match(r'select\b', query) and course_read: kinds.add('sql_read')
        if re.search(r'\binto\s+(out|dump)file\b', query): kinds.add('sql_export')
        if re.match(r'(drop|truncate|delete|alter|update|rename)\b', query): kinds.add('sql_change')
    if role == 7:
        if 'bk_operator' in text and re.search(r'accepted (publickey|password)', text): kinds.add('backup_login')
        if file_change and '/lab_backup' in text: kinds.add('backup_change')
        if rule == '100511' or ('backup-integrity-check' in text and 'status=failed' in text): kinds.add('backup_integrity_failure')
    # Wazuh detections are retained even when no course-specific behavior matches.
    try: level=int(event.get('rule',{}).get('level',0))
    except (TypeError,ValueError): level=0
    if level>=7 and not kinds:kinds.add('wazuh_detection')
    return (kinds or ({'pipeline_selftest'} if is_test else set())), is_test


class Store:
    def __init__(self, root, secrets=()):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.secrets = secrets
        self.db = sqlite3.connect(self.root/'state.sqlite', timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,label TEXT,start TEXT,end TEXT,state TEXT);
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,run TEXT,event_time TEXT,ingest_time TEXT,
          kinds TEXT,selftest INTEGER,payload TEXT,raw_hash TEXT,source TEXT,status TEXT DEFAULT 'pending',
          attempts INTEGER DEFAULT 0,next_try REAL DEFAULT 0,error TEXT,alert_id INTEGER,file_id INTEGER,timeline_id INTEGER);
        CREATE TABLE IF NOT EXISTS provenance(event TEXT,source TEXT,raw_hash TEXT,PRIMARY KEY(event,source,raw_hash));
        CREATE TABLE IF NOT EXISTS cursors(identity TEXT PRIMARY KEY,path TEXT,offset INTEGER,anchor TEXT,done INTEGER,size INTEGER,mtime INTEGER);
        CREATE TABLE IF NOT EXISTS issues(kind TEXT,source TEXT,detail TEXT,at TEXT,UNIQUE(kind,source,detail));
        CREATE TABLE IF NOT EXISTS confirmations(run TEXT,stage INTEGER,analyst TEXT,note TEXT,at TEXT,PRIMARY KEY(run,stage));
        CREATE TABLE IF NOT EXISTS markers(run TEXT,stage INTEGER,action TEXT,at TEXT);
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT);
        ''')
        os.chmod(self.root/'state.sqlite', 0o600)
        if not self.current(): self.begin('监控部署准备（尚未正式演练）', 'prepared')

    def current(self):
        return self.db.execute('SELECT * FROM runs ORDER BY start DESC LIMIT 1').fetchone()

    def waiting_for_begin(self):
        paused = self.db.execute('SELECT value FROM metadata WHERE key="case_reset_waiting"').fetchone()
        return bool(paused and self.current()['id'] == paused['value'])

    def begin(self, label, state='running', case_id=None, request_id=None):
        at = now(); rid = 'g5-'+dt.datetime.now(UTC).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:6]
        with self.db:
            self.db.execute('UPDATE runs SET end=?,state="finished" WHERE end IS NULL', (at,))
            self.db.execute('INSERT INTO runs VALUES(?,?,?,NULL,?)', (rid,label[:120],at,state))
            if case_id is not None:
                if type(case_id) is not int or case_id<1:raise ValueError('invalid case id')
                self.db.execute('INSERT INTO metadata VALUES(?,?)',('case:'+rid,str(case_id)))
            if request_id:
                self.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('begin_request:'+request_id,json.dumps({'run':rid,'case_id':case_id})))
                self.db.execute('DELETE FROM metadata WHERE key="begin_pending"')
                self.db.execute('DELETE FROM metadata WHERE key="reuse_primary_once"')
        return rid

    def issue(self, kind, source, detail):
        self.db.execute('INSERT OR IGNORE INTO issues VALUES(?,?,?,?)', (kind,source,detail[:160],now()))

    def blob(self, folder, data):
        digest = sha(data); target = self.root/folder/digest[:2]/digest
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not target.exists():
            with target.open('xb') as stream: stream.write(data)
            target.chmod(0o600)
        return digest

    def enqueue(self, event, raw, source, forced_kind=None):
        if not isinstance(event, dict): return None
        kinds, test = classify(event)
        if getattr(self,'presentation_mode','')=='post_finish':
            from fact_alerts import selected
            if selected(event):kinds={'wazuh_detection'}
        if forced_kind: kinds.add(forced_kind)
        if not kinds: return None
        at = timestamp(event.get('timestamp'))
        if at is None:
            self.issue('invalid_event_time',source,'事件缺少带时区时间；未替换成采集时间')
            return None
        run = self.db.execute('SELECT * FROM runs WHERE start<=? AND (end IS NULL OR end>?) ORDER BY start DESC LIMIT 1', (at,at)).fetchone()
        if run is None: return None
        paused = self.db.execute('SELECT value FROM metadata WHERE key="case_reset_waiting"').fetchone()
        if paused and run['id'] == paused['value']: return None
        identity = [event.get('manager',{}).get('name'), event.get('agent',{}).get('id'), event.get('id')]
        eid = sha(canonical(identity)) if identity[-1] else sha(canonical(event))
        if 'log_hash_comparison' in kinds:
            before=event.get('data',{}).get('before_sha256') or event.get('syscheck',{}).get('sha256_before')
            previous=self.db.execute('SELECT value FROM metadata WHERE key=?',('log_snapshot:'+str(before),)).fetchone()
            if previous:
                previous=json.loads(previous['value'])
                if previous['ingest_time']<at and (self.root/'original'/previous['raw_hash'][:2]/previous['raw_hash']).is_file():
                    kinds.add('central_original_preserved')
        rh = self.blob('original',raw)
        old = self.db.execute('SELECT * FROM events WHERE id=?',(eid,)).fetchone()
        if old:
            merged = sorted(set(json.loads(old['kinds'])) | kinds)
            envelope=json.loads(old['payload'])
            new_rule=bool(event.get('rule')) and event['rule'] != envelope['event'].get('rule')
            if merged!=json.loads(old['kinds']) or new_rule:
                envelope['observed_kinds']=merged
                envelope['revision']=envelope.get('revision',1)+1
                envelope['additional_source']={'source':source,'raw_sha256':rh}
                envelope['event'].update(redact(event,self.secrets))
                self.db.execute('UPDATE events SET kinds=?,payload=?,status="pending",next_try=0,error=NULL WHERE id=?',
                                (json.dumps(merged),canonical(envelope).decode(),eid))
        else:
            clean = redact(event,self.secrets)
            envelope = dict(event=clean,observed_kinds=sorted(kinds),selftest=test,
                            raw_sha256=rh,source=source,event_time=at,ingest_time=now(),
                            run_id=run['id'],verdict='candidate_observation_not_confirmed')
            self.db.execute('INSERT INTO events(id,run,event_time,ingest_time,kinds,selftest,payload,raw_hash,source) VALUES(?,?,?,?,?,?,?,?,?)',
                            (eid,run['id'],at,now(),json.dumps(sorted(kinds)),int(test),canonical(envelope).decode(),rh,source))
        self.db.execute('INSERT OR IGNORE INTO provenance VALUES(?,?,?)',(eid,source,rh))
        if 'application_log_snapshot' in kinds:
            digest=event.get('data',{}).get('snapshot_sha256')
            text=event.get('data',{}).get('snapshot_text')
            if isinstance(digest,str) and re.fullmatch('[0-9a-f]{64}',digest) and isinstance(text,str) and sha(text.encode())==digest:
                self.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('log_snapshot:'+digest,json.dumps({'event_id':eid,'ingest_time':now(),'raw_hash':rh})))
            else:self.issue('snapshot_hash_mismatch',source,'未把无法复核的声明当作集中原件留存证明')
        return eid

    def ingest(self, source, limit=10000):
        path = Path(source); info = path.stat()
        compressed = path.suffix == '.gz'
        identity = f'gz:{path}:{info.st_size}:{info.st_mtime_ns}' if compressed else f'{info.st_dev}:{info.st_ino}'
        cursor = self.db.execute('SELECT * FROM cursors WHERE identity=?',(identity,)).fetchone()
        if cursor and compressed and cursor['done']: return 0
        if cursor and cursor['done'] and not compressed and cursor['size']==info.st_size and cursor['mtime']==info.st_mtime_ns: return 0
        count=0
        with (gzip.open(path,'rb') if compressed else path.open('rb')) as stream, self.db:
            offset = cursor['offset'] if cursor else 0
            stream.seek(max(0,offset-128)); anchor = sha(stream.read(offset-max(0,offset-128)))
            if cursor and (not compressed and offset>info.st_size or anchor!=cursor['anchor']):
                self.issue('source_reset',str(path),'文件截断或内容改变，重读并按事件ID去重')
                offset=0
            stream.seek(offset)
            for _ in range(limit):
                start=stream.tell(); line=stream.readline(MAX_LINE+1)
                if not line: break
                if len(line)>MAX_LINE:
                    digest=hashlib.sha256(line);length=len(line)
                    while line and not line.endswith(b'\n'):
                        line=stream.readline(MAX_LINE+1);digest.update(line);length+=len(line)
                    self.issue('oversize_line',str(path),f'{start}:{length}:{digest.hexdigest()}')
                    offset=stream.tell()
                    continue
                if not line.endswith(b'\n'):
                    stream.seek(start); break
                try:
                    event=json.loads(line)
                    if self.enqueue(event,line,str(path)):count+=1
                except (ValueError,TypeError,AttributeError):
                    self.blob('quarantine',line)
                    self.issue('invalid_json',str(path),str(start))
                offset=stream.tell()
            offset=stream.tell(); done=not bool(stream.read(1))
            stream.seek(max(0,offset-128)); anchor=sha(stream.read(offset-max(0,offset-128)))
            self.db.execute('INSERT OR REPLACE INTO cursors VALUES(?,?,?,?,?,?,?)',
                            (identity,str(path),offset,anchor,int(done),info.st_size,info.st_mtime_ns))
        return count

    def coverage(self, run=None):
        """Legacy offline coverage reader; not used for live alerts or reports."""
        stages=json.loads(Path(__file__).with_name('stages.json').read_text())
        rid=run or self.current()['id']
        rows=self.db.execute('SELECT * FROM events WHERE run=?',(rid,)).fetchall()
        result=dict(run=dict(self.db.execute('SELECT * FROM runs WHERE id=?',(rid,)).fetchone()),generated_at=now(),
                    selftest_events=sum(row['selftest'] for row in rows),stages=[],
                    queue={row['status']:0 for row in rows},issues=[dict(row) for row in self.db.execute('SELECT * FROM issues')])
        result['stage_markers']=[dict(row) for row in self.db.execute('SELECT * FROM markers WHERE run=? ORDER BY at',(rid,))]
        for row in rows:result['queue'][row['status']]+=1
        for stage in stages:
            observations={kind:[row['id'] for row in rows if not row['selftest'] and kind in json.loads(row['kinds'])] for kind in stage['required']}
            if stage['id']==10:
                real=[row for row in rows if not row['selftest']]
                roles={role_of(json.loads(row['payload'])['event']) for row in real}
                if len(roles-{None})>=2 and observations['application_log_change']:
                    observations['cross_host_timeline']=[row['id'] for row in sorted(real,key=lambda row:row['event_time'])]
            missing=[kind for kind,ids in observations.items() if not ids]
            confirmation=self.db.execute('SELECT * FROM confirmations WHERE run=? AND stage=?',(rid,stage['id'])).fetchone()
            state='observed' if not missing else 'partial' if any(observations.values()) else 'pending'
            result['stages'].append(dict(**stage,state=state,analyst_state='confirmed' if confirmation else 'pending',observations=observations,missing=missing,
                                         analyst_confirmation=dict(confirmation) if confirmation else None))
        return result


def discover(roots):
    found={}
    cutoff=time.time()-3*86400
    for root in roots:
        for path in Path(root).rglob('*.json*'):
            if not re.search(r'\.json(?:\.\d+)?(?:\.gz)?$',path.name):continue
            info=path.stat()
            if info.st_mtime<cutoff and path.name not in ('alerts.json','archives.json'):continue
            key=('gzip',str(path)) if path.suffix=='.gz' else (info.st_dev,info.st_ino)
            found[key]=path
    return sorted(found.values(),key=lambda path:(path.stat().st_mtime,str(path)))
