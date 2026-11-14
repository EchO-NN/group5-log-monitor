"""IRIS 2.4 API adapter with remote reconciliation before non-idempotent writes."""
import hashlib
import json
import os
from pathlib import Path
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request
import uuid


class RemoteError(Exception):
    def __init__(self, code='transport', retryable=True):
        self.code,self.retryable=code,retryable
        super().__init__(str(code))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def walk(value):
    if isinstance(value,dict):
        yield value
        for child in value.values():yield from walk(child)
    elif isinstance(value,list):
        for child in value:yield from walk(child)


class Iris:
    def invalidate_indexes(self):
        # These are per-batch hints, never a replacement for retry reconciliation.
        self._evidence_tree=None
        self._timeline_entries=None

    def __init__(self, config):
        self.config=dict(config)
        path=Path(config['credential_file'])
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            info=os.fstat(stream.fileno())
            if info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):raise ValueError('credential permissions')
            self.credentials=json.load(stream)
        self.key=self.credentials['api_key']
        self.base=config['iris_url'].rstrip('/')+'/'
        parsed=urllib.parse.urlsplit(self.base)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:raise ValueError('invalid IRIS HTTPS URL')
        self.cid=int(config['case_id']);self.customer=int(config['customer_id'])
        context=ssl.create_default_context(cafile=config['ca_file'])
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context),NoRedirect())

    def request(self,path,data=None,files=None,raw=False,timeout=20):
        headers={'Authorization':'Bearer '+self.key}
        if files:
            boundary='g5'+uuid.uuid4().hex
            parts=[]
            for key,value in data.items():parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
            for key,(name,blob) in files.items():
                if any(c in name for c in '\r\n"'):raise ValueError('filename')
                parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"; filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()+blob+b'\r\n')
            payload=b''.join(parts)+f'--{boundary}--\r\n'.encode()
            headers['Content-Type']='multipart/form-data; boundary='+boundary
        else:
            payload=json.dumps(data).encode() if data is not None else None
            headers['Content-Type']='application/json'
        req=urllib.request.Request(self.base+path,data=payload,headers=headers)
        try:
            with self.opener.open(req,timeout=timeout) as response:blob=response.read()
        except urllib.error.HTTPError as exc:
            raise RemoteError('http_'+str(exc.code),exc.code>=500 or exc.code in (408,429)) from None
        except (OSError,urllib.error.URLError):
            error=RemoteError();error.operation=path.split('?',1)[0]
            raise error from None
        if raw:return blob
        try:result=json.loads(blob)
        except ValueError:raise RemoteError('invalid_json') from None
        if result.get('status')!='success':raise RemoteError('api_rejected',False)
        return result.get('data')

    def alert(self,reference,payload):
        query=urllib.parse.urlencode({'source_reference':reference,'per_page':100})
        data=self.request('alerts/filter?'+query)
        existing=[item for item in data.get('alerts',[]) if item.get('alert_source_ref')==reference]
        if existing:
            item=existing[0]
            # Enrichment/presentation updates must preserve analyst disposition and ownership.
            fields=('alert_title','alert_description','alert_source_content','alert_source_event_time','alert_severity_id')
            if any(item.get(k)!=payload.get(k) for k in fields):
                changes={k:payload[k] for k in fields if k in payload}
                changes['alert_owner_id']=item.get('alert_owner_id') if item.get('alert_owner_id') is not None else -1
                self.request('alerts/update/'+str(item['alert_id']),changes)
            return int(item['alert_id'])
        return int(self.request('alerts/add',payload)['alert_id'])

    def merge(self,alert_id,note='G5AUTO: 候选观察，实际结论待监控人员确认。'):
        current=self.request('alerts/'+str(alert_id))
        cases=current.get('cases',[])
        if self.cid in cases or any(isinstance(x,dict) and x.get('case_id')==self.cid for x in cases):return
        self.request('alerts/merge/'+str(alert_id),dict(target_case_id=self.cid,iocs_import_list=[],assets_import_list=[],
                     note=note,import_as_event=False,case_tags='G5AUTO'))

    def timeline(self,marker,event):
        if getattr(self,'_timeline_entries',None) is None:
            self._timeline_entries=self.request('case/timeline/events/list?cid='+str(self.cid)).get('timeline',[])
        for entry in self._timeline_entries:
            if entry.get('event_title','').startswith(marker):
                if entry.get('event_raw') != event.get('event_raw'):
                    self.request('case/timeline/events/update/'+str(entry['event_id'])+'?cid='+str(self.cid),event)
                    entry.update(event)
                return entry['event_id']
        try:
            result=self.request('case/timeline/events/add?cid='+str(self.cid),event)
        except Exception:
            self.invalidate_indexes();raise
        self._timeline_entries.append(dict(event,event_id=result['event_id']))
        return result['event_id']

    def evidence(self,name,blob,description,tags='G5AUTO',register=True):
        transfer_options={'timeout':120} if len(blob)>1024*1024 else {}
        if getattr(self,'_evidence_tree',None) is None:
            self._evidence_tree=self.request('datastore/list/tree?cid='+str(self.cid))
        tree=self._evidence_tree
        digest=hashlib.sha256(blob).hexdigest()
        for item in walk(tree):
            if item.get('file_original_name')==name and str(item.get('file_sha256','')).lower()==digest:
                downloaded=self.request(f'datastore/file/view/{item["file_id"]}?cid={self.cid}',raw=True,**transfer_options)
                if hashlib.sha256(downloaded).hexdigest()!=digest:raise RemoteError('existing_evidence_hash_mismatch',False)
                return int(item['file_id'])
            if item.get('file_original_name')==name and not item.get('file_sha256'):
                raise RemoteError('partial_remote_evidence',False)
        parent=None
        for node in walk(tree):
            for key,child in node.items():
                if key.startswith('d-') and isinstance(child,dict) and child.get('name')=='Evidences':parent=int(key[2:])
        if parent is None:raise RemoteError('no_evidence_folder',False)
        try:
            item=self.request(f'datastore/file/add/{parent}?cid={self.cid}',
                              dict(file_original_name=name,file_password='',file_is_ioc='n',file_is_evidence='y' if register else 'n',
                                   file_description=description,file_tags=tags),{'file_content':(name,blob)},**transfer_options)
            if str(item['file_sha256']).lower()!=digest:raise RemoteError('upload_hash_mismatch',False)
            downloaded=self.request(f'datastore/file/view/{item["file_id"]}?cid={self.cid}',raw=True,**transfer_options)
            if hashlib.sha256(downloaded).hexdigest()!=digest:raise RemoteError('download_hash_mismatch',False)
        except Exception:
            self.invalidate_indexes();raise
        # Keep our own successful writes visible within this batch.
        self._evidence_tree={'cached_tree':tree,'new_file':dict(item,file_original_name=name)}
        return int(item['file_id'])

