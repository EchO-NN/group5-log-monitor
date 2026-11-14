#!/usr/bin/env python3
"""Collect endpoint telemetry over configured SSH aliases and deliver to VM8."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from transport import BASE,invoke


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--roles',type=int,nargs='+',choices=range(2,10),default=[2,3,4,5,6,7,9])
    parser.add_argument('--state',type=Path,default=BASE/'runtime/collector')
    args=parser.parse_args();os.umask(0o077);args.state.mkdir(parents=True,exist_ok=True)
    with (args.state/'lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return 0
        path=args.state/'cursors.json';cursors=json.loads(path.read_text()) if path.exists() else {}
        collector=(BASE/'scripts/monitoring/collect_guest.py').read_text()
        statuses={}
        for role in args.roles:
            prefix=''
            if role==9:
                module=(BASE/'scripts/monitoring/performance.py').read_text()
                prefix="import sys,types\np=types.ModuleType('performance')\nexec("+repr(module)+",p.__dict__)\nsys.modules['performance']=p\n"
            try:
                result=invoke(role,prefix+'ROLE='+str(role)+'\nREQUEST='+repr(cursors.get(str(role),{}))+'\n'+collector,timeout=100)
                if result.get('kind')!='g5_collection_result' or result.get('role')!=role:raise ValueError('collector identity')
                blob=b''.join(json.dumps(e,ensure_ascii=False,sort_keys=True).encode()+b'\n' for e in result['events'])
                if blob:
                    digest=hashlib.sha256(blob).hexdigest()
                    source="""import base64,hashlib,json,os,pathlib,tempfile
blob=base64.b64decode(BLOB)
assert hashlib.sha256(blob).hexdigest()==DIGEST
root=pathlib.Path('/var/lib/group5-monitor/management-inbox');root.mkdir(parents=True,exist_ok=True,mode=0o700)
target=root/(DIGEST+'.jsonl')
if not target.exists():
 fd,tmp=tempfile.mkstemp(dir=root)
 with os.fdopen(fd,'wb') as f:f.write(blob);f.flush();os.fsync(f.fileno())
 os.replace(tmp,target)
print(json.dumps({'sha256':DIGEST}))
""".replace('BLOB',repr(base64.b64encode(blob).decode())).replace('DIGEST',repr(digest))
                    receipt=invoke(8,source)
                    if receipt.get('sha256')!=digest:raise ValueError('delivery checksum')
                cursors[str(role)]=result['cursor']
                temp=path.with_suffix('.tmp');temp.write_text(json.dumps(cursors));temp.replace(path)
                statuses['VM'+str(role)]={'state':'collected','events':len(result['events']),'capabilities':result['capabilities']}
            except (OSError,ValueError,RuntimeError,TimeoutError,subprocess.TimeoutExpired):statuses['VM'+str(role)]={'state':'unavailable','cursor_preserved':True}
        (args.state/'status.json').write_text(json.dumps(statuses,ensure_ascii=False,indent=2))
        print(json.dumps(statuses,ensure_ascii=False))
        return 0 if all(s['state']=='collected' for s in statuses.values()) else 2


if __name__=='__main__':raise SystemExit(main())
