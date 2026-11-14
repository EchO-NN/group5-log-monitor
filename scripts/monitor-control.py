#!/usr/bin/env python3
"""Operator commands for independent IRIS cases and post-run investigation."""
import argparse
import json
import os
from pathlib import Path
import shlex
import sys
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parent))
from transport import BASE,ssh

REMOTE='/usr/local/lib/group5-monitor/bridge.py'


def guest(command,timeout=180):
    output=ssh(8,command,timeout=timeout)
    return json.loads(output) if output.strip() else {}


def fetch_report():
    return {'location':'VM8 /var/lib/group5-monitor/reports; export from IRIS case'}


def main():
    parser=argparse.ArgumentParser(description='Wazuh IRIS 监控与调查')
    parser.add_argument('command',choices=['begin','status','finish','report','summary','ai'])
    parser.add_argument('--label',default='第五组演练')
    parser.add_argument('--run');parser.add_argument('--full',action='store_true')
    args=parser.parse_args();os.umask(0o077)
    if args.command=='ai':
        sys.path.insert(0,str(BASE/'scripts/monitoring'))
        from summary_preview import show
        show(BASE/'reports/summary-worker/live',full=args.full);return 0
    command=['python3',REMOTE,'--config','/etc/group5-monitor/config.json',args.command]
    pending=BASE/'runtime/pending-begin.json'
    if args.command=='begin':
        pending.parent.mkdir(parents=True,exist_ok=True)
        intent=json.loads(pending.read_text()) if pending.exists() else {'label':args.label,'id':uuid.uuid4().hex}
        if intent['label']!=args.label:raise ValueError('retry pending begin using its original label')
        pending.write_text(json.dumps(intent,ensure_ascii=False));pending.chmod(0o600)
        command+=['--label',args.label,'--request-id',intent['id']]
    if args.command=='finish' and args.run:command+=['--run',args.run]
    result=guest(shlex.join(command))
    if args.command=='begin':pending.unlink(missing_ok=True)
    print(json.dumps(result,ensure_ascii=False,indent=2));return 0


if __name__=='__main__':raise SystemExit(main())
