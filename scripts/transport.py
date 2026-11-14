"""SSH transport using user-managed aliases and pinned known_hosts entries."""
import json
import os
from pathlib import Path
import re
import subprocess

BASE=Path(__file__).resolve().parents[1]


def hosts():
    path=Path(os.environ.get('G5_HOSTS_CONFIG',BASE/'configs/hosts.local.json'))
    return json.loads(path.read_text())


def ssh(role,command,*,source=None,timeout=60):
    if role not in range(2,10):raise ValueError('host outside investigation scope')
    cfg=hosts();entry=cfg['hosts']['VM'+str(role)]
    alias=entry['ssh_alias']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}',alias):raise ValueError('invalid SSH alias')
    result=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
        '-o','ConnectTimeout=10',alias,command],input=source,capture_output=True,text=True,timeout=timeout)
    if result.returncode:raise RuntimeError('SSH operation failed; inspect connection locally')
    return result.stdout


def invoke(role,source,timeout=90,update_proxy=False,isolated_python=False):
    if update_proxy:raise ValueError('network configuration is managed separately')
    output=ssh(role,'python3 -I -',source=source,timeout=timeout)
    for line in reversed(output.splitlines()):
        try:
            value=json.loads(line)
            if isinstance(value,dict):return value
        except ValueError:pass
    raise RuntimeError('invalid guest JSON result')
