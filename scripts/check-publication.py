#!/usr/bin/env python3
"""Check public source files without printing potentially sensitive values."""
import re
from pathlib import Path

root=Path(__file__).resolve().parents[1]
excluded={'.git','.venv','build','dist','__pycache__','runtime','reports','private'}
patterns=[re.compile(rb'sk-[A-Za-z0-9_-]{24,}'),re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'),
          re.compile(rb'github_pat_[A-Za-z0-9_]{30,}'),
          re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]')]
findings=[];count=0
for path in root.rglob('*'):
    rel=path.relative_to(root)
    if any(p in excluded or p.endswith('.egg-info') for p in rel.parts) or not path.is_file():continue
    if path.is_symlink():findings.append(str(rel)+': symlink');continue
    if path.name.endswith('.local.json') or path.name=='.env' or 'secrets' in rel.parts:
        findings.append(str(rel)+': local file present');continue
    data=path.read_bytes();count+=1
    if any(p.search(data) for p in patterns):findings.append(str(rel)+': credential pattern')
print('Checked',count,'public files;',len(findings),'findings')
for item in findings:print(item)
raise SystemExit(bool(findings))
