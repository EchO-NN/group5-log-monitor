"""One-time reuse guard for the deliberately emptied built-in IRIS case."""
import hashlib
import json
import subprocess
from core import canonical


def snapshot():
    # Read only. Refuse reuse if the case or its contents changed after preparation.
    query="""SELECT json_build_object(
      'case',(SELECT row_to_json(c) FROM cases c WHERE case_id=1),
      'cases',(SELECT count(*) FROM cases),
      'alerts',(SELECT count(*) FROM alerts),
      'events',(SELECT count(*) FROM cases_events),
      'tasks',(SELECT count(*) FROM case_tasks),
      'assets',(SELECT count(*) FROM case_assets),
      'notes',(SELECT count(*) FROM notes),
      'iocs',(SELECT count(*) FROM ioc_link),
      'files',(SELECT count(*) FROM data_store_file));"""
    result=subprocess.run(['docker','exec','-u','postgres','iriswebapp_db','psql','-X','-At','-v','ON_ERROR_STOP=1','-d','iris_db','-c',query],
                          capture_output=True,text=True,timeout=20)
    if result.returncode:raise ValueError('cannot verify empty primary case')
    data=json.loads(result.stdout)
    evidence=subprocess.run(['docker','exec','-u','postgres','iriswebapp_db','psql','-X','-At','-v','ON_ERROR_STOP=1','-d','iris_db','-c','SELECT count(*) FROM case_received_file;'],capture_output=True,text=True,timeout=20)
    if evidence.returncode or evidence.stdout.strip()!='0':raise ValueError('primary case has registered evidence')
    if data['cases']!=1 or not data['case'] or any(data[k] for k in ('alerts','events','tasks','assets','notes','iocs','files')):
        raise ValueError('primary case is not empty')
    return hashlib.sha256(canonical(data)).hexdigest()
