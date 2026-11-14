import gzip
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).with_name('monitoring')))
import agent_files as files
import agent_runner
import agent_query_guest


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.req=dict(role=7,query='files',start='2026-11-04T19:26:44+00:00',end='2026-11-04T19:28:59+00:00',match='',operation='read',path=str(self.root/'app.log'))
    def pages(self,req=None):
        req=dict(req or self.req);all=[]
        while True:
            answer=files.run(req);self.assertTrue(answer['ok']);all.append(answer)
            if not answer['has_more']:return all
            self.assertLess(len(all),50);req['cursor']=answer['continuation']
    def test_more_than_80_lines_are_read_without_overlap_and_source_is_unchanged(self):
        p=Path(self.req['path']);text=''.join(f'line {n}\n' for n in range(213));p.write_text(text);before=p.stat()
        pages=self.pages();self.assertEqual([len(x['records']) for x in pages],[80,80,53])
        self.assertEqual([r['text'] for x in pages for r in x['records']],[f'line {n}' for n in range(213)])
        self.assertEqual(p.read_text(),text);self.assertEqual(p.stat().st_mtime_ns,before.st_mtime_ns)
    def test_json_state_can_be_read_and_credential_values_are_redacted(self):
        p=self.root/'agent.json';p.write_text(json.dumps(dict(password='HIDDEN',nested={'api_key':'OTHER'},observations=[dict(message='业务日志') for _ in range(200)],encrypted_content='CIPHER')))
        pages=self.pages(dict(self.req,path=str(p)))
        text='\n'.join(r['text'] for x in pages for r in x['records'])
        for value in ('HIDDEN','OTHER','CIPHER'):self.assertNotIn(value,text)
        self.assertIn('业务日志',text);self.assertEqual(pages[0]['format'],'formatted_redacted_json')
    def test_secret_files_virtual_files_and_special_devices_are_not_exposed(self):
        p=self.root/'credentials.txt';p.write_text('SENSITIVE CONTENT')
        answer=files.run(dict(self.req,path=str(p)));self.assertTrue(answer['content_withheld']);self.assertNotIn('SENSITIVE',json.dumps(answer))
        alias=self.root/'alias';alias.symlink_to(p);self.assertTrue(files.run(dict(self.req,path=str(alias)))['content_withheld'])
        with self.assertRaises(ValueError):files.run(dict(self.req,path='/proc/self/environ'))
        pipe=self.root/'pipe';os.mkfifo(pipe)
        with self.assertRaises(ValueError):files.run(dict(self.req,path=str(pipe)))
    def test_literal_search_and_gzip_do_not_execute_file_contents(self):
        p=self.root/'trace.log.gz';p.write_bytes(gzip.compress(('noise\n'*100+'needle $(touch /tmp/not-a-command)\n').encode()))
        result=self.pages(dict(self.req,path=str(p),operation='search',match='needle'))
        self.assertEqual(result[0]['records'][0]['line'],101);self.assertIn('$(touch',result[0]['records'][0]['text'])
    def test_directory_continuation_and_scope_binding(self):
        for n in range(81):(self.root/f'{n:03}.txt').write_text('x')
        req=dict(self.req,path=str(self.root),operation='list');pages=self.pages(req)
        self.assertEqual(sum(len(p['records']) for p in pages),81)
        with self.assertRaises(ValueError):files.run(dict(req,match='different',cursor=pages[0]['continuation']))
    def test_truncated_or_replaced_file_cannot_claim_complete(self):
        p=Path(self.req['path']);p.write_text('x\n'*81);first=files.run(self.req)
        p.write_text('short')
        last=files.run(dict(self.req,cursor=first['continuation']))
        self.assertFalse(last['ok']);self.assertFalse(last['coverage_complete'])
    def test_multiline_private_key_cannot_escape_across_pages(self):
        p=Path(self.req['path']);p.write_text('text\n-----BEGIN OPENSSH PRIVATE KEY-----\nVERYPRIVATE\nSECRETLINE\n-----END OPENSSH PRIVATE KEY-----\npublic\n')
        with patch.object(files,'PAGE_RECORDS',2):pages=self.pages()
        body=json.dumps(pages);self.assertNotIn('VERYPRIVATE',body);self.assertNotIn('SECRETLINE',body);self.assertIn('public',body)
    def test_pem_pagination_state_survives_storage_redaction(self):
        from core import redact
        p=Path(self.req['path']);p.write_text('text\n-----BEGIN OPENSSH PRIVATE KEY-----\nVERYPRIVATE\nSECRETLINE\n-----END OPENSSH PRIVATE KEY-----\npublic\n')
        request=dict(self.req);pages=[]
        with patch.object(files,'PAGE_RECORDS',2):
            for _ in range(5):
                page=redact(files.run(request));pages.append(page)
                if not page['has_more']:break
                self.assertIs(type(page['continuation']['inside_pem_block']),bool)
                request['cursor']=page['continuation']
        self.assertTrue(pages[-1]['coverage_complete'])
        body=json.dumps(pages);self.assertNotIn('VERYPRIVATE',body);self.assertNotIn('SECRETLINE',body);self.assertIn('public',body)
    def test_embedded_credentials_are_masked(self):
        value=files.scrub('db_password="HIDDEN" mysql://user:OTHER@db/ Bearer TOKEN sk-1234567890abcdefghij')
        for secret in ('HIDDEN','OTHER','TOKEN','sk-1234567890'):self.assertNotIn(secret,value)
    def test_public_ssh_config_and_passwd_are_readable_but_private_keys_are_not(self):
        folder=self.root/'.ssh';folder.mkdir();config=folder/'config';config.write_text('Host lab\n  Hostname 192.0.2.1\n')
        result=files.run(dict(self.req,path=str(config)))
        self.assertTrue(result['coverage_complete']);self.assertIn('Hostname',result['records'][1]['text'])
        self.assertFalse(files.protected('/etc/passwd'));self.assertTrue(files.protected('/etc/shadow'))
        self.assertTrue(files.protected(folder/'id_ed25519'))
    def test_remote_clock_error_cannot_backdate_file_collection(self):
        value=agent_runner.received_file_result({'collected_at':'2014-11-04T21:19:08+00:00','records':[]})
        self.assertEqual(value['host_collected_at'],'2014-11-04T21:19:08+00:00')
        self.assertIn('host_clock_warning',value);self.assertNotEqual(value['collected_at'],value['host_collected_at'])

    def test_denied_hosts_are_rejected_before_transport_or_file_open(self):
        with patch('agent_runner.subprocess.run') as transport,patch('agent_files.safe_path') as open_path:
            for role in (1,10,11):
                with self.assertRaises(ValueError):files.run(dict(self.req,role=role))
                with self.assertRaises(ValueError):agent_runner.query_files({'request':dict(self.req,role=role)})
                req={k:v for k,v in dict(self.req,role=role,query='authentication').items() if k not in ('operation','path')}
                with self.assertRaises(ValueError):agent_runner.query_guest({'request':req})
                with self.assertRaises(ValueError):agent_query_guest.run(req)
            transport.assert_not_called();open_path.assert_not_called()
        exposed={t['name']:t['parameters']['properties'].get('host',{}).get('enum',[]) for t in agent_runner.TOOLS}
        for name in ('query_host','inspect_files'):
            self.assertIn('VM3',exposed[name])
            for host in ('VM1','B','C'):self.assertNotIn(host,exposed[name])

    def test_local_project_scope_blocks_traversal_symlinks_and_prefix_siblings(self):
        project=self.root/'project';project.mkdir();inside=project/'own-report.txt';inside.write_text('自己的调查报告')
        outside=self.root/'outside.txt';outside.write_text('OUTSIDE CONTENT')
        link=project/'link';link.symlink_to(outside)
        with patch.object(files,'LOCAL_FILE_ROOT',project):
            value=files.run(dict(self.req,role=0,path=str(inside)));self.assertTrue(value['ok'])
            for path in (outside,link,project/'..'/'outside.txt',self.root/'project-other'/'file'):
                with self.assertRaises(ValueError):files.run(dict(self.req,role=0,path=str(path)))
        self.assertEqual(str(files.LOCAL_FILE_ROOT),agent_runner.POLICY['local_file_root'])

    def test_vm3_file_reader_keeps_employee_endpoint_access(self):
        p=Path(self.req['path']);p.write_text('员工工作站日志')
        result=files.run(dict(self.req,role=3))
        self.assertTrue(result['ok']);self.assertEqual(result['host'],'VM3')

    def test_local_reader_works_under_worker_no_new_privileges_without_sudo(self):
        req=dict(self.req,role=0,path=str(files.LOCAL_FILE_ROOT/'scripts/monitoring/agent_policy.json'))
        with patch('agent_runner.subprocess.run') as run:
            run.return_value.returncode=0;run.return_value.stdout=json.dumps(dict(ok=True,collected_at='2026-11-04T21:00:00+00:00',records=[]))
            self.assertTrue(agent_runner.query_files({'request':req})['ok'])
            self.assertNotIn('sudo',run.call_args.args[0])


if __name__=='__main__':unittest.main()
