import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import json
import contextlib
import io
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent))
import transport


class TransportTests(unittest.TestCase):
    def test_only_vm2_to_vm9_are_available(self):
        with self.assertRaises(ValueError):transport.ssh(1,'python3 -I -')
        with patch.object(transport,'hosts',return_value={'hosts':{'VM9':{'ssh_alias':'lab-vm9'}}}),patch.object(transport.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'{"ok":true}\n','')) as run:
            result=transport.invoke(9,'print(1)')
            self.assertTrue(result['ok'])
            self.assertIn('StrictHostKeyChecking=yes',run.call_args[0][0])
            self.assertEqual(run.call_args.kwargs['input'],'print(1)')

    def test_shell_metacharacters_are_rejected_in_alias(self):
        with patch.object(transport,'hosts',return_value={'hosts':{'VM9':{'ssh_alias':'host; id'}}}):
            with self.assertRaises(ValueError):transport.ssh(9,'python3 -I -')

    def test_one_offline_host_does_not_stop_other_collectors(self):
        spec=importlib.util.spec_from_file_location('public_collector',Path(__file__).with_name('collect-monitor-remotes.py'))
        collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'scripts/monitoring';source.mkdir(parents=True)
            (source/'collect_guest.py').write_text('# fixture')
            def invoke(role,*args,**kwargs):
                if role==3:raise subprocess.TimeoutExpired('ssh',1)
                return {'kind':'g5_collection_result','role':role,'events':[],'cursor':{'offset':42},'capabilities':{}}
            with patch.object(collector,'BASE',root),patch.object(collector,'invoke',side_effect=invoke),patch.object(sys,'argv',['collector','--roles','3','4','--state',str(root/'state')]),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(collector.main(),2)
            state=json.loads((root/'state/status.json').read_text());cursors=json.loads((root/'state/cursors.json').read_text())
            self.assertEqual(state['VM3']['state'],'unavailable');self.assertEqual(state['VM4']['state'],'collected')
            self.assertNotIn('3',cursors);self.assertEqual(cursors['4']['offset'],42)


if __name__=='__main__':unittest.main()
