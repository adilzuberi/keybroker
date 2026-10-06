import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

s=importlib.util.spec_from_file_location('installer',Path(__file__).with_name('install.py'))
i=importlib.util.module_from_spec(s);s.loader.exec_module(i)

class InstallerTests(unittest.TestCase):
    def fixture(self,d):
        p=Path(d);(p/'release-manager.py').write_bytes(b'reviewed bytes')
        b=json.dumps({'schema':1,'files':{'release-manager.py':i.h(b'reviewed bytes')}}).encode()
        (p/'bootstrap.json').write_bytes(b);return p,i.h(b)

    def test_verified_snapshot_survives_staging_swap(self):
        with tempfile.TemporaryDirectory() as d:
            p,sha=self.fixture(d);boot,verified=i.load_bundle(p,sha)
            (p/'release-manager.py').write_bytes(b'unapproved replacement')
            self.assertEqual(verified['release-manager.py'],b'reviewed bytes')
            self.assertRaises(SystemExit,i.load_bundle,p,sha)

    def test_wrong_bootstrap_or_link_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p,sha=self.fixture(d)
            self.assertRaises(SystemExit,i.load_bundle,p,'0'*64)
            (p/'release-manager.py').rename(p/'preserved')
            (p/'release-manager.py').symlink_to(p/'preserved')
            self.assertRaises(SystemExit,i.load_bundle,p,sha)

    def test_existing_target_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file';p.write_bytes(b'existing')
            self.assertRaises(FileExistsError,i.write_new,p,b'new',0o600)
            self.assertEqual(p.read_bytes(),b'existing')

    def test_wrapper_and_unit_have_fixed_scope(self):
        w=i.wrapper('keybroker-mcp','/run/keybroker-health/keybroker.sock','worker').decode()
        self.assertIn('/usr/bin/sudo -n /usr/local/libexec/keybroker-health-maintain check',w)
        self.assertNotIn('curl',w);self.assertNotIn('bunny',w)
        unit=i.service('worker').decode()
        self.assertIn('User=worker',unit);self.assertIn('RestrictAddressFamilies=AF_UNIX',unit)
        self.assertIn('NoNewPrivileges=true',unit)

    def test_failed_install_stops_only_new_service_and_preserves_files(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'state').mkdir()
            with patch.object(i,'ROOT',root),patch.object(i,'ACTIVE_UNIT',Path('/etc/systemd/system/keybroker-health.service')),patch.object(i,'START_ATTEMPTED',True),patch.object(i.os,'geteuid',return_value=0),patch.object(i.platform,'system',return_value='Linux'),patch.object(i.subprocess,'run',return_value=subprocess.CompletedProcess([],0)) as run:
                i.stop_failed_install()
                self.assertEqual(run.call_args.args[0],['/usr/bin/systemctl','disable','--now','keybroker-health.service'])
                self.assertTrue((root/'state/installation-failed.json').exists())
                receipt=json.loads((root/'state/installation-failed.json').read_bytes())
                self.assertEqual(receipt['stop']['exit_code'],0)

    def test_failed_stop_and_timeout_are_not_reported_as_stopped(self):
        for response in [subprocess.CompletedProcess([],1),subprocess.TimeoutExpired('fixed stop',20)]:
            with self.subTest(response=type(response).__name__),tempfile.TemporaryDirectory() as d:
                root=Path(d);(root/'state').mkdir()
                settings={'side_effect':response} if isinstance(response,Exception) else {'return_value':response}
                with patch.object(i,'ROOT',root),patch.object(i,'ACTIVE_UNIT',Path('/etc/systemd/system/keybroker-health.service')),patch.object(i,'START_ATTEMPTED',True),patch.object(i.os,'geteuid',return_value=0),patch.object(i.platform,'system',return_value='Linux'),patch.object(i.subprocess,'run',**settings):
                    i.stop_failed_install()
                receipt=json.loads((root/'state/installation-failed.json').read_bytes())
                self.assertIn(receipt['stop']['outcome'],['command failed','timed out'])
                self.assertIn('requires inspection',receipt['state'])

    def test_fresh_linux_validation_sees_executables_before_grants(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'bootstrap').mkdir();(root/'releases').mkdir()
            manifest=b'approved manifest';sha=i.h(manifest);plat='linux-amd64'
            verified={'release-manager.py':b'manager','release-verify-'+plat:b'verifier',
                      'keybroker-'+plat:b'cli','keybroker-mcp-'+plat:b'mcp'}
            def validate(command,**kwargs):
                self.assertEqual(command[:2],['/usr/bin/systemd-analyze','verify'])
                for role in ['keybroker','keybroker-mcp']:
                    executable=root/'current'/role
                    self.assertTrue(executable.is_file())
                    self.assertTrue(os.access(executable,os.X_OK))
                    self.assertEqual(executable.read_bytes(),verified[role+'-'+plat])
                self.assertFalse((root/'policy.json').exists())
                self.assertTrue(Path(command[2]).is_file())
                return subprocess.CompletedProcess(command,0)
            with patch.object(i,'ROOT',root),patch.object(i.subprocess,'run',side_effect=validate) as run:
                i.stage_and_validate_release(verified,sha,manifest,plat,Path('keybroker-health.service'),i.service('worker'),'linux')
                run.assert_called_once()

if __name__=='__main__':unittest.main()
