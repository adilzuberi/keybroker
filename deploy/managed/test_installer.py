import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
import stat
from types import SimpleNamespace
from unittest.mock import patch

s=importlib.util.spec_from_file_location('installer',Path(__file__).with_name('install.py'))
i=importlib.util.module_from_spec(s);s.loader.exec_module(i)

class InstallerTests(unittest.TestCase):
    def parent_metadata(self,goos='darwin',link='private/etc',changes=None,canonical='/private/etc',target='/etc/sudoers.d/keybroker-health'):
        metadata={'/etc':(0,stat.S_IFLNK|0o755)}
        metadata.update(changes or {})
        def lstat(path):
            uid,mode=metadata.get(str(path),(0,stat.S_IFDIR|0o755))
            return SimpleNamespace(st_uid=uid,st_mode=mode)
        # Every filesystem observation is mocked, including canonical system paths.
        with patch.object(Path,'exists',return_value=True),patch.object(Path,'lstat',lstat),patch.object(Path,'resolve',return_value=Path(canonical)),patch.object(i.os,'readlink',return_value=link):
            i.validate_install_parent(Path(target),goos)

    def test_mac_fixed_system_alias_requires_protected_canonical_chain(self):
        for link in ('private/etc','/private/etc'):
            with self.subTest(link=link):self.parent_metadata(link=link)

    def test_system_alias_wrong_platform_owner_or_destination_denied(self):
        cases=[{'goos':'linux'},{'changes':{'/etc':(501,stat.S_IFLNK|0o755)}},
               {'link':'/tmp/etc'},{'link':'/tmp/indirect-alias','canonical':'/private/etc'},
               {'canonical':'/tmp/etc'}]
        for case in cases:
            with self.subTest(case=case):self.assertRaises(SystemExit,self.parent_metadata,**case)

    def test_system_alias_unprotected_canonical_ancestor_denied(self):
        for path in ('/','/private','/private/etc','/etc/sudoers.d'):
            for uid,mode in ((501,stat.S_IFDIR|0o755),(0,stat.S_IFDIR|0o777),(0,stat.S_IFLNK|0o755),(0,stat.S_IFREG|0o755)):
                with self.subTest(path=path,uid=uid,mode=mode):
                    self.assertRaises(SystemExit,self.parent_metadata,changes={path:(uid,mode)})

    def test_other_parent_links_remain_denied(self):
        self.assertRaises(SystemExit,self.parent_metadata,
                          target='/usr/local/bin/keybroker-health',
                          changes={'/usr/local':(0,stat.S_IFLNK|0o755)})

    def test_protected_linux_parent_chain_remains_allowed(self):
        self.parent_metadata(goos='linux',changes={'/etc':(0,stat.S_IFDIR|0o755)})

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
