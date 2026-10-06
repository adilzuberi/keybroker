import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('manager', Path(__file__).with_name('release-manager.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
NOW = 1791318000

def metadata(seq=1, tag='v0.1.0-health.1', revoked=None):
    a = {'keybroker': {'sha256': m.digest(b'cli'), 'size': 3}, 'keybroker-mcp': {'sha256': m.digest(b'mcp'), 'size': 3}}
    return {'schema': 1, 'sequence': seq, 'release': tag, 'source_commit': '5'*40,
            'source_manifest_sha256': '6'*64, 'state_schema': 1, 'capabilities': ['system.status'],
            'issued_at': NOW-1, 'expires_at': NOW+86400, 'revoked': revoked or [], 'artefacts': {'linux-amd64': a}}

def raw(x): return json.dumps(x, sort_keys=True, separators=(',', ':')).encode()
def envelope(b): return raw({'payload': base64.b64encode(b).decode(), 'signature': ''})

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)/'root'; self.root.mkdir()
        (self.root/'state').mkdir(); (self.root/'releases').mkdir()
        self.original = raw(metadata()); self.sha = m.digest(self.original)
        self.stage(self.original)
        (self.root/'current').symlink_to('releases/'+self.sha)
        self.policy = {'schema': 1, 'owner_uid': 1000, 'owner_user': 'worker', 'platform': 'linux-amd64',
                       'approved_manifest_sha256': [self.sha], 'release_public_key_hex': '',
                       'verifier_sha256': '7'*64, 'offline_grace_seconds': 86400, 'enabled': True}
        self.state = {'schema': 1, 'current': self.sha, 'previous': None, 'sequence': 1,
                      'metadata_sha256': self.sha, 'last_verified_at': NOW, 'expires_at': NOW+86400, 'revoked': [], 'failed': []}
        self.write()
        # Ownership is exercised separately; synthetic temporary roots are never installations.
        self.guard = patch.object(m, 'protected'); self.guard.start()
        self.addCleanup(self.guard.stop); self.addCleanup(self.temp.cleanup)

    def write(self):
        (self.root/'policy.json').write_bytes(raw(self.policy)); (self.root/'state/installed.json').write_bytes(raw(self.state))

    def stage(self, b):
        p = self.root/'releases'/m.digest(b); p.mkdir()
        (p/'manifest.json').write_bytes(b)
        for role, data in [('keybroker', b'cli'), ('keybroker-mcp', b'mcp')]:
            (p/role).write_bytes(data); (p/role).chmod(0o555)

    def manager(self, b=None, fetch=None, now=NOW):
        return m.Manager(self.root, fetch or (lambda url, limit: envelope(b or self.original)), lambda: now)

    def approve(self, b):
        self.policy['approved_manifest_sha256'].append(m.digest(b)); self.write()

    def test_current_release(self):
        self.assertEqual(self.manager().check(), 'current')

    def test_metadata_authentication_required(self):
        b=raw(metadata(2)); self.assertRaises(m.Refused, self.manager(b).check)

    def test_signature_rejects_wrong_key(self):
        self.policy['release_public_key_hex']='a'*64
        verifier=self.root/'verify';verifier.write_bytes(b'synthetic verifier')
        self.policy['verifier_sha256']=m.digest(verifier.read_bytes())
        with patch.object(m.subprocess, 'run') as run:
            run.return_value.returncode=3
            self.assertRaises(m.Refused, m.authenticate, {'payload':base64.b64encode(self.original).decode(),'signature':'0'*128},
                              dict(self.policy, approved_manifest_sha256=[]), verifier)

    def test_corrupted_metadata_and_duplicate_fields(self):
        self.assertRaises(m.Refused, m.decode, b'{"schema":1,"schema":2}')
        self.assertRaises(m.Refused, m.decode, b'x'*65537)

    def test_platform_and_state_incompatibility(self):
        for field, value in [('state_schema', 2), ('schema', 2), ('capabilities', ['ssh.execute']), ('release', '../bad')]:
            x=metadata();x[field]=value
            self.assertRaises(m.Refused, m.manifest, raw(x), 'linux-amd64', NOW)
        self.assertRaises(m.Refused, m.manifest, self.original, 'linux-arm64', NOW)

    def test_expiry_clock_and_replay(self):
        self.assertRaises(m.Refused, m.manifest, self.original, 'linux-amd64', NOW+86400)
        self.assertRaises(m.Refused, self.manager(now=NOW-100).check)
        b=raw(metadata(1,'v0.1.0-health.2'));self.approve(b)
        self.assertRaises(m.Refused, self.manager(b).check)

    def test_revocation_persisted_before_download(self):
        b=raw(metadata(2,'v0.1.0-health.2',[self.sha]));self.approve(b)
        self.assertRaises(m.Refused, self.manager(b).check)
        self.assertIn(self.sha, m.decode((self.root/'state/installed.json').read_bytes())['revoked'])
        self.assertRaises(m.Refused, self.manager().check)

    def test_offline_bounded_use(self):
        def off(*args):raise m.Offline()
        self.assertEqual(self.manager(fetch=off).check(), 'offline-approved')
        self.assertRaises(m.Refused, self.manager(fetch=off, now=NOW+86401).check)
        def rejected(*args):raise m.Refused()
        self.assertRaises(m.Refused, self.manager(fetch=rejected).check)

    def test_replaced_installed_binary_and_pointer(self):
        f=self.root/'releases'/self.sha/'keybroker';f.chmod(0o755);f.write_bytes(b'bad');f.chmod(0o555)
        self.assertRaises(m.Refused, self.manager().check)
        f.chmod(0o755);f.write_bytes(b'cli');f.chmod(0o555)
        (self.root/'current').unlink();(self.root/'current').symlink_to('/arbitrary')
        self.assertRaises(m.Refused, self.manager().check)

    def test_upgrade_with_proof_and_no_shell(self):
        b=raw(metadata(2,'v0.1.0-health.2'));self.approve(b)
        def fetch(url, limit):
            if url==m.CHANNEL:return envelope(b)
            return b'mcp' if url.endswith('keybroker-mcp-linux-amd64') else b'cli'
        x=self.manager(fetch=fetch)
        with patch.object(x,'restart') as restart,patch.object(x,'probe') as probe:
            self.assertEqual(x.check(),'upgraded');restart.assert_called_once();probe.assert_called_once_with(m.digest(b))
        self.assertEqual(x.state['previous'], self.sha)
        self.assertEqual((self.root/'current').readlink(), Path('releases')/m.digest(b))

    def test_failed_health_restores_previous(self):
        b=raw(metadata(2,'v0.1.0-health.2'));self.approve(b);self.stage(b)
        x=self.manager(b)
        with patch.object(x,'restart'),patch.object(x,'probe',side_effect=[m.Refused('bad'),None]):
            self.assertRaises(m.Refused,x.check)
        self.assertEqual((self.root/'current').readlink(),Path('releases')/self.sha)
        self.assertEqual(m.decode((self.root/'state/installed.json').read_bytes())['sequence'],2)

    def test_download_hash_failure_and_resume(self):
        b=raw(metadata(2,'v0.1.0-health.2'));self.approve(b)
        def fetch(url,limit):return envelope(b) if url==m.CHANNEL else b'bad'
        self.assertRaises(m.Refused,self.manager(fetch=fetch).check)
        self.assertEqual((self.root/'current').readlink(),Path('releases')/self.sha)
        def good(url,limit):return envelope(b) if url==m.CHANNEL else (b'mcp' if 'keybroker-mcp-' in url else b'cli')
        x=self.manager(fetch=good)
        with patch.object(x,'restart'),patch.object(x,'probe'):self.assertEqual(x.check(),'upgraded')

    def test_interrupted_upgrade_and_interrupted_receipt(self):
        b=raw(metadata(2,'v0.1.0-health.2'));self.stage(b)
        x=self.manager();x.link(m.digest(b))
        m.save(self.root/'state/transaction.json',{'previous':self.sha,'candidate':m.digest(b)})
        with patch.object(x,'restart'),patch.object(x,'probe'):x.recover()
        self.assertEqual((self.root/'current').readlink(),Path('releases')/self.sha)
        x.state['current']=m.digest(b);x.record()
        m.save(self.root/'state/transaction.json',{'previous':self.sha,'candidate':m.digest(b)})
        with patch.object(x,'restart'),patch.object(x,'probe'):x.recover()
        self.assertEqual((self.root/'current').readlink(),Path('releases')/m.digest(b))

    def test_rollback_denies_revoked_release(self):
        x=self.manager();x.state.update(previous='8'*64,revoked=['8'*64])
        self.assertRaises(m.Refused,x.rollback)

    def test_online_successor_after_installed_lease_expiry(self):
        self.state['expires_at']=NOW-86400;self.state['last_verified_at']=NOW-2*86400;self.write()
        b=raw(metadata(2,'v0.1.0-health.2'));self.approve(b);self.stage(b)
        x=self.manager(b)
        with patch.object(x,'restart'),patch.object(x,'probe'):self.assertEqual(x.check(),'upgraded')

    def test_recovery_does_not_execute_cached_revoked_release(self):
        x=self.manager();x.state['revoked']=[self.sha]
        m.save(self.root/'state/transaction.json',{'previous':self.sha,'candidate':'8'*64})
        with patch.object(x,'restart') as restart:
            self.assertRaises(m.Refused,x.recover);restart.assert_not_called()

class OwnershipTests(unittest.TestCase):
    def test_writable_and_symlink_paths_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file';p.write_bytes(b'public');p.chmod(0o666)
            self.assertRaises(m.Refused,m.protected,p)
            s=Path(d)/'link';s.symlink_to(p)
            self.assertRaises(m.Refused,m.protected,s)

if __name__ == '__main__': unittest.main()
