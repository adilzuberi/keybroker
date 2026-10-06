#!/usr/bin/env python3
"""Protected health-only updater. No URL, path, shell or credential input from clients."""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path('/opt/keybroker-health')
ORIGIN = 'https://truth.adilzuberi.com/git/adil/keybroker/releases/download/'
CHANNEL = ORIGIN + 'approved-health/channel.json'
MAX_META = 65536
MAX_BINARY = 32 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{64}\Z')
TAG = re.compile(r'v[0-9]+\.[0-9]+\.[0-9]+-health\.[0-9]+\Z')
PLATFORMS = {'linux-amd64', 'linux-arm64', 'darwin-arm64'}

class Refused(Exception):
    pass

class Offline(Exception):
    pass

def digest(b):
    return hashlib.sha256(b).hexdigest()

def decode(b):
    def unique(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise Refused('duplicate JSON field')
            d[k] = v
        return d
    try:
        if len(b) > MAX_META:
            raise Refused('metadata too large')
        return json.loads(b, object_pairs_hook=unique)
    except (ValueError, TypeError) as e:
        raise Refused('invalid metadata') from e

def fields(d, names):
    if not isinstance(d, dict) or set(d) != set(names):
        raise Refused('unexpected metadata fields')

def number(n, minimum, maximum):
    if type(n) is not int or not minimum <= n <= maximum:
        raise Refused('invalid integer')

def protected(p, uid=0, directory=False):
    # Check every existing parent; a writable ancestor can replace trusted bytes.
    p = Path(p)
    for parent in [*reversed(p.parents), p]:
        s = parent.lstat()
        if parent.is_symlink() or s.st_uid != uid or s.st_mode & 0o022:
            raise Refused('unprotected installation path')
    if directory and not p.is_dir():
        raise Refused('expected directory')

def atomic(p, b, mode=0o600):
    tmp = p.with_name(p.name + '.new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(b); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, p)
        d = os.open(p.parent, os.O_RDONLY)
        try: os.fsync(d)
        finally: os.close(d)
    except BaseException:
        # Interrupted files stay for operator review, never broad cleanup.
        raise

def save(p, obj):
    atomic(p, json.dumps(obj, sort_keys=True, separators=(',', ':')).encode() + b'\n')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Refused('redirect forbidden')

def download(url, limit):
    # Exact paths derived from authenticated tags/roles; no caller URL accepted.
    if not url.startswith(ORIGIN) or '?' in url or '#' in url:
        raise Refused('unexpected release URL')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(urllib.request.Request(url, headers={'User-Agent': 'Keybroker-Health/1'}), timeout=3) as r:
            if r.status != 200 or r.geturl() != url:
                raise Refused('unexpected release response')
            length = r.headers.get('Content-Length')
            if length and int(length) > limit:
                raise Refused('download too large')
            # Socket timeout plus total byte/time bounds. No environment proxy.
            end = time.monotonic() + 15
            chunks, total = [], 0
            while True:
                if time.monotonic() > end:
                    raise Offline('download time bound reached')
                chunk = r.read(min(65536, limit + 1 - total))
                if not chunk: break
                chunks.append(chunk); total += len(chunk)
                if total > limit: raise Refused('download too large')
            return b''.join(chunks)
    except urllib.error.HTTPError as e:
        # A removed/missing channel is not proof that an old release is safe.
        raise Refused('release endpoint rejected request') from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise Offline('release transport unavailable') from e
    except ValueError as e:
        raise Refused('invalid response length') from e

def authenticate(envelope, policy, verifier):
    fields(envelope, ['payload', 'signature'])
    try:
        if not isinstance(envelope['payload'], str) or not isinstance(envelope['signature'], str):
            raise Refused('invalid envelope')
        b = base64.b64decode(envelope['payload'], validate=True)
    except (ValueError, TypeError) as e:
        raise Refused('invalid envelope') from e
    sha = digest(b)
    if sha in policy['approved_manifest_sha256']:
        # Explicit owner-reviewed bytes in root-owned policy are a trust anchor.
        return b, sha
    key = policy['release_public_key_hex']
    sig = envelope['signature']
    if not isinstance(key, str) or not re.fullmatch(r'[0-9a-f]{64}', key):
        raise Refused('release has no approved trust anchor')
    if not re.fullmatch(r'[0-9a-f]{128}', sig):
        raise Refused('invalid release signature')
    protected(verifier)
    if digest(verifier.read_bytes()) != policy['verifier_sha256']:
        raise Refused('bootstrap verifier changed')
    result = subprocess.run([str(verifier), key, sig], input=b, capture_output=True, timeout=3,
                            env={'PATH': '/usr/bin:/bin'})
    if result.returncode != 0:
        raise Refused('release signature rejected')
    return b, sha

def manifest(b, platform, now):
    m = decode(b)
    fields(m, ['schema', 'sequence', 'release', 'source_commit', 'source_manifest_sha256',
               'state_schema', 'capabilities', 'issued_at', 'expires_at', 'revoked', 'artefacts'])
    if m['schema'] != 1 or m['state_schema'] != 1 or m['capabilities'] != ['system.status']:
        raise Refused('incompatible health release')
    number(m['sequence'], 1, 2**53 - 1)
    number(m['issued_at'], 1, 2**53 - 1); number(m['expires_at'], 1, 2**53 - 1)
    if m['issued_at'] > now + 60 or m['expires_at'] <= now or not 0 < m['expires_at'] - m['issued_at'] <= 7 * 86400:
        raise Refused('release metadata expired or time invalid')
    if not isinstance(m['release'], str) or not TAG.fullmatch(m['release']):
        raise Refused('invalid release tag')
    if not re.fullmatch('[0-9a-f]{40}', m['source_commit']):
        raise Refused('invalid source commit')
    if not SHA.fullmatch(m['source_manifest_sha256']): raise Refused('invalid source manifest')
    if not isinstance(m['revoked'], list) or len(m['revoked']) > 1000 or any(not isinstance(x, str) or not SHA.fullmatch(x) for x in m['revoked']):
        raise Refused('invalid revocation list')
    if not isinstance(m['artefacts'], dict) or platform not in m['artefacts'] or set(m['artefacts']) - PLATFORMS:
        raise Refused('platform unavailable')
    for plat, roles in m['artefacts'].items():
        fields(roles, ['keybroker', 'keybroker-mcp'])
        for role, a in roles.items():
            fields(a, ['sha256', 'size'])
            if not isinstance(a['sha256'], str) or not SHA.fullmatch(a['sha256']): raise Refused('invalid artefact hash')
            number(a['size'], 1, MAX_BINARY)
    return m

class Manager:
    def __init__(self, root=ROOT, fetch=download, clock=time.time):
        self.root, self.fetch, self.clock = root, fetch, clock
        self.state_dir = root / 'state'
        protected(root, directory=True); protected(self.state_dir, directory=True)
        protected(root / 'policy.json'); self.policy = decode((root / 'policy.json').read_bytes())
        fields(self.policy, ['schema', 'owner_uid', 'owner_user', 'platform', 'approved_manifest_sha256',
                             'release_public_key_hex', 'verifier_sha256', 'offline_grace_seconds', 'enabled'])
        if self.policy['schema'] != 1 or self.policy['enabled'] is not True: raise Refused('updates disabled')
        if self.policy['platform'] not in PLATFORMS: raise Refused('invalid platform')
        number(self.policy['owner_uid'], 1, 2**31 - 1)
        number(self.policy['offline_grace_seconds'], 0, 86400)
        if not re.fullmatch('[a-z_][a-z0-9_-]{0,31}', self.policy['owner_user']): raise Refused('invalid service user')
        if not isinstance(self.policy['approved_manifest_sha256'], list) or any(not SHA.fullmatch(x) for x in self.policy['approved_manifest_sha256']): raise Refused('invalid approval pins')
        if not SHA.fullmatch(self.policy['verifier_sha256']): raise Refused('invalid verifier pin')
        protected(self.state_dir / 'installed.json')
        self.state = decode((self.state_dir / 'installed.json').read_bytes())
        fields(self.state, ['schema', 'current', 'previous', 'sequence', 'metadata_sha256', 'last_verified_at', 'expires_at', 'revoked', 'failed'])
        if self.state['schema'] != 1: raise Refused('incompatible installed state')
        for key in ['current', 'previous']:
            if self.state[key] is not None and (not isinstance(self.state[key], str) or not SHA.fullmatch(self.state[key])): raise Refused('invalid release state')
        number(self.state['sequence'], 1, 2**53 - 1)
        for key in ['last_verified_at', 'expires_at']: number(self.state[key], 1, 2**53-1)
        if not isinstance(self.state['revoked'], list) or any(not SHA.fullmatch(x) for x in self.state['revoked']): raise Refused('invalid cached revocations')
        if not isinstance(self.state['failed'], list) or any(not SHA.fullmatch(x) for x in self.state['failed']): raise Refused('invalid failed release list')

    def record(self):
        save(self.state_dir / 'installed.json', self.state)

    def audit(self, event, release=None):
        p = self.state_dir / 'updates.jsonl'
        if p.exists(): protected(p)
        fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as f:
            f.write(json.dumps({'time': int(self.clock()), 'event': event, 'manifest_sha256': release}) + '\n')
            f.flush(); os.fsync(f.fileno())

    def release(self, sha):
        if not isinstance(sha, str) or not SHA.fullmatch(sha): raise Refused('invalid release identity')
        p = self.root / 'releases' / sha
        protected(p, directory=True)
        raw = (p / 'manifest.json').read_bytes()
        if digest(raw) != sha: raise Refused('installed manifest changed')
        stored = decode(raw)
        m = manifest(raw, self.policy['platform'], min(int(self.clock()), stored['expires_at'] - 1))
        for role, a in m['artefacts'][self.policy['platform']].items():
            f = p / role; protected(f)
            data = f.read_bytes()
            if len(data) != a['size'] or digest(data) != a['sha256'] or f.stat().st_mode & 0o222:
                raise Refused('installed executable changed')
        return p

    def link(self, sha):
        self.release(sha)
        dest = self.root / 'current'; tmp = self.root / 'current.new'
        if tmp.exists() or tmp.is_symlink(): raise Refused('interrupted link needs review')
        os.symlink('releases/' + sha, tmp); os.replace(tmp, dest)
        fd = os.open(self.root, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)

    def command(self, argv, timeout=20):
        p = subprocess.run(argv, capture_output=True, timeout=timeout,
                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        if p.returncode: raise Refused('fixed service operation failed')

    def restart(self):
        if self.policy['platform'].startswith('linux-'):
            self.command(['/usr/bin/systemctl', 'restart', 'keybroker-health.service'])
        else:
            uid = str(self.policy['owner_uid'])
            self.command(['/bin/launchctl', 'kickstart', '-k', 'system/com.keybroker.health'])

    def probe(self, sha):
        p = self.release(sha) / 'keybroker'
        expected = decode(p.with_name('manifest.json').read_bytes())
        uid, user = self.policy['owner_uid'], self.policy['owner_user']
        if self.policy['platform'].startswith('linux-'):
            socket = '/run/keybroker-health/keybroker.sock'
            prefix = ['/usr/sbin/runuser', '-u', user, '--', '/usr/bin/env', 'KEYBROKER_SOCKET=' + socket]
        else:
            import pwd
            socket = str(Path(pwd.getpwuid(uid).pw_dir) / 'Library/Application Support/KeybrokerHealth/keybroker.sock')
            prefix = ['/usr/bin/sudo', '-u', user, '/usr/bin/env', 'KEYBROKER_SOCKET=' + socket]
        for args, code in [(['wait'], 0), (['capabilities'], 0), (['check', 'system.status'], 0),
                           (['invoke', 'system.status'], 0), (['invoke', 'credential.reveal'], 3),
                           (['invoke', 'bunny.zones.list'], 3), (['invoke', 'ssh.execute'], 3)]:
            r = subprocess.run(prefix + [str(p)] + args, capture_output=True, timeout=8,
                               env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
            if r.returncode != code: raise Refused('health or denial proof failed')
            if args[0] == 'capabilities' and [x.get('name') for x in decode(r.stdout)] != ['system.status']:
                raise Refused('unexpected live capability')
            if args == ['invoke', 'system.status']:
                o = decode(r.stdout)
                if o.get('allowed') is not True or o.get('output', {}).get('status') != 'ok': raise Refused('health output failed')
                if o['output'].get('release') != expected['release'] or o['output'].get('source') != expected['source_manifest_sha256']:
                    raise Refused('running release identity mismatch')

    def recover(self):
        journal = self.state_dir / 'transaction.json'
        if journal.exists():
            protected(journal)
            j = decode(journal.read_bytes()); fields(j, ['previous', 'candidate'])
            if j['candidate'] == self.state['current']:
                if j['candidate'] in self.state['revoked']: raise Refused('recovery release revoked')
                self.link(j['candidate']); self.restart(); self.probe(j['candidate'])
                self.audit('completed interrupted receipt', j['candidate'])
            elif j['previous'] == self.state['current']:
                if j['previous'] in self.state['revoked']: raise Refused('recovery release revoked')
                self.link(j['previous']); self.restart(); self.probe(j['previous'])
                self.audit('recovered interrupted upgrade', j['candidate'])
            else: raise Refused('transaction needs operator reconciliation')
            journal.unlink()
        current = self.root / 'current'
        if not current.is_symlink() or os.readlink(current) != 'releases/' + self.state['current']:
            raise Refused('unexpected current pointer')

    def prepare(self, raw, sha, m):
        p = self.root / 'releases' / sha
        if p.exists():
            protected(p, directory=True)
            if digest((p / 'manifest.json').read_bytes()) != sha: raise Refused('staged manifest changed')
        else:
            p.mkdir(mode=0o755)
            atomic(p / 'manifest.json', raw, 0o444)
        for role, a in m['artefacts'][self.policy['platform']].items():
            if (p / role).exists():
                protected(p / role)
                if digest((p / role).read_bytes()) != a['sha256']: raise Refused('staged executable changed')
                continue
            name = role + '-' + self.policy['platform']
            data = self.fetch(ORIGIN + m['release'] + '/' + name, a['size'])
            if len(data) != a['size'] or digest(data) != a['sha256']:
                raise Refused('artefact hash or length mismatch')
            atomic(p / role, data, 0o555)
        self.release(sha)

    def check(self):
        self.recover(); self.release(self.state['current'])
        if self.state['current'] in self.state['revoked']: raise Refused('installed release revoked')
        now = int(self.clock())
        if now < self.state['last_verified_at'] - 60: raise Refused('clock moved backwards')
        try:
            envelope = decode(self.fetch(CHANNEL, MAX_META))
        except Offline:
            if now > min(self.state['expires_at'], self.state['last_verified_at'] + self.policy['offline_grace_seconds']):
                raise Refused('offline health lease expired')
            self.audit('offline approved health use', self.state['current'])
            return 'offline-approved'
        raw, sha = authenticate(envelope, self.policy, self.root / 'bootstrap' / 'release-verify')
        m = manifest(raw, self.policy['platform'], now)
        if sha in m['revoked']: raise Refused('channel release revoked')
        if sha in self.state['failed']: raise Refused('failed release quarantined; new approval required')
        if m['sequence'] < self.state['sequence'] or (m['sequence'] == self.state['sequence'] and sha != self.state['metadata_sha256']):
            raise Refused('release replay or equivocation')
        # Record authenticated revocation before downloading anything.
        self.state['revoked'] = sorted(set(self.state['revoked']) | set(m['revoked']))
        self.state.update(sequence=m['sequence'], metadata_sha256=sha)
        if self.state['current'] in self.state['revoked']:
            self.record(); self.audit('installed release revoked', self.state['current'])
            raise Refused('installed release revoked; operator recovery required')
        if sha == self.state['current']:
            self.state.update(last_verified_at=now, expires_at=m['expires_at'])
            self.record(); self.audit('approved release checked', sha)
            return 'current'
        self.record()
        self.prepare(raw, sha, m)
        old = self.state['current']
        self.audit('upgrade prepared', sha)
        save(self.state_dir / 'transaction.json', {'previous': old, 'candidate': sha})
        try:
            self.link(sha); self.restart(); self.probe(sha)
        except Exception:
            self.link(old); self.restart(); self.probe(old)
            self.audit('upgrade rolled back after failed proof', sha)
            self.state['failed'] = sorted(set(self.state['failed']) | {sha}); self.record()
            (self.state_dir / 'transaction.json').unlink()
            raise Refused('upgrade failed; previous release restored')
        self.state.update(current=sha, previous=old, sequence=m['sequence'], metadata_sha256=sha,
                          last_verified_at=now, expires_at=m['expires_at'])
        self.record(); self.audit('upgrade verified', sha)
        (self.state_dir / 'transaction.json').unlink()
        return 'upgraded'

    def rollback(self):
        self.recover()
        previous = self.state['previous']
        if previous is None or previous in self.state['revoked']: raise Refused('no non-revoked rollback release')
        old = self.state['current']
        save(self.state_dir / 'transaction.json', {'previous': old, 'candidate': previous})
        self.link(previous)
        try: self.restart(); self.probe(previous)
        except Exception:
            self.link(old); self.restart(); self.probe(old)
            (self.state_dir / 'transaction.json').unlink(); raise
        self.state.update(current=previous, previous=old)
        # Retain highest sequence: an old channel cannot erase a revocation.
        self.record(); self.audit('operator rollback', previous)
        (self.state_dir / 'transaction.json').unlink()

def main():
    if os.geteuid() != 0: raise Refused('trusted host administrator required')
    if len(sys.argv) != 2 or sys.argv[1] not in ['check', 'status', 'rollback']:
        raise Refused('fixed operation required')
    # Rollback and status have no model-facing sudoers entry.
    protected(ROOT / 'bootstrap' / 'release-manager.py')
    lock = ROOT / 'state' / 'update.lock'
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        m = Manager()
        if sys.argv[1] == 'check': result = m.check()
        elif sys.argv[1] == 'rollback': m.rollback(); result = 'rolled-back'
        else: result = m.state
        current_manifest = decode(m.release(m.state['current']).joinpath('manifest.json').read_bytes())
        print(json.dumps({'status': result, 'release': current_manifest['release'], 'source': current_manifest['source_manifest_sha256']}))

if __name__ == '__main__':
    try: main()
    except (Refused, Offline, OSError, ValueError, subprocess.SubprocessError):
        print('keybroker-health: protected release check failed', file=sys.stderr)
        sys.exit(1)
