#!/usr/bin/env python3
"""Dry-run first. Installs a distinct health service; preserves all existing brokers."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import shlex
import subprocess
import sys
import time
import plistlib

# Filled into the immutable bootstrap copy by build.py after preparation.
BOOTSTRAP_SHA256 = 'UNPREPARED'
ROOT = Path('/opt/keybroker-health')
LIBEXEC = Path('/usr/local/libexec/keybroker-health-maintain')
CLI = Path('/usr/local/bin/keybroker-health')
MCP = Path('/usr/local/bin/keybroker-health-mcp')
ACTIVE_UNIT = None
START_ATTEMPTED = False

def stop_failed_install():
    # Fixed new-service labels only. Retain every file and receipt for review.
    if os.geteuid()!=0 or ACTIVE_UNIT is None:return
    stop={'attempted':False,'outcome':'not attempted'}
    if START_ATTEMPTED:
        command=(['/usr/bin/systemctl','disable','--now','keybroker-health.service'] if platform.system()=='Linux'
                 else ['/bin/launchctl','bootout','system/com.keybroker.health'])
        stop={'attempted':True,'outcome':'unknown'}
        try:
            result=subprocess.run(command,capture_output=True,timeout=20)
            stop.update(outcome='command succeeded' if result.returncode==0 else 'command failed',exit_code=result.returncode)
        except subprocess.TimeoutExpired:stop['outcome']='timed out'
        except OSError:stop['outcome']='execution failed'
    p=ROOT/'state/installation-failed.json'
    if not p.exists():write_new(p,json.dumps({'state':'failed; files retained; service state requires inspection',
                                            'stop':stop,'unit':str(ACTIVE_UNIT),
                                            'requires':'operator reconciliation; no automatic replay'}).encode(),0o600)

def fail(s): raise SystemExit('keybroker-health installer: '+s)

def h(b):return hashlib.sha256(b).hexdigest()

def load_bundle(bundle, expected=BOOTSTRAP_SHA256):
    raw=(bundle/'bootstrap.json').read_bytes()
    if h(raw)!=expected:fail('bootstrap metadata mismatch')
    boot=json.loads(raw)
    if boot['schema']!=1:fail('bootstrap schema')
    verified={}
    for name, wanted in boot['files'].items():
        if '/' in name or '..' in name:fail('bootstrap file name')
        f=bundle/name
        if f.is_symlink() or not f.is_file():fail('bootstrap file mismatch')
        data=f.read_bytes()
        if h(data)!=wanted:fail('bootstrap file mismatch')
        verified[name]=data
    return boot,verified

def write_new(path, data, mode):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())

def stage_and_validate_release(verified,sha,manifest_raw,plat,unit,unit_bytes,goos):
    # systemd verifies ExecStart/ExecStartPost exist. Stage authenticated bytes
    # before validation, and validate before grants, public wrappers or activation.
    write_new(ROOT/'bootstrap/release-manager.py',verified['release-manager.py'],0o555)
    verifier=verified['release-verify-'+plat]
    write_new(ROOT/'bootstrap/release-verify',verifier,0o555)
    r=ROOT/'releases'/sha;r.mkdir(mode=0o755)
    write_new(r/'manifest.json',manifest_raw,0o444)
    for role in ['keybroker','keybroker-mcp']:
        write_new(r/role,verified[role+'-'+plat],0o555)
    os.symlink('releases/'+sha,ROOT/'current')
    staged_unit=ROOT/'bootstrap'/unit.name;write_new(staged_unit,unit_bytes,0o644)
    validator=['/usr/bin/systemd-analyze','verify'] if goos=='linux' else ['/usr/bin/plutil','-lint']
    subprocess.run(validator+[str(staged_unit)],check=True,capture_output=True)
    return verifier

def wrapper(binary,socket,user,root_client=False):
    # Shell interprets only operator-generated paths. No provider operation.
    command=shlex.quote(str(ROOT/'current'/binary))
    if root_client:
        command='/usr/sbin/runuser -u '+shlex.quote(user)+' -- /usr/bin/env KEYBROKER_SOCKET='+shlex.quote(socket)+' '+command
    else:
        command='/usr/bin/env KEYBROKER_SOCKET='+shlex.quote(socket)+' '+command
    return ('#!/bin/sh\n/usr/bin/sudo -n '+str(LIBEXEC)+' check >/dev/null || exit 1\nexec '+command+' "$@"\n').encode()

def service(user):
    return ('''[Unit]
Description=Keybroker approved health-only base
After=local-fs.target
[Service]
Type=simple
User=%s
ExecStart=/opt/keybroker-health/current/keybroker serve
ExecStartPost=/opt/keybroker-health/current/keybroker wait
Environment=KEYBROKER_SOCKET=/run/keybroker-health/keybroker.sock
Environment=KEYBROKER_AUDIT_LOG=/var/lib/keybroker-health/audit.jsonl
RuntimeDirectory=keybroker-health
RuntimeDirectoryMode=0700
StateDirectory=keybroker-health
StateDirectoryMode=0700
UMask=0077
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
ReadWritePaths=/run/keybroker-health /var/lib/keybroker-health
[Install]
WantedBy=multi-user.target
'''%user).encode()

def main():
    global ACTIVE_UNIT,START_ATTEMPTED
    ap=argparse.ArgumentParser()
    ap.add_argument('--owner',required=True,help='existing unprivileged runtime account')
    ap.add_argument('--apply',action='store_true')
    args=ap.parse_args()
    bundle=Path(__file__).resolve().parent;boot,verified=load_bundle(bundle)
    who=pwd.getpwnam(args.owner)
    if who.pw_uid==0 or not __import__('re').fullmatch('[a-z_][a-z0-9_-]{0,31}',args.owner):fail('unprivileged account required')
    goos={'Linux':'linux','Darwin':'darwin'}.get(platform.system())
    arch={'x86_64':'amd64','arm64':'arm64','aarch64':'arm64'}.get(platform.machine())
    plat=str(goos)+'-'+str(arch)
    if plat not in boot['platforms']:fail('unsupported host platform')
    manifest_raw=verified['manifest.json'];release=json.loads(manifest_raw);sha=h(manifest_raw)
    if release['expires_at']<=int(time.time()):fail('approved metadata expired; refresh and review required')
    manager_path=ROOT/'bootstrap/release-manager.py'
    if goos=='linux':
        unit=Path('/etc/systemd/system/keybroker-health.service');socket='/run/keybroker-health/keybroker.sock'
    else:
        unit=Path('/Library/LaunchDaemons/com.keybroker.health.plist')
        socket=str(Path(who.pw_dir)/'Library/Application Support/KeybrokerHealth/keybroker.sock')
    paths=[ROOT,LIBEXEC,CLI,MCP,unit,Path('/etc/sudoers.d/keybroker-health')]
    if goos=='darwin':paths.extend([Path(who.pw_dir)/'Library/Application Support/KeybrokerHealth',Path(who.pw_dir)/'Library/Logs/KeybrokerHealth'])
    for p in paths:
        if p.exists() or p.is_symlink():fail('existing managed target requires inspection: '+str(p))
    plan={'state':'prepared','owner':args.owner,'uid':who.pw_uid,'platform':plat,'release':release['release'],
          'manifest_sha256':sha,'targets':[str(p) for p in paths], 'capabilities':['system.status'],
          'existing_keybroker_and_bunny':'preserved','auto_updates':'only approved manifest hashes; signing trust not enrolled'}
    if not args.apply:print(json.dumps(plan,indent=2));return
    if os.geteuid()!=0:fail('--apply requires trusted host administrator')
    # All existing parent paths must be protected. No existing service is replaced.
    for p in paths[:6]:
        ancestor=p.parent
        while not ancestor.exists():ancestor=ancestor.parent
        for q in [*reversed(ancestor.parents),ancestor]:
            st=q.lstat()
            if q.is_symlink() or st.st_uid!=0 or st.st_mode&0o022:fail('unprotected parent: '+str(q))
    ROOT.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    ROOT.mkdir(mode=0o755);(ROOT/'bootstrap').mkdir(mode=0o755);(ROOT/'state').mkdir(mode=0o700);(ROOT/'releases').mkdir(mode=0o755)
    ACTIVE_UNIT=unit
    write_new(ROOT/'state/installation.json',json.dumps({'state':'installation in progress; health unverified','targets':[str(p) for p in paths]}).encode(),0o600)
    sudoers=(args.owner+' ALL=(root) NOPASSWD: '+str(LIBEXEC)+' check\n').encode()
    staged=ROOT/'bootstrap/sudoers';write_new(staged,sudoers,0o440)
    subprocess.run(['/usr/sbin/visudo','-cf',str(staged)],check=True,capture_output=True)
    if goos=='linux':unit_bytes=service(args.owner)
    else:
        logs=Path(who.pw_dir)/'Library/Logs/KeybrokerHealth'
        unit_bytes=plistlib.dumps({'Label':'com.keybroker.health','UserName':args.owner,'ProgramArguments':[str(ROOT/'current/keybroker'),'serve'],
                 'EnvironmentVariables':{'KEYBROKER_SOCKET':socket,'KEYBROKER_AUDIT_LOG':str(logs/'audit.jsonl')},
                 'RunAtLoad':True,'KeepAlive':True,'Umask':63,'ThrottleInterval':5,
                 'StandardOutPath':str(logs/'service.log'),'StandardErrorPath':str(logs/'service-error.log')})
    verifier=stage_and_validate_release(verified,sha,manifest_raw,plat,unit,unit_bytes,goos)
    LIBEXEC.parent.mkdir(mode=0o755,parents=True,exist_ok=True);CLI.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    policy={'schema':1,'owner_uid':who.pw_uid,'owner_user':args.owner,'platform':plat,'approved_manifest_sha256':[sha],
            'release_public_key_hex':'','verifier_sha256':h(verifier),'offline_grace_seconds':86400,'enabled':True}
    installed={'schema':1,'current':sha,'previous':None,'sequence':release['sequence'],'metadata_sha256':sha,
               'last_verified_at':1,'expires_at':release['expires_at'],'revoked':[], 'failed':[]}
    write_new(ROOT/'policy.json',json.dumps(policy).encode(),0o644)
    write_new(ROOT/'state/installed.json',json.dumps(installed).encode(),0o600)
    write_new(LIBEXEC,('#!/bin/sh\nexec /usr/bin/python3 -I '+str(manager_path)+' "$@"\n').encode(),0o555)
    write_new(CLI,wrapper('keybroker',socket,args.owner),0o555);write_new(MCP,wrapper('keybroker-mcp',socket,args.owner),0o555)
    write_new(Path('/etc/sudoers.d/keybroker-health'),sudoers,0o440)
    if goos=='linux':
        write_new(unit,unit_bytes,0o644)
        subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True)
        START_ATTEMPTED=True
        subprocess.run(['/usr/bin/systemctl','enable','--now','keybroker-health.service'],check=True)
    else:
        logs=Path(who.pw_dir)/'Library/Logs/KeybrokerHealth';runtime=Path(who.pw_dir)/'Library/Application Support/KeybrokerHealth'
        for p in [logs,runtime]:p.mkdir(mode=0o700);os.chown(p,who.pw_uid,who.pw_gid)
        write_new(unit,unit_bytes,0o644)
        START_ATTEMPTED=True
        subprocess.run(['/bin/launchctl','bootstrap','system',str(unit)],check=True)
    spec=importlib.util.spec_from_file_location('installed_manager',manager_path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    manager=module.Manager();manager.probe(sha);manager.audit('initial health installation verified',sha)
    manager.state['last_verified_at']=int(time.time());manager.record()
    module.save(ROOT/'state/installation.json',{'state':'installed and health verified','targets':[str(p) for p in paths]})
    print(json.dumps(dict(plan,state='installed and health verified')))

if __name__=='__main__':
    try:main()
    except BaseException:
        try:stop_failed_install()
        except Exception:pass
        raise
