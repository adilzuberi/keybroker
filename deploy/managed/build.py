#!/usr/bin/env python3
"""Offline candidate builder. Explicit staging source; never builds the dirty companion tree."""
import base64
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import time

HERE=Path(__file__).resolve().parent
PROJECT=HERE.parents[1]
SOURCE=PROJECT
OUT=PROJECT/'release-preparation'
GO=Path(os.environ.get('KEYBROKER_GO') or shutil.which('go') or '/Volumes/ai-vaults/Code/keybroker-recovery-20261001/go/bin/go')
BASE=subprocess.check_output(['git','rev-parse','HEAD'],cwd=PROJECT,text=True).strip()
RELEASE='v0.1.0-health.5'

def h(b):return hashlib.sha256(b).hexdigest()
def raw(d):return json.dumps(d,sort_keys=True,separators=(',',':')).encode()+b'\n'

def main():
    inputs=json.loads((HERE/'source-files.json').read_bytes())
    if inputs['schema']!=1 or not isinstance(inputs['files'],list) or len(set(inputs['files']))!=len(inputs['files']):raise SystemExit('Invalid source file list')
    files={}
    for name in inputs['files']:
        if not isinstance(name,str) or Path(name).is_absolute() or '..' in Path(name).parts or any(x in name.lower() for x in ['bunny','private','no-ai','secrets','grant','receipt']):raise SystemExit('Excluded release input')
        p=SOURCE/name
        if p.is_symlink() or not p.is_file():raise SystemExit('Invalid source input')
        files[name]=h(p.read_bytes())
    tracked=subprocess.run(['git','ls-files','--error-unmatch','--',*files],cwd=PROJECT,capture_output=True).returncode==0
    unchanged=subprocess.run(['git','diff','--quiet','HEAD','--',*files],cwd=PROJECT).returncode==0
    source_state='committed source' if tracked and unchanged else 'uncommitted isolated candidate'
    source_raw=raw({'base_commit':BASE,'status':source_state,'files':files})
    source_id=h(source_raw)
    out=OUT/(RELEASE+'-'+source_id[:12])
    if out.exists():raise SystemExit('Bundle exists; preserve it')
    out.mkdir(mode=0o700,parents=True)
    (out/'source-manifest.json').write_bytes(source_raw)
    env=dict(os.environ,GOCACHE=str(PROJECT/'.build-cache'),GOPROXY='off',GOTOOLCHAIN='local',CGO_ENABLED='0')
    subprocess.run([str(GO),'vet','./...'],cwd=SOURCE,env=env,check=True)
    artefacts={};platforms=['darwin-arm64','linux-amd64','linux-arm64']
    for plat in platforms:
        goos,arch=plat.split('-');e=dict(env,GOOS=goos,GOARCH=arch)
        artefacts[plat]={}
        for role,package in [('keybroker','keybroker'),('keybroker-mcp','keybroker-mcp'),('release-verify','keybroker-release-verify')]:
            output=out/(role+'-'+plat)
            flags='-s -w -X github.com/adilzuberi/keybroker.ReleaseID='+RELEASE+' -X github.com/adilzuberi/keybroker.SourceID='+source_id
            if role=='keybroker-mcp':flags+=' -X github.com/adilzuberi/keybroker.ManagedMCP=1'
            subprocess.run([str(GO),'build','-trimpath','-ldflags',flags,'-o',str(output),'./cmd/'+package],cwd=SOURCE,env=e,check=True)
            output.chmod(0o700)
            if role!='release-verify':artefacts[plat][role]={'sha256':h(output.read_bytes()),'size':output.stat().st_size}
    now=int(time.time())
    manifest={'schema':1,'sequence':5,'release':RELEASE,'source_commit':BASE,'source_manifest_sha256':source_id,
              'state_schema':1,'capabilities':['system.status'],'issued_at':now,'expires_at':now+7*86400,'revoked':[],
              'artefacts':artefacts}
    b=raw(manifest);(out/'manifest.json').write_bytes(b)
    (out/'channel.json').write_bytes(raw({'payload':base64.b64encode(b).decode(),'signature':''}))
    (out/'release-manager.py').write_bytes((HERE/'release-manager.py').read_bytes())
    payload_files={p.name:h(p.read_bytes()) for p in sorted(out.iterdir()) if p.is_file()}
    bootstrap=raw({'schema':1,'release':RELEASE,'platforms':platforms,'files':payload_files})
    (out/'bootstrap.json').write_bytes(bootstrap)
    installer=(HERE/'install.py').read_text().replace("BOOTSTRAP_SHA256 = 'UNPREPARED'","BOOTSTRAP_SHA256 = '"+h(bootstrap)+"'")
    (out/'install.py').write_text(installer);(out/'install.py').chmod(0o700)
    receipt={'state':'prepared and cross-built; unpublished and not installed','base_commit':BASE,
             'source_manifest_sha256':source_id,'source_state':source_state,'release':RELEASE,'manifest_sha256':h(b),'bootstrap_sha256':h(bootstrap),
             'installer_sha256':h(installer.encode()),'go_version':subprocess.check_output([str(GO),'version'],text=True).strip(),
             'platforms':platforms,'signing_key_enrolled':False,'channel':'reviewed hash only; signature absent',
             'no_bunny_credentials_grants_or_host_pins':True,'issued_at':now,'expires_at':manifest['expires_at']}
    (out/'preparation-receipt.json').write_bytes(raw(receipt));print(json.dumps(dict(receipt,bundle=str(out)),indent=2))

if __name__=='__main__':main()
