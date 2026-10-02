#!/usr/bin/env python3
"""Enroll reviewed public APT sources on one exact paired SRD, then mirror to Sileo."""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import shlex

from repair_device_connection import profiles, usb_identity, worker_namespace


RESOURCE_ROOT = Path(__file__).resolve().parents[2] / "bridge/DeviceRuntime/zero_sky_core"
MANIFEST = RESOURCE_ROOT / "apt_source_manifest.json"
DEVICE = r'''import base64,hashlib,json,os,pathlib,stat,subprocess,sys,tempfile
request=json.load(sys.stdin)
if not isinstance(request,dict) or set(request)!=set(('sources','identity')):raise SystemExit('invalid enrollment request')
items=request['sources'];identity=request['identity']
if not isinstance(items,list) or not 1<=len(items)<=2:raise SystemExit('invalid source count')
if not isinstance(identity,dict) or set(identity)!=set(('udid','model')):raise SystemExit('invalid device identity')
source_root=pathlib.Path('/var/jb/etc/apt/sources.list.d')
key_root=pathlib.Path('/var/jb/etc/apt/keyrings')
if source_root.is_symlink() or source_root.stat().st_uid!=0:raise SystemExit('source directory ownership invalid')
if key_root.is_symlink():raise SystemExit('key directory is symbolic')
key_root.mkdir(mode=0o755,exist_ok=True)
if key_root.stat().st_uid!=0 or key_root.stat().st_mode & 0o022:raise SystemExit('key directory ownership invalid')
created=[];legacy=[];moved=[]
def install(path,data):
 if path.is_symlink():raise RuntimeError('target is symbolic')
 if path.exists():
  if not path.is_file() or path.stat().st_uid!=0 or path.read_bytes()!=data:raise RuntimeError('existing source differs')
  return 'EXISTING_VERIFIED'
 fd,name=tempfile.mkstemp(prefix='.0sky-source-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
  os.chown(name,0,0);os.chmod(name,0o644);os.replace(name,path)
  created.append(path)
 finally:
  if os.path.exists(name):os.unlink(name)
 return 'ADDED'
try:
 for item in items:
  identifier=item['id']
  if identifier not in ('chariz','havoc'):raise RuntimeError('source is not reviewed')
  expected={'chariz':('https://repo.chariz.com/','3D32F8ECD0930A1BC4F2A4A817C6BB3FC4114BDF'),'havoc':('https://havoc.app/','C101A4205F8616491D9B23BAB4532449E1E8AA68')}
  uri,fingerprint=expected[identifier]
  if item['uri']!=uri or item['fingerprint']!=fingerprint:raise RuntimeError('source provenance mismatch')
  key=base64.b64decode(item['key'],validate=True)
  if len(key)>10000 or hashlib.sha256(key).hexdigest()!=item['key_sha256']:raise RuntimeError('public key hash mismatch')
  key_path=key_root/('0sky-'+identifier+'.gpg')
  source_path=source_root/('0sky-'+identifier+'.sources')
  for other in source_root.glob('*.sources'):
   if other==source_path or other.is_symlink():continue
   text=other.read_text(errors='replace')
   if uri not in text:continue
   old_key=pathlib.Path('/var/jb/etc/apt/trusted.gpg.d')/(identifier+'.gpg')
   old_stanza=('Types: deb\nURIs: '+uri+'\nSuites: ./\nSigned-By: '+str(old_key)+'\n')
   if (other.name=='sileo.sources' and text==old_stanza and old_key.is_file()
       and not old_key.is_symlink() and old_key.stat().st_uid==0
       and not old_key.stat().st_mode & 0o022
       and hashlib.sha256(old_key.read_bytes()).hexdigest()==item['key_sha256']):
    legacy.append((other,old_key));continue
   raise RuntimeError('source is already configured outside the reviewed profile')
  install(key_path,key)
  stanza=('Types: deb\nURIs: '+uri+'\nSuites: ./\nArchitectures: iphoneos-arm64\nSigned-By: '+str(key_path)+'\n').encode()
  install(source_path,stanza)
 for old_source,old_key in legacy:
  backup=old_source.with_name('.'+old_source.name+'.0sky-migrate')
  if backup.exists() or backup.is_symlink():raise RuntimeError('legacy source migration target exists')
  os.replace(old_source,backup);moved.append((old_source,old_key,backup))
 update=subprocess.run(['/var/jb/usr/bin/apt-get','update','-o','APT::Get::AllowUnauthenticated=false','-o','Acquire::AllowInsecureRepositories=false','-o','Dpkg::Use-Pty=0'],cwd='/var/jb/var/tmp',stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=420,check=False)
 if update.returncode:raise RuntimeError('signed APT source refresh failed: '+update.stderr.decode(errors='replace')[-250:])
 evidence=[]
 for item in items:
  identifier=item['id'];host='repo.chariz.com' if identifier=='chariz' else 'havoc.app'
  key_path=key_root/('0sky-'+identifier+'.gpg')
  base=pathlib.Path('/var/jb/var/lib/apt/lists')/(host+'_._Release')
  signature=base.with_name(base.name+'.gpg')
  checked=subprocess.run(['/var/jb/usr/bin/gpgv','--status-fd','1','--keyring',str(key_path),str(signature),str(base)],cwd='/var/jb/var/tmp',stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
  if checked.returncode or ('[GNUPG:] VALIDSIG '+item['fingerprint']) not in checked.stdout.decode(errors='replace'):
   raise RuntimeError(identifier+' Release signature verification failed')
  evidence.append({'source':identifier,'signature':'PASS','fingerprint':item['fingerprint']})
 mirror=subprocess.run(['/var/jb/usr/bin/python3','/var/jb/usr/local/libexec/trollstorelite-srd-bridge.py','--provision-sileo-bridge'],cwd='/var/jb/var/tmp',input=json.dumps(identity,separators=(',',':')).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
 if mirror.returncode or json.loads(mirror.stdout).get('result')!='SILEO_BRIDGE_CREDENTIAL_PROVISIONED':
  raise RuntimeError('Sileo source mirror failed')
 for old_source,old_key,backup in moved:
  backup.unlink()
 print(json.dumps({'result':'SIGNED_SOURCES_ENROLLED','sources':evidence,'sileo_mirror':'PASS','legacy_sources_migrated':len(legacy)}))
except Exception as error:
 for old_source,old_key,backup in reversed(moved):
  if backup.exists() and not old_source.exists():os.replace(backup,old_source)
 for path in reversed(created):
  try:path.unlink()
  except OSError:pass
 print(json.dumps({'result':'ROLLBACK','error':str(error)[:350],'removed_new_files':len(created)}))
 raise SystemExit(1)
'''


def run(instance: str, udid: str, source_ids: list[str]) -> dict:
    selected = profiles(instance_name=instance)
    device = asyncio.run(usb_identity(udid))
    if udid not in selected or device["udid"] != udid:
        raise RuntimeError("EXACT_USB_PROFILE_MISMATCH")
    manifest = json.loads(MANIFEST.read_text())
    available = {item["id"]: item for item in manifest["sources"]}
    if len(set(source_ids)) != len(source_ids) or not source_ids:
        raise ValueError("sources must be unique and nonempty")
    payload = []
    for identifier in source_ids:
        item = available[identifier]
        key_path = RESOURCE_ROOT / item["key_file"]
        data = key_path.read_bytes()
        if key_path.is_symlink() or hashlib.sha256(data).hexdigest() != item["key_sha256"]:
            raise RuntimeError("REVIEWED_SOURCE_KEY_MISMATCH")
        payload.append({"id": identifier, "uri": item["uri"],
                        "fingerprint": item["signing_fingerprint"],
                        "key_sha256": item["key_sha256"],
                        "key": base64.b64encode(data).decode("ascii")})
    worker = worker_namespace(selected[udid][1])
    request = {"sources": payload,
               "identity": {"udid": udid, "model": device["product"]}}
    response = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(DEVICE),
                             input_data=json.dumps(request).encode(), timeout=500,
                             check=False)
    report = json.loads(response.stdout)
    report["device"] = udid[-8:]
    if response.returncode or report.get("result") != "SIGNED_SOURCES_ENROLLED":
        raise RuntimeError("SOURCE_ENROLLMENT_FAILED: " + json.dumps(report))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instance")
    parser.add_argument("udid")
    parser.add_argument("sources", nargs="+", choices=("chariz", "havoc"))
    args = parser.parse_args()
    print(json.dumps(run(args.instance, args.udid, args.sources), indent=2, sort_keys=True))
