#!/usr/bin/env python3
"""Read-only Sileo source, folder, and authenticated APT-plan UAT."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import plistlib
import shlex
import time

from device_python import ensure_device_python
from repair_device_connection import atomic_write, profiles, usb_identity, worker_namespace


REMOTE = r'''import hashlib,http.client,json,pathlib,stat,subprocess,sys
sys.path.insert(0,'/var/jb/usr/local/libexec')
from zero_sky_core.sileo_package_service import _container
container=_container()
documents=container/'Documents'
source=documents/'sileo.sources'
def permissions(path):
 if path.is_symlink() or not path.exists():return {'state':'UNAVAILABLE'}
 value=path.stat()
 return {'state':'DIRECTORY' if path.is_dir() else 'FILE','uid':value.st_uid,
         'gid':value.st_gid,'mode':oct(stat.S_IMODE(value.st_mode))}
paths={'container':container,'documents':documents,'sources':source,
 'sileo_lists':documents/'lists','apt_lists':pathlib.Path('/var/jb/var/lib/apt/lists'),
 'apt_partial':pathlib.Path('/var/jb/var/lib/apt/lists/partial'),
 'apt_archives':pathlib.Path('/var/jb/var/cache/apt/archives'),
 'archives_partial':pathlib.Path('/var/jb/var/cache/apt/archives/partial')}
folders={name:permissions(path) for name,path in paths.items()}
if not source.is_file() or source.is_symlink():raise RuntimeError('Sileo source file unavailable')
before=source.read_bytes()
version=subprocess.run(['/var/jb/usr/bin/dpkg-query','-W','-f=${Version}','dpkg'],
 capture_output=True,text=True,timeout=10)
if version.returncode:raise RuntimeError('dpkg version unavailable')
with open('/var/jb/etc/0sky-sileo-bridge.token',encoding='ascii') as stream:
 token=stream.read().strip()
request={'operation':'plan','packages':[{'id':'dpkg','version':version.stdout.strip()}]}
connection=http.client.HTTPConnection('127.0.0.1',48654,timeout=90)
try:
 connection.request('POST','/v1/sileo/package',json.dumps(request),
  {'Content-Type':'application/json','X-0Sky-Sileo-Token':token})
 response=connection.getresponse();body=json.loads(response.read(131072))
 plan={'http_status':response.status,'status':body.get('status'),
       'result':body.get('result'),'stage':body.get('stage')}
finally:connection.close()
after=source.read_bytes()
owner=folders['container'].get('uid')
ownership=(owner not in (None,0) and
 all(folders[name].get('uid')==owner for name in ('documents','sources','sileo_lists')) and
 all(folders[name].get('uid')==0 for name in ('apt_lists','apt_archives')) and
 all(folders[name].get('uid')==1001 for name in ('apt_partial','archives_partial')))
passed=ownership and before==after and plan=={'http_status':200,'status':0,
                                               'result':'PLAN_READY','stage':None}
print(json.dumps({'result':'PASS' if passed else 'FAIL','folders':folders,
 'sources':{'sha256':hashlib.sha256(after).hexdigest(),
            'source_stanzas':after.lower().count(b'uris:'),'unchanged_during_plan':before==after},
 'plan':plan,'scope':'source file and simulated installed dpkg package plan; no package mutation'}))
'''


def run(udid: str, instance_name: str) -> dict:
    identity = asyncio.run(usb_identity(udid))
    path, _ = profiles(instance_name=instance_name)[udid]
    namespace = worker_namespace(plistlib.loads(path.read_bytes()))
    response = namespace['ssh']('/var/jb/usr/bin/python3 -c ' + shlex.quote(REMOTE),
                                timeout=120, check=False)
    if response.returncode:
        lines = response.stderr.decode('utf-8', 'replace').splitlines()
        evidence = {'result': 'FAIL', 'reason': lines[-1][:200] if lines else 'REMOTE_CHECK_FAILED'}
    else:
        evidence = json.loads(response.stdout)
    return {'device_model': identity['product'], 'ios_build': identity['build'],
            'device_reference': hashlib.sha256(udid.encode()).hexdigest()[:16],
            'timestamp': int(time.time()), 'evidence': evidence}


def main() -> int:
    ensure_device_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--instance-name', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = run(args.udid, args.instance_name)
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write(args.output, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())
    evidence = value['evidence']
    print(json.dumps({'device_model': value['device_model'],
                      'result': evidence['result'],
                      'source_stanzas': evidence.get('sources', {}).get('source_stanzas'),
                      'plan': evidence.get('plan', {}).get('result')}, sort_keys=True))
    return 0 if evidence['result'] == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
