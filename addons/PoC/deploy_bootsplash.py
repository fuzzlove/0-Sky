#!/usr/bin/env python3
"""Converge the read-only splash endpoint on selected configured SRDs."""
import argparse
import hashlib
import json
import shlex

from repair_device_connection import HERE, profiles, worker_namespace
from update_device_bridge import update as update_bridge

MODULE = HERE.parents[1] / "bridge/DeviceRuntime/zero_sky_core/bootsplash.py"

REMOTE = r'''import ast,hashlib,json,os,pathlib,sys,tempfile
target=pathlib.Path('/var/jb/usr/local/libexec/zero_sky_core/bootsplash.py')
if not target.parent.is_dir() or target.is_symlink():raise SystemExit('Invalid Core package path')
payload=sys.stdin.buffer.read()
if hashlib.sha256(payload).hexdigest()!=sys.argv[1]:raise SystemExit('Source hash mismatch')
ast.parse(payload.decode(),filename=str(target))
before=target.read_bytes() if target.exists() else None
if before==payload:
 print(json.dumps({'changed':False,'sha256':sys.argv[1]}));raise SystemExit(0)
backup=target.with_name('bootsplash.py.0sky-backup')
if before is not None and not backup.exists():
 with backup.open('xb') as stream:stream.write(before)
 os.chmod(backup,0o600)
fd,temporary=tempfile.mkstemp(prefix='.bootsplash-',dir=target.parent)
try:
 with os.fdopen(fd,'wb') as stream:stream.write(payload);stream.flush();os.fsync(stream.fileno())
 os.chmod(temporary,0o644);os.chown(temporary,0,0)
 os.replace(temporary,target)
except BaseException:
 if os.path.exists(temporary):os.unlink(temporary)
 raise
print(json.dumps({'changed':True,'sha256':sys.argv[1]}))'''

CHECK = r'''import http.client,json,pathlib
token=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
conn=http.client.HTTPConnection('127.0.0.1',48654,timeout=7)
conn.request('GET','/v1/bootsplash/status',headers={'X-TrollStore-Bridge-Token':token})
response=conn.getresponse();value=json.loads(response.read(65536));conn.close()
print(json.dumps({'http_status':response.status,'root':value.get('root_status'),
 'uid':value.get('uid'),'euid':value.get('euid'),
 'bootstrap':value.get('bootstrap_status'),'bootstrap_reasons':value.get('bootstrap_reasons'),
 'trust':value.get('trusted_host_status'),'ssh':value.get('ssh_status'),
 'runtime':value.get('runtime_status'),'control':value.get('control_status'),
 'device_mode':value.get('device_mode'),'duration_ms':value.get('duration_ms'),
 'diagnostics':value.get('diagnostics')}))'''


def deploy(udid: str) -> dict:
    _, profile = profiles()[udid]
    namespace = worker_namespace(profile)
    payload = MODULE.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    remote = namespace['ssh']('/var/jb/usr/bin/python3 -c ' + shlex.quote(REMOTE) +
                              ' ' + digest, input_data=payload, timeout=30)
    module = json.loads(remote.stdout)
    bridge = update_bridge(namespace)
    result = namespace['ssh']('/var/jb/usr/bin/python3 -c ' + shlex.quote(CHECK), timeout=20)
    status = json.loads(result.stdout)
    if status['http_status'] != 200:
        raise RuntimeError('Splash endpoint health failed')
    return {'device': udid, 'module': module, 'bridge': bridge, 'snapshot': status}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    device = parser.add_mutually_exclusive_group(required=True)
    device.add_argument('--udid')
    device.add_argument('--all', action='store_true')
    args = parser.parse_args()
    devices = list(profiles()) if args.all else [args.udid]
    failed = False
    for udid in devices:
        try:
            print(json.dumps(deploy(udid), indent=2))
        except Exception as exc:
            failed = True
            print(json.dumps({'device': udid, 'error': type(exc).__name__ + ': ' + str(exc)[:500]}))
    raise SystemExit(1 if failed else 0)
