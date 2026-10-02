#!/usr/bin/env python3
"""Bounded allowlisted GUI launch check on one exact paired research iPhone."""
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

ALLOWED_BUNDLE_IDS = frozenset({'com.amywhile.sileo', 'com.tigisoftware.Filza',
                                'com.liquidsky.TrollDecryptResearch'})

REMOTE = r'''import hashlib,json,pathlib,plistlib,subprocess,sys,time
identity=sys.argv[1]
if identity not in ('com.amywhile.sileo','com.tigisoftware.Filza',
                    'com.liquidsky.TrollDecryptResearch'):
 raise RuntimeError('application is outside reviewed test allowlist')
listing=subprocess.run(['/var/jb/usr/bin/uicache','-l'],capture_output=True,text=True,timeout=20)
if listing.returncode:raise RuntimeError('LaunchServices inventory unavailable')
prefix=identity+' : '
paths=[line[len(prefix):].strip() for line in listing.stdout.splitlines() if line.startswith(prefix)]
if len(paths)!=1:raise RuntimeError('application registration is absent or ambiguous')
app=pathlib.Path(paths[0])
if app.is_symlink() or not app.is_dir():raise RuntimeError('application registration path unsafe')
resolved=str(app.resolve())
if not resolved.startswith(('/private/var/containers/Bundle/Application/',
                            '/private/var/run/com.apple.security.cryptexd/mnt/')):
 raise RuntimeError('application registration outside reviewed roots')
info=plistlib.loads((app/'Info.plist').read_bytes())
name=info.get('CFBundleExecutable')
if info.get('CFBundleIdentifier')!=identity or not isinstance(name,str) or '/' in name:
 raise RuntimeError('application bundle identity invalid')
exe=app/name
if not exe.is_file() or exe.is_symlink():raise RuntimeError('application executable unavailable')
expected=str(exe)
expected_paths={expected}
if expected.startswith('/private/var/'):expected_paths.add(expected[len('/private'):])
before=int(time.time())
opened=subprocess.run(['/var/jb/usr/bin/uiopen','--bundleid',identity],
                      capture_output=True,timeout=30)
if opened.returncode:raise RuntimeError('uiopen rejected application launch')
deadline=time.monotonic()+10
appeared=False
samples=0
while time.monotonic()<deadline:
 probe=subprocess.run(['ps','-axo','command='],capture_output=True,text=True,timeout=10)
 if probe.returncode:raise RuntimeError('process inventory unavailable')
 running=any(line.strip().split(None,1)[0] in expected_paths
             for line in probe.stdout.splitlines() if line.strip())
 if running:appeared=True
 elif appeared:raise RuntimeError('application exited during launch check')
 samples+=1
 time.sleep(.5)
if not appeared:raise RuntimeError('application did not reach a running state')
print(json.dumps({'bundle_id':identity,'version':info.get('CFBundleShortVersionString'),
 'build':info.get('CFBundleVersion'),'executable_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
 'process_appeared':appeared,'process_alive_after_seconds':10,
 'process_samples':samples,'launched_at':before,'result':'PASS'}))
'''


def run(udid: str, instance_name: str, bundle_id: str) -> dict:
    if bundle_id not in ALLOWED_BUNDLE_IDS:
        raise ValueError('application is outside reviewed test allowlist')
    identity = asyncio.run(usb_identity(udid))
    path, _ = profiles(instance_name=instance_name)[udid]
    namespace = worker_namespace(plistlib.loads(path.read_bytes()))
    result = namespace['ssh']('/var/jb/usr/bin/python3 -c ' + shlex.quote(REMOTE) +
                              ' ' + shlex.quote(bundle_id),
                              timeout=80, check=False)
    if result.returncode:
        lines = result.stderr.decode('utf-8', 'replace').splitlines()
        reason = lines[-1][:200] if lines else 'REMOTE_CHECK_FAILED'
        return {'result': 'FAIL', 'reason': reason,
                'device_model': identity['product'], 'ios_build': identity['build'],
                'device_reference': hashlib.sha256(udid.encode()).hexdigest()[:16]}
    evidence = json.loads(result.stdout)
    return {'result': evidence['result'], 'evidence': evidence,
            'device_model': identity['product'], 'ios_build': identity['build'],
            'device_reference': hashlib.sha256(udid.encode()).hexdigest()[:16]}


def main() -> int:
    ensure_device_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--instance-name', required=True)
    parser.add_argument('--bundle-id', required=True, choices=sorted(ALLOWED_BUNDLE_IDS))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = run(args.udid, args.instance_name, args.bundle_id)
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write(args.output, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())
    print(json.dumps({'bundle_id': args.bundle_id,
                      'device_model': value['device_model'], 'ios_build': value['ios_build'],
                      'result': value['result'],
                      'reason': value.get('reason', '')[-250:]}, sort_keys=True))
    return 0 if value['result'] == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
