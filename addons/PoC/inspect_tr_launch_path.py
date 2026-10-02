"""Inspect TrollRecorder's launch prerequisites on the selected SRD."""
import argparse
import asyncio
import json
import shlex

from device_python import ensure_device_python
from repair_device_connection import profiles, usb_identity, worker_namespace


PROGRAM = r'''import glob, hashlib, json, os, pathlib, subprocess
report={}
paths=['/var/jb/usr/bin/launchctl','/var/jb/bin/launchctl','/usr/bin/launchctl','/var/jb/Library/LaunchDaemons','/Library/LaunchDaemons','/var/jb/.thebootstrapped','/private/preboot','/var/jb/Applications']
for name in paths:
 p=pathlib.Path(name)
 entry={'exists':p.exists(),'symlink':p.is_symlink(),'resolved':str(p.resolve()) if p.exists() else None}
 if p.is_file():
  entry['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
  entry['size']=p.stat().st_size
 if p.is_dir() and 'LaunchDaemons' in name:
  entry['matches']=[x.name for x in p.glob('*') if any(t in x.name.lower() for t in ('tr','troll','qaq'))]
 report[name]=entry
for name in ['/var/jb/usr/bin/launchctl','/usr/bin/launchctl']:
 try:
  p=subprocess.run([name,'version'],capture_output=True,timeout=5)
  report[name]['version']={'status':p.returncode,'out':p.stdout.decode(errors='replace')[-200:],'err':p.stderr.decode(errors='replace')[-500:]}
 except Exception as e:report[name]['version_error']=str(e)
helpers=glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd')
report['helpers']=[]
for name in helpers:
 p=pathlib.Path(name);r=subprocess.run([name,'version'],capture_output=True,timeout=5)
 report['helpers'].append({'path':name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'status':r.returncode,'out':r.stdout.decode(errors='replace')[-200:],'err':r.stderr.decode(errors='replace')[-200:]})
print(json.dumps(report))
'''


if __name__ == '__main__':
    ensure_device_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    args = parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _, profile = profiles()[args.udid]
    result = worker_namespace(profile)['ssh']('/var/jb/usr/bin/python3 -c ' + shlex.quote(PROGRAM), timeout=60)
    print(json.dumps(json.loads(result.stdout), indent=2))
