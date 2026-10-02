"""Temporarily expose the existing Procursus bootstrap to TrollRecorder."""
import argparse
import asyncio
import json
import shlex

from device_python import ensure_device_python
from repair_device_connection import profiles, usb_identity, worker_namespace


PROGRAM = r'''import json,os,pathlib,sys
mode=sys.argv[1]
root=pathlib.Path('/var/jb')
resolved=root.resolve()
if not root.is_symlink() or resolved.name!='procursus' or resolved.parent.parent!=pathlib.Path('/private/preboot') or not (resolved/'usr/bin/launchctl').is_file():raise SystemExit('Unexpected bootstrap root')
marker=root/'.thebootstrapped'
if marker.is_symlink() or (marker.exists() and (not marker.is_file() or marker.read_bytes()!=b'')):raise SystemExit('Unexpected marker')
if mode=='apply' and not marker.exists():
 fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644);os.close(fd)
if mode=='remove' and marker.exists():marker.unlink()
print(json.dumps({'marker':str(marker),'exists':marker.exists(),'root':str(resolved)}))
'''


if __name__ == '__main__':
    ensure_device_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--mode', choices=('apply','remove','inspect'), required=True)
    args = parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _, profile = profiles()[args.udid]
    command = '/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM)+' '+shlex.quote(args.mode)
    result = worker_namespace(profile)['ssh'](command, timeout=45)
    print(json.dumps(json.loads(result.stdout), indent=2))
