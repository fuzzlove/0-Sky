"""Test whether the signed TrollRecorder main binary serves daemon requests as root."""
import argparse
import asyncio
import json
import shlex

from device_python import ensure_device_python
from repair_device_connection import profiles, usb_identity, worker_namespace


PROGRAM = r'''import json,os,pathlib,plistlib,subprocess,time,signal
bundle='wiki.qaq.trapp'
listing=subprocess.run(['/var/jb/usr/bin/uicache','-l'],capture_output=True,text=True,timeout=30)
matches=[s.split(' : ',1)[1] for s in listing.stdout.splitlines() if s.startswith(bundle+' : ')]
if len(matches)!=1:raise SystemExit('Ambiguous app registration')
app=pathlib.Path(matches[0]);container=app.parent
if app.is_symlink() or container.is_symlink() or container.parent!=pathlib.Path('/private/var/containers/Bundle/Application'):raise SystemExit('Unsafe app path')
info=plistlib.loads((app/'Info.plist').read_bytes());metadata=plistlib.loads((container/'.com.apple.mobile_container_manager.metadata.plist').read_bytes())
if info.get('CFBundleIdentifier')!=bundle or metadata.get('MCMMetadataIdentifier')!=bundle:raise SystemExit('App identity mismatch')
process=subprocess.Popen([str(app/'TRApp')],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
print(json.dumps({'pid':process.pid,'started':True}),flush=True)
try:
 time.sleep(25)
 print(json.dumps({'pid':process.pid,'alive_after_25s':process.poll() is None,'status':process.poll()}),flush=True)
finally:
 if process.poll() is None:
  process.terminate()
  try:process.wait(timeout=3)
  except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
'''


if __name__ == '__main__':
    ensure_device_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    args = parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _, profile = profiles()[args.udid]
    command = '/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM)
    result = worker_namespace(profile)['ssh'](command, timeout=75)
    print(result.stdout.decode())
