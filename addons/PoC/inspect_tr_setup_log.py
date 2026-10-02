"""Extract only daemon setup diagnostics from TrollRecorder's own log."""
import argparse
import asyncio
import json
import shlex

from device_python import ensure_device_python
from repair_device_connection import profiles, usb_identity, worker_namespace


PROGRAM = r'''import json,pathlib,time
root=pathlib.Path('/var/mobile/Library/Caches/wiki.qaq.trapp/Logs/wiki.qaq.trapp')
files=sorted((p for p in root.glob('*.log') if p.is_file()),key=lambda p:p.stat().st_mtime,reverse=True)[:3]
patterns=('spawning daemon','spawnasscrewdriver','initial daemon check','jailbreak detected','launchctl','globalsetupapplication','setupapplication','posixspawnfailed','failed to spawn','launch daemon','trservices','error','signature')
result=[]
for path in files:
 with path.open('rb') as f:f.seek(max(0,path.stat().st_size-1024*1024));text=f.read().decode(errors='replace')
 matches=[line[:350] for line in text.splitlines() if any(token in line.lower() for token in patterns)]
 result.append({'file':path.name,'size':path.stat().st_size,'age_seconds':round(time.time()-path.stat().st_mtime),'matches':matches[-90:]})
print(json.dumps(result))
'''


if __name__ == '__main__':
    ensure_device_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    args = parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _, profile = profiles()[args.udid]
    result = worker_namespace(profile)['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM), timeout=60)
    print(json.dumps(json.loads(result.stdout),indent=2))
