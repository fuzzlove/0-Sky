"""Find TrollRecorder's own recent setup logs without reading recording content."""
import argparse
import asyncio
import json
import shlex

from device_python import ensure_device_python
from repair_device_connection import profiles, usb_identity, worker_namespace


PROGRAM = r'''import json,pathlib,time
roots=['/var/mobile/Library/Caches/wiki.qaq.trapp','/var/mobile/Library/Preferences/wiki.qaq.trapp','/var/mobile/Library/Logs/wiki.qaq.trapp','/var/jb/var/log/wiki.qaq.trapp','/var/root/Library/Caches/wiki.qaq.trapp']
report={}
for name in roots:
 root=pathlib.Path(name);entry={'exists':root.exists()}
 if root.is_dir():
  files=[p for p in root.rglob('*') if p.is_file()]
  entry['recent_files']=[]
  for path in sorted(files,key=lambda p:p.stat().st_mtime,reverse=True)[:20]:
   item={'name':str(path.relative_to(root)),'size':path.stat().st_size,'age_seconds':round(time.time()-path.stat().st_mtime)}
   if path.stat().st_size<=256*1024 and path.suffix.lower() in ('.log','.txt','.json'):
    text=path.read_text(errors='replace')
    item['lines']=[s[-1000:] for s in text.splitlines() if any(t in s.lower() for t in ('daemon','spawn','signature','jailbreak','launchctl','bootstrap','error','fail'))][-20:]
   entry['recent_files'].append(item)
 report[name]=entry
print(json.dumps(report))
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
