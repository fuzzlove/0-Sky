#!/usr/bin/env python3
"""Show recent nonsecret pair-job outcomes for one enrolled SRD."""
import argparse
import json
import shlex

from repair_device_connection import profiles, worker_namespace

REMOTE = r'''import json,pathlib
root=pathlib.Path('/var/jb/var/spool/crypstore/jobs')
rows=[]
for path in sorted(root.glob('*/result.json'),key=lambda p:p.stat().st_mtime,reverse=True)[:8]:
 try: value=json.loads(path.read_text())
 except (OSError,ValueError): continue
 result=value.get('result',value)
 if not isinstance(result,dict): continue
 rows.append({'status':result.get('status'),'errorCode':result.get('errorCode'),
              'stderr':str(result.get('stderr',''))[:180],
              'pairing_error':(result.get('pairing') or {}).get('errorCode')})
print(json.dumps(rows))'''

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    udid = parser.parse_args().udid
    namespace = worker_namespace(profiles()[udid][1])
    response = namespace["ssh"](
        "/var/jb/usr/bin/python3 -c " + shlex.quote(REMOTE), timeout=20, check=True)
    print(json.dumps({"device": udid, "jobs": json.loads(response.stdout)}, indent=2))
