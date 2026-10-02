#!/usr/bin/env python3
"""Verify authenticated 0-Sky Core operations on one exact paired USB device."""
import argparse
import asyncio
import json
from pathlib import Path
import plistlib
import shlex
import time

from device_python import ensure_device_python
from repair_device_connection import profiles,usb_identity,worker_namespace,atomic_write


PROGRAM=r'''import http.client,json,time,uuid
with open("/var/jb/etc/trollstorelite-srd-bridge.token",encoding="ascii") as f: token=f.read().strip()
results=[]
for operation in ("getStatus","getControlCenterSummary"):
 connection=http.client.HTTPConnection("127.0.0.1",48654,timeout=20)
 try:
  payload={"protocolVersion":1,"requestId":str(uuid.uuid4()),"timestamp":time.time(),"operation":operation,"parameters":{}}
  connection.request("POST","/v1/core",json.dumps(payload),{"Content-Type":"application/json","X-TrollStore-Bridge-Token":token})
  response=connection.getresponse();body=response.read(1048577)
  if len(body)>1048576: raise RuntimeError("Core response exceeds size limit")
  value=json.loads(body)
  results.append({"operation":operation,"http_status":response.status,"success":value.get("success",False),
   "errorCode":value.get("errorCode"),"errorMessage":value.get("errorMessage",value.get("stderr")),
   "result":value.get("result"),"pairing_state":value.get("pairing",{}).get("pairing_state"),
   "pairing_diagnostic":{k:value.get("pairing",{}).get(k) for k in ("paired","marker_valid","pairing_registry_valid","pairing_registry_schema","paired_host_count","active_host_enrolled","worker_fresh","worker_host_key_authorized","marker_diagnostic","apple_pairing_verified","host_identity_verified")} if not value.get("success") else None})
 finally: connection.close()
print(json.dumps(results))
'''


def verify(udid, instance_name=None):
    identity=asyncio.run(usb_identity(udid))
    path,value=profiles(instance_name=instance_name)[udid]
    namespace=worker_namespace(plistlib.loads(path.read_bytes()))
    report=check(namespace)
    return {"device":identity,**report}


def check(namespace):
    result=namespace["ssh"]("/var/jb/usr/bin/python3 -c "+shlex.quote(PROGRAM),timeout=50,check=False)
    if result.returncode:
        return {"core_verified":False,"error":result.stderr.decode(errors="replace")[-1200:]}
    checks=json.loads(result.stdout)
    return {"core_verified":all(x["success"] and x["http_status"]==200 for x in checks),
            "checks":checks,"checked_at":int(time.time())}


if __name__=="__main__":
    ensure_device_python()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid",required=True)
    parser.add_argument("--instance-name")
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    result=verify(args.udid,args.instance_name)
    if args.output: atomic_write(args.output,(json.dumps(result,indent=2)+"\n").encode())
    print(json.dumps(result,indent=2))
    raise SystemExit(0 if result["core_verified"] else 2)
