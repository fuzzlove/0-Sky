"""Retry the latest install admissions and report their actual backend errors."""
import argparse,asyncio,json,shlex
from repair_device_connection import profiles,usb_identity,worker_namespace
from device_python import ensure_device_python
PROGRAM=r'''import http.client,json,pathlib
log=pathlib.Path("/var/jb/var/log/trollstorelite-srd-bridge.log")
with log.open('rb') as f:
 f.seek(max(0,log.stat().st_size-65536));lines=f.read().decode(errors='replace').splitlines()
requests={}
for line in lines:
 try:
  value=json.loads(line);args=value.get("request_arguments")
  if isinstance(args,list) and args and args[0] in ("install-deb","install") and isinstance(args[-1],str):requests[args[0]]=args
 except Exception:pass
token=pathlib.Path("/var/jb/etc/trollstorelite-srd-bridge.token").read_text().strip()
results=[]
for kind,args in requests.items():
 c=http.client.HTTPConnection("127.0.0.1",48654,timeout=90)
 try:
  c.request("POST","/v1/trollstore",json.dumps({"arguments":args}),{"Content-Type":"application/json","X-TrollStore-Bridge-Token":token})
  response=c.getresponse();value=json.loads(response.read(1048576))
  results.append({"kind":kind,"file":pathlib.Path(args[-1]).name,"http_status":response.status,"status":value.get("status"),"error":value.get("stderr"),"stdout":value.get("stdout","")[-1500:]})
 finally:c.close()
print(json.dumps(results))'''
if __name__=='__main__':
 ensure_device_python()
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--udid',required=True);a=p.parse_args()
 asyncio.run(usb_identity(a.udid));_,v=profiles()[a.udid]
 r=worker_namespace(v)['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM),timeout=200)
 print(json.dumps(json.loads(r.stdout),indent=2))
