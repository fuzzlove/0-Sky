"""Read bounded, non-secret install diagnostics for an exact paired device."""
import argparse,asyncio,json,shlex
from repair_device_connection import profiles,usb_identity,worker_namespace
from device_python import ensure_device_python
PROGRAM=r'''import pathlib,json,importlib.util,sys
sys.path.insert(0,"/var/jb/usr/local/libexec")
report={"modules":{n:importlib.util.find_spec(n) is not None for n in ("zero_sky_compat","zero_sky_core")},"jobs":[],"bridge_log":[]}
root=pathlib.Path("/var/jb/var/spool/crypstore/jobs")
if root.exists():
 for directory in sorted(root.iterdir(),key=lambda p:p.stat().st_mtime,reverse=True)[:12]:
  item={"id":directory.name}
  for name in ("request.json","processing.json","result.json"):
   p=directory/name
   if p.is_file():
    try:
     v=json.loads(p.read_text());item[name]={k:v.get(k) for k in ("operation","original_name","status","stderr","errorCode","created_at") if k in v}
     if "stderr" in item[name]:item[name]["stderr"]=str(item[name]["stderr"])[-2000:]
    except Exception as e:item[name]={"error":type(e).__name__}
  report["jobs"].append(item)
log=pathlib.Path("/var/jb/var/log/trollstorelite-srd-bridge.log")
if log.is_file():
 with log.open("rb") as f:
  f.seek(max(0,log.stat().st_size-65536));lines=f.read().decode(errors="replace").splitlines()
 for line in lines[-50:]:
  try:
   value=json.loads(line)
   if value.get("operation")!="device-password":report["bridge_log"].append({k:str(value[k])[-1800:] for k in ("operation","status","stderr","args","request_arguments","rejected") if k in value})
  except Exception:pass
print(json.dumps(report))'''
if __name__=='__main__':
 ensure_device_python()
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--udid',required=True);a=p.parse_args()
 asyncio.run(usb_identity(a.udid));_,v=profiles()[a.udid]
 r=worker_namespace(v)['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM),timeout=30)
 print(json.dumps(json.loads(r.stdout),indent=2))
