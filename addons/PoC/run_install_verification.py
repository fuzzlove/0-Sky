"""Exercise the actual authenticated DEB or IPA installer with a local fixture."""
import argparse,asyncio,hashlib,json,shlex,time,uuid
from pathlib import Path
from repair_device_connection import HERE,profiles,usb_identity,worker_namespace,atomic_write
from device_python import ensure_device_python

def verify(udid,kind):
    asyncio.run(usb_identity(udid));_,value=profiles()[udid];namespace=worker_namespace(value)
    source=HERE/'installer-verification'/('0-sky-install-check.'+kind)
    raw=source.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    destination='/var/mobile/tmp/0sky-install-check-'+uuid.uuid4().hex+'.'+kind
    program="import sys,hashlib,os;raw=sys.stdin.buffer.read();assert hashlib.sha256(raw).hexdigest()==sys.argv[2];fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);f=os.fdopen(fd,'wb');f.write(raw);f.close()"
    namespace['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(program)+' '+shlex.quote(destination)+' '+digest,input_data=raw,timeout=30)
    program=r'''import http.client,json,pathlib,sys
token=pathlib.Path("/var/jb/etc/trollstorelite-srd-bridge.token").read_text().strip()
args=["install-deb",sys.argv[1]] if sys.argv[2]=="deb" else ["install","custom",sys.argv[1]]
c=http.client.HTTPConnection("127.0.0.1",48654,timeout=1850)
c.request("POST","/v1/trollstore",json.dumps({"arguments":args}),{"Content-Type":"application/json","X-TrollStore-Bridge-Token":token})
r=c.getresponse();value=json.loads(r.read(1048576));c.close()
print(json.dumps({"http_status":r.status,"status":value.get("status"),"stderr":value.get("stderr"),"stdout":value.get("stdout","")[-6000:]}))'''
    try:
        result=namespace['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(program)+' '+shlex.quote(destination)+' '+kind,timeout=1900)
        report={'udid':udid,'kind':kind,'checked_at':int(time.time()),**json.loads(result.stdout)}
        atomic_write(HERE/'installer-verification'/(kind+'-result.json'),json.dumps(report,indent=2).encode())
        return report
    finally:
        namespace['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote('import os,sys;os.unlink(sys.argv[1])')+' '+shlex.quote(destination),timeout=15,check=False)

if __name__=='__main__':
    ensure_device_python();p=argparse.ArgumentParser(description=__doc__);p.add_argument('--udid',required=True);p.add_argument('--kind',choices=['deb','ipa'],required=True);a=p.parse_args()
    result=verify(a.udid,a.kind);print(json.dumps(result,indent=2));raise SystemExit(0 if result.get('status')==0 else 2)
