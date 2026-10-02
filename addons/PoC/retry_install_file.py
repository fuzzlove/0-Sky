"""Retry one selected IPA through the actual authenticated device installer."""
import argparse,asyncio,hashlib,json,shlex,time,uuid
from pathlib import Path
from repair_device_connection import HERE,profiles,usb_identity,worker_namespace,atomic_write
from device_python import ensure_device_python

def retry(udid,source,instance_name=None,output=None):
    report_path=(Path(output) if output else HERE/'installer-verification/latest-retry.json').expanduser().resolve()
    report_path.parent.mkdir(parents=True,exist_ok=True)
    asyncio.run(usb_identity(udid));_,profile=profiles(instance_name=instance_name)[udid];namespace=worker_namespace(profile)
    source=Path(source).resolve(strict=True)
    if source.stat().st_size>2*1024**3:raise RuntimeError('IPA exceeds transport limit')
    raw=source.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    folder='/var/mobile/tmp/0sky-retry-'+uuid.uuid4().hex
    destination=folder+'/'+source.name
    upload=r'''import hashlib,os,sys
raw=sys.stdin.buffer.read()
if hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise SystemExit('Source hash mismatch')
os.mkdir(os.path.dirname(sys.argv[1]),0o700)
fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f:f.write(raw)
'''
    request=r'''import http.client,json,pathlib,sys
token=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
c=http.client.HTTPConnection('127.0.0.1',48654,timeout=1850)
c.request('POST','/v1/trollstore',json.dumps({'arguments':['install','custom',sys.argv[1]]}),{'Content-Type':'application/json','X-TrollStore-Bridge-Token':token})
r=c.getresponse();value=json.loads(r.read(1048576));c.close()
print(json.dumps({'http_status':r.status,'status':value.get('status'),'stderr':value.get('stderr'),'stdout':value.get('stdout','')[-6000:]}))
'''
    try:
        namespace['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(upload)+' '+shlex.quote(destination)+' '+digest,input_data=raw,timeout=600)
        result=namespace['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(request)+' '+shlex.quote(destination),timeout=1900)
        report={'udid':udid,'file':source.name,'source_sha256':digest,'checked_at':int(time.time()),**json.loads(result.stdout)}
        atomic_write(report_path,json.dumps(report,indent=2).encode())
        return report
    finally:
        cleanup='import os,sys;os.unlink(sys.argv[1]);os.rmdir(os.path.dirname(sys.argv[1]))'
        namespace['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(cleanup)+' '+shlex.quote(destination),timeout=15,check=False)

if __name__=='__main__':
    ensure_device_python();p=argparse.ArgumentParser(description=__doc__);p.add_argument('--udid',required=True);p.add_argument('--file',required=True);p.add_argument('--instance-name');p.add_argument('--output',type=Path);a=p.parse_args()
    report=retry(a.udid,a.file,a.instance_name,a.output);print(json.dumps(report,indent=2));raise SystemExit(0 if report.get('status')==0 else 2)
