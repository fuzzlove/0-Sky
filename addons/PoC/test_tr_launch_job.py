"""Test a verified TrollRecorder helper as a launchd-managed root service."""
import argparse
import asyncio
import json
import shlex

from device_python import ensure_device_python
from repair_device_connection import profiles, usb_identity, worker_namespace


PROGRAM = r'''import glob,hashlib,json,os,pathlib,plistlib,re,subprocess,sys,time
mode=sys.argv[1];bundle='wiki.qaq.trapp';label='wiki.qaq.trservices'
plist=pathlib.Path('/var/jb/Library/LaunchDaemons/'+label+'.plist')
helpers=glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd')+glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd')
trusted=[p for p in helpers if hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()=='a2d095b681cd4bf1ac819a7052b5b376516ed663bd989edc60d25297fa1e9bbc']
ctl=trusted[0] if len(trusted)==1 else '/var/jb/usr/bin/launchctl'
def check_job():
 r=subprocess.run([ctl,'print','system/'+label],capture_output=True,timeout=8)
 return {'status':r.returncode,'text':'\n'.join(s.strip() for s in r.stdout.decode(errors='replace').splitlines() if any(t in s for t in ('state =','pid =','last exit','program =','path =','reason =')))[-2000:],'stderr':r.stderr.decode(errors='replace')[-400:]}
if mode=='inspect':print(json.dumps({'plist_exists':plist.exists(),'job':check_job()}));raise SystemExit(0)
if mode=='remove':
 if plist.exists():
  data=plistlib.loads(plist.read_bytes())
  if data.get('Label')!=label or data.get('0SkyTest')!=True:raise SystemExit('Not our test job')
  subprocess.run([ctl,'bootout','system/'+label],capture_output=True,timeout=10)
  plist.unlink()
 print(json.dumps({'removed':True,'job':check_job()}));raise SystemExit(0)
if plist.exists():raise SystemExit('Vendor launch plist already exists')
listing=subprocess.run(['/var/jb/usr/bin/uicache','-l'],capture_output=True,text=True,timeout=30)
matches=[s.split(' : ',1)[1] for s in listing.stdout.splitlines() if s.startswith(bundle+' : ')]
if len(matches)!=1:raise SystemExit('Ambiguous app registration')
app=pathlib.Path(matches[0]);container=app.parent
if app.is_symlink() or container.is_symlink() or container.parent!=pathlib.Path('/private/var/containers/Bundle/Application'):raise SystemExit('Unsafe MCM app path')
info=plistlib.loads((app/'Info.plist').read_bytes());metadata=plistlib.loads((container/'.com.apple.mobile_container_manager.metadata.plist').read_bytes())
if info.get('CFBundleIdentifier')!=bundle or metadata.get('MCMMetadataIdentifier')!=bundle or not (container/'_TrollStore').is_file():raise SystemExit('Unverified app identity')
state=json.loads(pathlib.Path('/var/jb/var/lib/crypstore/'+bundle+'.json').read_text());identifier=state['cryptex_identifier']
mounts=glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/'+identifier+'.*/Applications/TRApp.app/TRCallMonitor')
if len(mounts)!=1 or hashlib.sha256((app/'TRCallMonitor').read_bytes()).digest()!=hashlib.sha256(pathlib.Path(mounts[0]).read_bytes()).digest():raise SystemExit('Daemon differs from mounted Cryptex')
data={'Label':label,'ProgramArguments':[str(app/'TRCallMonitor')],'UserName':'root','RunAtLoad':True,'KeepAlive':False,'MachServices':{'wiki.qaq.trapp.xpc':True},'0SkyTest':True}
fd=os.open(plist,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
try:
 with os.fdopen(fd,'wb') as f:f.write(plistlib.dumps(data));f.flush();os.fsync(f.fileno())
 r=subprocess.run([ctl,'bootstrap','system',str(plist)],capture_output=True,timeout=12)
 if r.returncode:raise RuntimeError('bootstrap '+r.stderr.decode(errors='replace')[-500:])
 time.sleep(8)
 job=check_job()
 keep=bool(re.search(r'pid = [0-9]+',job['text']))
 if not keep:
  subprocess.run([ctl,'bootout','system/'+label],capture_output=True,timeout=10)
  plist.unlink()
 print(json.dumps({'kept':keep,'job':job,'path':str(plist)}))
except BaseException:
 subprocess.run([ctl,'bootout','system/'+label],capture_output=True,timeout=10)
 if plist.exists():plist.unlink()
 raise
'''


if __name__ == '__main__':
    ensure_device_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--mode', choices=('apply','inspect','remove'), required=True)
    args = parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _, profile = profiles()[args.udid]
    command = '/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM)+' '+shlex.quote(args.mode)
    result = worker_namespace(profile)['ssh'](command, timeout=90)
    print(json.dumps(json.loads(result.stdout),indent=2))
