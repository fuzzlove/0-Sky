"""Inspect app setup logs and test the trusted daemon's non-recording help path."""
import argparse,asyncio,json,shlex
from repair_device_connection import HERE,profiles,usb_identity,worker_namespace,atomic_write
from device_python import ensure_device_python
PROGRAM=r'''import glob,json,os,pathlib,plistlib,subprocess
bundle='wiki.qaq.trapp';report={'logs':{},'help':{}}
listing=subprocess.run(['/var/jb/usr/bin/uicache','-l'],capture_output=True,text=True,timeout=30)
matches=[s.split(' : ',1)[1] for s in listing.stdout.splitlines() if s.startswith(bundle+' : ')]
if len(matches)!=1:raise SystemExit('Ambiguous registration')
app=pathlib.Path(matches[0]);report['app']=str(app)
for name in glob.glob('/var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist'):
 try:
  p=pathlib.Path(name);metadata=plistlib.loads(p.read_bytes())
  if metadata.get('MCMMetadataIdentifier')!=bundle:continue
  for folder in ('Library/Logs','Library/Caches/Logs','Documents/Logs','Library/Caches/com.cocoalumberjack'):
   root=p.parent/folder
   if not root.exists():continue
   files=[f for f in root.rglob('*') if f.is_file()]
   for f in sorted(files,key=lambda x:x.stat().st_mtime,reverse=True)[:3]:
    with f.open('rb') as h:h.seek(max(0,f.stat().st_size-65536));text=h.read().decode(errors='replace')
    report['logs'][f.name]='\n'.join(s[-1000:] for s in text.splitlines() if any(t in s.lower() for t in ('[cs]','signature','spawning daemon','spawn process','jailbreak detected','launchctl','setupapplication')))[-8000:]
 except Exception as e:report['log_error']=type(e).__name__
for key, arguments in (('help',['--help']),('no_arguments',[])):
 try:
  r=subprocess.run([str(app/'TRCallMonitor'),*arguments],stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
  report[key]={'status':r.returncode,'stdout':r.stdout.decode(errors='replace')[-3000:],'stderr':r.stderr.decode(errors='replace')[-3000:]}
 except subprocess.TimeoutExpired as e:
  report[key]={'status':'timeout','stdout':(e.stdout or b'').decode(errors='replace')[-3000:],'stderr':(e.stderr or b'').decode(errors='replace')[-3000:]}
try:
 r=subprocess.run([str(app/'TRApp')],stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
 report['main_root']={'status':r.returncode,'stdout':r.stdout.decode(errors='replace')[-3000:],'stderr':r.stderr.decode(errors='replace')[-3000:]}
except subprocess.TimeoutExpired as e:
 report['main_root']={'status':'timeout','stdout':(e.stdout or b'').decode(errors='replace')[-3000:],'stderr':(e.stderr or b'').decode(errors='replace')[-3000:]}
print(json.dumps(report))
'''
if __name__=='__main__':
 ensure_device_python();p=argparse.ArgumentParser();p.add_argument('--udid',required=True);a=p.parse_args();asyncio.run(usb_identity(a.udid));_,value=profiles()[a.udid]
 r=worker_namespace(value)['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM),timeout=70);report={'udid':a.udid,**json.loads(r.stdout)}
 atomic_write(HERE/'installer-verification/trollrecorder-daemon-probe.json',json.dumps(report,indent=2).encode());print(json.dumps(report,indent=2))
