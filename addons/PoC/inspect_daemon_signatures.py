"""Read recent signature failures and launchd state without changing services."""
import argparse,asyncio,json,shlex
from repair_device_connection import HERE,profiles,usb_identity,worker_namespace,atomic_write
from device_python import ensure_device_python

PROGRAM=r'''import ctypes,glob,json,os,pathlib,plistlib,subprocess,time
report={'crashes':[],'jobs':[],'logs':{},'processes':[]}
files=[]
for folder in ('/var/mobile/Library/Logs/CrashReporter','/Library/Logs/CrashReporter'):
 for name in glob.glob(folder+'/*.ips'):
  path=pathlib.Path(name)
  if path.stat().st_mtime>time.time()-86400:files.append(path)
for path in sorted(files,key=lambda p:p.stat().st_mtime,reverse=True)[:25]:
 try:
  text=path.read_text(errors='replace')[:524288];head,body=text.split('\n',1);value=json.loads(body)
  report['crashes'].append({'name':path.name,'modified':path.stat().st_mtime,**{k:value[k] for k in ('procName','procPath','exception','termination','asi') if k in value}})
 except Exception as e:report['crashes'].append({'name':path.name,'error':type(e).__name__})
helpers=glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd')+glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd')
helper=helpers[0] if len(helpers)==1 else None
report['launch_helper']=helper
roots=['/var/jb/Library/LaunchDaemons','/Library/LaunchDaemons','/var/mobile/Library/LaunchDaemons']
for root in roots:
 for path in pathlib.Path(root).glob('*.plist'):
  try:
   value=plistlib.loads(path.read_bytes());label=value.get('Label','');args=value.get('ProgramArguments',[]) or [value.get('Program','')]
   if not root.startswith('/var/jb') and not any(t in str(value).lower() for t in ('trapp','trd','trollrecorder','localfence')):continue
   entry={'path':str(path),'label':label,'arguments':args}
   if helper:
    result=subprocess.run([helper,'print','system/'+label],capture_output=True,timeout=8)
    entry['loaded']=result.returncode==0
    entry['state']='\n'.join(s.strip() for s in result.stdout.decode(errors='replace').splitlines() if any(t in s for t in ('state =','pid =','last exit','reason','code-sign','program =')))
   report['jobs'].append(entry)
  except Exception as e:report['jobs'].append({'path':str(path),'error':type(e).__name__})
lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib');pids=(ctypes.c_int*8192)();count=lib.proc_listallpids(pids,ctypes.sizeof(pids))
for pid in pids[:min(count,len(pids))]:
 path=ctypes.create_string_buffer(4096)
 if lib.proc_pidpath(pid,path,len(path))>0:
  name=path.value.decode(errors='replace')
  if any(t in name.lower() for t in ('trapp','trd','trollrecorder','localfence','srd-runtime')):report['processes'].append({'pid':pid,'path':name})
for path in pathlib.Path('/var/jb/var/log').glob('*'):
 if path.is_file() and any(t in path.name.lower() for t in ('localfence','runtime','trapp','trd','troll')):
  with path.open('rb') as f:f.seek(max(0,path.stat().st_size-8192));text=f.read().decode(errors='replace')
  report['logs'][path.name]='\n'.join(s[:500] for s in text.splitlines()[-20:])
print(json.dumps(report))
'''

if __name__=='__main__':
 ensure_device_python();p=argparse.ArgumentParser(description=__doc__);p.add_argument('--udid',required=True);a=p.parse_args()
 asyncio.run(usb_identity(a.udid));_,value=profiles()[a.udid]
 result=worker_namespace(value)['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM),timeout=150)
 report={'udid':a.udid,**json.loads(result.stdout)}
 atomic_write(HERE/'installer-verification/daemon-diagnostics.json',json.dumps(report,indent=2).encode())
 print(json.dumps(report,indent=2))
