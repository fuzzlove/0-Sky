"""Copy only TrollRecorder code for signature comparison; read runtime flags."""
import argparse,asyncio,hashlib,json,shlex,subprocess
from pathlib import Path
from repair_device_connection import HERE,profiles,usb_identity,worker_namespace,atomic_write
from device_python import ensure_device_python

PROGRAM=r'''import ctypes,glob,hashlib,json,pathlib,plistlib,subprocess
bundle='wiki.qaq.trapp'
listing=subprocess.run(['/var/jb/usr/bin/uicache','-l'],capture_output=True,text=True,timeout=30)
paths=[s.split(' : ',1)[1] for s in listing.stdout.splitlines() if s.startswith(bundle+' : ')]
if len(paths)!=1:raise SystemExit('Ambiguous TrollRecorder registration')
app=pathlib.Path(paths[0]);info=plistlib.loads((app/'Info.plist').read_bytes())
if info.get('CFBundleIdentifier')!=bundle:raise SystemExit('App identity mismatch')
lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib');pids=(ctypes.c_int*8192)();count=lib.proc_listallpids(pids,ctypes.sizeof(pids));processes=[]
for pid in pids[:min(count,len(pids))]:
 path=ctypes.create_string_buffer(4096)
 if lib.proc_pidpath(pid,path,len(path))>0 and path.value.decode(errors='replace').startswith(str(app)+'/'):
  flags=ctypes.c_uint32();result=lib.csops(pid,0,ctypes.byref(flags),ctypes.sizeof(flags))
  processes.append({'pid':pid,'path':path.value.decode(),'csops_status':result,'flags':hex(flags.value)})
record=json.loads(pathlib.Path('/var/jb/var/lib/crypstore/'+bundle+'.json').read_text())
report={'app':str(app),'processes':processes,'cryptex_identifier':record.get('cryptex_identifier'),
 'code':{},'jobs':[]}
for name in ('TRApp','TRCallMonitor','TRAudioRecorder','TRRealtimeRecorder'):
 path=app/name
 report['code'][name]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'size':path.stat().st_size}
for name in glob.glob('/var/jb/Library/LaunchDaemons/*tr*services*.plist')+glob.glob('/Library/LaunchDaemons/*tr*services*.plist'):
 report['jobs'].append({'path':name,'value':plistlib.loads(pathlib.Path(name).read_bytes())})
print(json.dumps(report))
'''
if __name__=='__main__':
 ensure_device_python();p=argparse.ArgumentParser();p.add_argument('--udid',required=True);a=p.parse_args()
 asyncio.run(usb_identity(a.udid));_,value=profiles()[a.udid];ssh=worker_namespace(value)['ssh']
 r=ssh('/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM),timeout=45);report=json.loads(r.stdout)
 output=HERE/'installer-verification/trollrecorder-signatures';output.mkdir(parents=True,exist_ok=True,mode=0o700)
 for name in ('TRApp','TRCallMonitor'):
  raw=ssh('/var/jb/usr/bin/python3 -c '+shlex.quote('import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())')+' '+shlex.quote(report['app']+'/'+name),timeout=90).stdout
  if hashlib.sha256(raw).hexdigest()!=report['code'][name]['sha256']:raise RuntimeError('Code changed during inspection')
  path=output/name;atomic_write(path,raw,0o700)
  check=subprocess.run(['/usr/bin/codesign','--verify','--strict',str(path)],capture_output=True,text=True,timeout=30)
  display=subprocess.run(['/usr/bin/codesign','-dvvv',str(path)],capture_output=True,text=True,timeout=30)
  report['code'][name].update({'verify_status':check.returncode,'verify_error':check.stderr[-1500:],
   'signature':[s for s in display.stderr.splitlines() if s.startswith(('Identifier=','TeamIdentifier=','Signature=','CodeDirectory','CDHash='))]})
 atomic_write(output/'report.json',json.dumps(report,indent=2).encode());print(json.dumps(report,indent=2))
