import json,argparse
from recovery_ssh import channel
from device_python import ensure_device_python
PROGRAM=r'''import os,json,glob,plistlib,subprocess,ctypes,struct,hashlib
p="/var/jb/usr/local/libexec/trollstorelite-srd-bridge.py"
result={"bridge_path":p,"exists":os.path.exists(p),"realpath":os.path.realpath(p)}
if os.path.exists(p):
 s=open(p).read();result["registry_v2"]="def pairing_host_id(" in s;result["sha256"]=hashlib.sha256(s.encode()).hexdigest()
 result["version_lines"]=[l.strip() for l in s.splitlines() if "VERSION" in l or "PAIRING_REGISTRY" in l][:15]
result["launch_jobs"]=glob.glob("/var/jb/Library/LaunchDaemons/*sky*")+glob.glob("/var/jb/Library/LaunchDaemons/*bridge*")
result["bridge_job"]=plistlib.load(open("/var/jb/Library/LaunchDaemons/com.liquidskysecurity.trollstorelite-srd-bridge.plist","rb"))
result["launchctl"]=dict((p,os.path.exists(p)) for p in ("/var/jb/usr/bin/launchctl","/bin/launchctl","/var/jb/bin/launchctl"))
result["processes"]={}
lib=ctypes.CDLL("/usr/lib/libSystem.B.dylib",use_errno=True)
pids=(ctypes.c_int*8192)()
count=lib.proc_listallpids(pids,ctypes.sizeof(pids))
found=[]
for pid in pids[:count]:
 name=ctypes.create_string_buffer(4096)
 if lib.proc_pidpath(pid,name,len(name))<=0 or b"python" not in name.value: continue
 mib=(ctypes.c_int*3)(1,49,pid);buf=ctypes.create_string_buffer(65536);size=ctypes.c_size_t(len(buf))
 if lib.sysctl(mib,3,buf,ctypes.byref(size),None,0)!=0: continue
 argc=struct.unpack("i",buf.raw[:4])[0];parts=buf.raw[4:size.value].split(b"\0");args=[x for x in parts[1:] if x][:argc]
 if any(a.endswith(b".py") and b"bridge" in a for a in args): found.append({"pid":pid,"path":name.value.decode(),"args":[a.decode(errors="replace") for a in args if a.endswith(b".py")]})
result["processes"]["libproc"]={"count":count,"bridge":found}
result["direct_pairing"]=__import__('runpy').run_path(p,run_name='bridge_inspection')['pairing_status']()
result["log_errors"]={}
for log in ("/var/jb/var/log/trollstorelite-srd-bridge-service.log","/var/jb/var/log/trollstorelite-srd-bridge.log"):
 if os.path.exists(log):
  with open(log,'rb') as f:
   f.seek(max(0,os.path.getsize(log)-2000));tail=f.read().decode(errors='replace')
  result["log_errors"][log]=[l[:250] for l in tail.splitlines() if any(k in l for k in ('Error','Traceback','Exception','line '))][-10:]
result["launch_helpers"]=glob.glob("/private/var/run/com.apple.security.cryptexd/mnt/*/usr/bin/*launchctl*")+glob.glob("/var/jb/usr/local/bin/*launchctl*")
toybox=glob.glob("/private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.srdssh.recovery-*/usr/bin/toybox")[0]
r=subprocess.run([toybox,"ps","-A","-o","PID,ARGS"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
result["processes"]["toybox"]={"exit":r.returncode,"bridge":[l for l in r.stdout.decode(errors="replace").splitlines() if l.strip().endswith("/var/jb/usr/local/libexec/trollstorelite-srd-bridge.py")],"error":r.stderr.decode()[:300]}
for p in ("/var/jb/bin/ps","/var/jb/usr/bin/ps"):
 if os.path.exists(p):
  r=subprocess.run([p,"-ax","-o","pid=","-o","command="],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  result["processes"][p]={"exit":r.returncode,"bridge":[l for l in r.stdout.decode(errors="replace").splitlines() if l.strip().endswith("/var/jb/usr/local/libexec/trollstorelite-srd-bridge.py")],"error":r.stderr.decode()[:300]}
result["mounts"]=glob.glob("/private/var/run/com.apple.security.cryptexd/mnt/*")
print(json.dumps(result))'''
if __name__=='__main__':
 ensure_device_python()
 parser=argparse.ArgumentParser();parser.add_argument('--udid',required=True);args=parser.parse_args()
 with channel(args.udid) as ssh:
  print(ssh("/var/jb/usr/bin/python3 - <<'PY'\n"+PROGRAM+"\nPY").stdout.decode())
