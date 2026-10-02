"""Update an existing device bridge with root backups and health rollback."""
import argparse
import base64
import hashlib
import json
import shlex
from pathlib import Path
from repair_device_connection import HERE,profiles,worker_namespace
from device_python import ensure_device_python

PROGRAM=r'''import base64,hashlib,http.client,json,os,pathlib,plistlib,runpy,shutil,stat,subprocess,sys,time,uuid,ctypes,struct,signal,glob
request=json.load(sys.stdin)
path=pathlib.Path("/var/jb/usr/local/libexec/trollstorelite-srd-bridge.py")
if path.is_symlink() or not path.is_file(): raise SystemExit("Bridge must be an existing regular file")
payload=base64.b64decode(request["source"],validate=True)
if hashlib.sha256(payload).hexdigest()!=request["sha256"]: raise SystemExit("Source hash mismatch")
original=path.read_bytes()
if original==payload and not request.get("restart"):
 print(json.dumps({"changed":False,"sha256":request["sha256"]}));raise SystemExit(0)
metadata=path.stat()
backup=pathlib.Path("/var/jb/var/lib/0-sky/bridge-backups")/uuid.uuid4().hex
backup.mkdir(parents=True,mode=0o700)
os.chmod(backup,0o700)
saved=backup/path.name
saved.write_bytes(original);os.chmod(saved,0o600)
candidate=path.with_name(".bridge-update-"+uuid.uuid4().hex+".py")
def write(raw):
 with candidate.open("xb") as stream:
  stream.write(raw);stream.flush();os.fsync(stream.fileno())
 os.chmod(candidate,stat.S_IMODE(metadata.st_mode));os.chown(candidate,metadata.st_uid,metadata.st_gid)
expected=["/var/jb/usr/bin/python3",str(path)]
job_path=pathlib.Path("/var/jb/Library/LaunchDaemons/com.liquidskysecurity.trollstorelite-srd-bridge.plist")
if job_path.is_symlink():raise SystemExit("Bridge job must not be a symlink")
new_job=not job_path.exists()
job=plistlib.loads(job_path.read_bytes()) if not new_job else {
 "Label":"com.liquidskysecurity.trollstorelite-srd-bridge","ProgramArguments":expected,
 "RunAtLoad":True,"KeepAlive":True,"ThrottleInterval":5,"UserName":"root",
 "StandardOutPath":"/var/jb/var/log/0-sky-device-bridge.stdout.log",
 "StandardErrorPath":"/var/jb/var/log/0-sky-device-bridge.stderr.log"}
if job.get("Label")!="com.liquidskysecurity.trollstorelite-srd-bridge" or job.get("ProgramArguments")!=expected or job.get("KeepAlive") is not True:
 raise SystemExit("Bridge must have its exact existing KeepAlive job")
lib=ctypes.CDLL("/usr/lib/libSystem.B.dylib",use_errno=True)
def bridge_pids():
 pids=(ctypes.c_int*8192)();count=lib.proc_listallpids(pids,ctypes.sizeof(pids));found=[]
 if count<0 or count>=len(pids):raise RuntimeError("Process enumeration failed")
 for pid in pids[:count]:
  executable=ctypes.create_string_buffer(4096)
  if lib.proc_pidpath(pid,executable,len(executable))<=0 or b"python" not in executable.value:continue
  mib=(ctypes.c_int*3)(1,49,pid);buf=ctypes.create_string_buffer(65536);size=ctypes.c_size_t(len(buf))
  if lib.sysctl(mib,3,buf,ctypes.byref(size),None,0)!=0:continue
  argc=struct.unpack("i",buf.raw[:4])[0];parts=buf.raw[4:size.value].split(b"\0")
  args=[x.decode(errors="replace") for x in parts[1:] if x][:argc]
  if args==expected:found.append(pid)
 return found
def restart():
 helpers=glob.glob("/private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd")+glob.glob("/private/var/run/com.apple.security.cryptexd/mnt/com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd")
 helper=helpers[0] if len(helpers)==1 else "/var/jb/usr/bin/launchctl"
 if helpers and hashlib.sha256(pathlib.Path(helper).read_bytes()).hexdigest()!=request["helper_sha256"]:
  raise RuntimeError("Installed launch helper hash mismatch")
 version=subprocess.run([helper,"version"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
 if version.returncode:raise RuntimeError("Compatible launch helper is required")
 loaded=subprocess.run([helper,"print","system/com.liquidskysecurity.trollstorelite-srd-bridge"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
 if loaded.returncode==0:
  stopped=subprocess.run([helper,"bootout","system/com.liquidskysecurity.trollstorelite-srd-bridge"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
  if stopped.returncode:raise RuntimeError("Bridge unload failed")
  time.sleep(.5)
 matches=bridge_pids()
 if len(matches)>1:raise RuntimeError("Multiple bridge processes; refusing restart")
 if matches:os.kill(matches[0],signal.SIGTERM)
 for _ in range(40):
  if not bridge_pids():break
  time.sleep(.1)
 else:raise RuntimeError("Old bridge did not stop")
 result=subprocess.run([helper,"bootstrap","system","/var/jb/Library/LaunchDaemons/com.liquidskysecurity.trollstorelite-srd-bridge.plist"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
 if result.returncode:raise RuntimeError("Bridge launch failed: "+result.stderr.decode(errors="replace")[:500])
def healthy():
 for _ in range(40):
  try:
   connection=http.client.HTTPConnection("127.0.0.1",48654,timeout=2)
   connection.request("GET","/health");response=connection.getresponse()
   valid=response.status==200 and json.loads(response.read(65536)).get("ok") is True
   connection.close()
   if valid:return True
  except Exception: pass
  time.sleep(.25)
 return False
write(payload)
try:
 validation=subprocess.run(["/var/jb/usr/bin/python3","-c","import runpy,sys;runpy.run_path(sys.argv[1],run_name='bridge_validation')",str(candidate)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
 if validation.returncode: raise RuntimeError("Bridge validation failed: "+validation.stderr.decode(errors="replace")[:1000])
 if new_job:
  job_path.parent.mkdir(parents=True,exist_ok=True)
  pathlib.Path("/var/jb/var/log").mkdir(parents=True,exist_ok=True)
  with job_path.open("xb") as stream:stream.write(plistlib.dumps(job));stream.flush();os.fsync(stream.fileno())
  os.chmod(job_path,0o644);os.chown(job_path,0,0)
 os.replace(candidate,path)
 try:
  restart()
  if not healthy(): raise RuntimeError("Updated bridge health check failed")
 except Exception:
  write(original);os.replace(candidate,path);restart();raise
finally:
 if candidate.exists():candidate.unlink()
print(json.dumps({"changed":True,"backup":str(saved),"sha256":request["sha256"],"health_verified":True,"created_root_job":new_job}))'''

def update(namespace,force_restart=False):
    source=(HERE.parents[1]/'bridge/DeviceRuntime/trollstorelite-srd-bridge.py').read_bytes()
    helper_hash=json.loads((HERE/'localfence-repair-v2/payload-sha256.json').read_text())['launchctl-srd']
    request=json.dumps({'source':base64.b64encode(source).decode(),'sha256':hashlib.sha256(source).hexdigest(),'helper_sha256':helper_hash,'restart':force_restart}).encode()
    result=namespace['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM),input_data=request,timeout=90)
    return json.loads(result.stdout)

if __name__=='__main__':
    ensure_device_python()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid',required=True)
    parser.add_argument('--instance-name')
    parser.add_argument('--restart',action='store_true')
    args=parser.parse_args()
    _,value=profiles(instance_name=args.instance_name)[args.udid]
    print(json.dumps(update(worker_namespace(value),args.restart),indent=2))
