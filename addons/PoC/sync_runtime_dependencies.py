"""Deploy bridge compatibility dependencies with import validation and backups."""
import argparse,asyncio,base64,hashlib,json,shlex,uuid
from pathlib import Path
from repair_device_connection import HERE,profiles,usb_identity,worker_namespace,atomic_write
from device_python import ensure_device_python

PROGRAM=r'''import base64,hashlib,json,os,pathlib,shutil,subprocess,sys,uuid
request=json.load(sys.stdin)
parent=pathlib.Path("/var/jb/usr/local/libexec")
name="zero_sky_compat"
target=parent/name
stage=parent/(".dependencies-"+uuid.uuid4().hex)
if target.is_symlink():raise SystemExit("Dependency directory cannot be a symlink")
stage.mkdir(mode=0o755)
package=stage/name;package.mkdir(mode=0o755)
try:
 changed=False
 for relative,item in request["files"].items():
  p=pathlib.PurePosixPath(relative)
  if p.is_absolute() or ".." in p.parts or p.suffix!=".py":raise ValueError("Invalid dependency path")
  raw=base64.b64decode(item["data"],validate=True)
  if hashlib.sha256(raw).hexdigest()!=item["sha256"]:raise ValueError("Dependency hash mismatch")
  compile(raw,str(p),"exec")
  dest=package/p;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
  with dest.open("xb") as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
  os.chmod(dest,0o644)
  old=target/p
  if old.is_symlink() or not old.is_file() or old.read_bytes()!=raw:changed=True
 validation=subprocess.run(["/var/jb/usr/bin/python3","-c","import sys;sys.path.insert(0,sys.argv[1]);import zero_sky_compat.integration;from zero_sky_compat.environment import detect;detect()",str(stage)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 if validation.returncode:raise RuntimeError("Dependency validation failed: "+validation.stderr.decode(errors="replace")[-1500:])
 backup=None
 if changed:
  backups=pathlib.Path("/var/jb/var/lib/0-sky/dependency-backups");backups.mkdir(parents=True,exist_ok=True,mode=0o700)
  backup=backups/(name+"-"+uuid.uuid4().hex)
  if target.exists():os.rename(target,backup)
  try:os.rename(package,target)
  except Exception:
   if backup.exists():os.rename(backup,target)
   raise
 print(json.dumps({"changed":changed,"import_verified":True,"file_count":len(request["files"]),"backup":str(backup) if backup and backup.exists() else None}))
finally:shutil.rmtree(stage)
'''

def manifest():
    source=HERE.parents[1]/'bridge/DeviceRuntime/zero_sky_compat'
    files={}
    for path in source.rglob('*.py'):
        raw=path.read_bytes()
        files[path.relative_to(source).as_posix()]={'data':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}
    if '__init__.py' not in files or 'integration.py' not in files:raise RuntimeError('Compatibility source is incomplete')
    return {'files':files}

def sync(namespace):
    result=namespace['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM),input_data=json.dumps(manifest()).encode(),timeout=60)
    return json.loads(result.stdout)

def sync_host_worker(value):
    worker=next(Path(a) for a in value['ProgramArguments'] if a.endswith('/crypstore_worker.py'))
    target=worker.parent/'zero_sky_compat'
    if target.is_symlink():raise RuntimeError('Worker dependency directory cannot be a symlink')
    files=manifest()['files']
    if target.is_dir() and all((target/p).is_file() and not (target/p).is_symlink() and hashlib.sha256((target/p).read_bytes()).hexdigest()==item['sha256'] for p,item in files.items()):
        return {'changed':False}
    stage=worker.parent/('.dependencies-'+uuid.uuid4().hex);stage.mkdir(mode=0o700)
    for p,item in files.items():
        dest=stage/p;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        atomic_write(dest,base64.b64decode(item['data']))
    backup=worker.parent/('zero_sky_compat.before-'+uuid.uuid4().hex)
    if target.exists():target.rename(backup)
    try:stage.rename(target)
    except Exception:
        if backup.exists():backup.rename(target)
        raise
    return {'changed':True,'backup':str(backup) if backup.exists() else None}

if __name__=='__main__':
    ensure_device_python()
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--udid',required=True);args=parser.parse_args()
    asyncio.run(usb_identity(args.udid));_,value=profiles()[args.udid]
    device=sync(worker_namespace(value));host=sync_host_worker(value)
    print(json.dumps({'udid':args.udid,'device':device,'host_worker':host},indent=2))
