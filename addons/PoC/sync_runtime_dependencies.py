"""Deploy bridge compatibility dependencies with import validation and backups."""
import argparse,asyncio,base64,hashlib,json,shlex,uuid
from pathlib import Path
from repair_device_connection import HERE,profiles,usb_identity,worker_namespace,atomic_write
from device_python import ensure_device_python

PROGRAM=r'''import base64,hashlib,json,os,pathlib,shutil,subprocess,sys,uuid
request=json.load(sys.stdin)
parent=pathlib.Path("/var/jb/usr/local/libexec")
stage=parent/(".dependencies-"+uuid.uuid4().hex)
stage.mkdir(mode=0o755)
installed=[]
try:
 changes={}
 for name,items in request["packages"].items():
  if name not in ("zero_sky_compat","zero_sky_core"):raise ValueError("Invalid dependency package")
  target=parent/name
  if target.is_symlink():raise SystemExit("Dependency directory cannot be a symlink")
  package=stage/name;package.mkdir(mode=0o755)
  changed=False
  for relative,item in items.items():
   p=pathlib.PurePosixPath(relative)
   if (p.is_absolute() or ".." in p.parts or p.suffix not in (".py",".json",".gpg")):
    raise ValueError("Invalid dependency path")
   raw=base64.b64decode(item["data"],validate=True)
   if hashlib.sha256(raw).hexdigest()!=item["sha256"]:raise ValueError("Dependency hash mismatch")
   if p.suffix==".py":compile(raw,str(p),"exec")
   dest=package/p;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
   with dest.open("xb") as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
   os.chmod(dest,0o644)
   old=target/p
   if old.is_symlink() or not old.is_file() or old.read_bytes()!=raw:changed=True
  current={p.relative_to(target).as_posix() for p in target.rglob('*')
           if p.is_file() and not p.is_symlink() and p.suffix in (".py",".json",".gpg")}
  if current!={str(pathlib.PurePosixPath(p)) for p in items}:changed=True
  changes[name]=changed
 validation=subprocess.run(["/var/jb/usr/bin/python3","-c","import sys;sys.path.insert(0,sys.argv[1]);import zero_sky_compat.integration;from zero_sky_compat.environment import detect;detect();from zero_sky_core.bootsplash import snapshot;from zero_sky_core import control_install_service,sileo_package_service;from zero_sky_core.package_integration import resolve_owner",str(stage)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 if validation.returncode:raise RuntimeError("Dependency validation failed: "+validation.stderr.decode(errors="replace")[-1500:])
 backups=pathlib.Path("/var/jb/var/lib/0-sky/dependency-backups");backups.mkdir(parents=True,exist_ok=True,mode=0o700)
 result={}
 try:
  for name,changed in changes.items():
   target=parent/name;package=stage/name;backup=None
   if changed:
    backup=backups/(name+"-"+uuid.uuid4().hex)
    if target.exists():os.rename(target,backup)
    try:os.rename(package,target)
    except Exception:
     if backup and backup.exists():os.rename(backup,target)
     raise
    installed.append((target,backup))
   result[name]={"changed":changed,"file_count":len(request["packages"][name]),"backup":str(backup) if backup and backup.exists() else None}
 except Exception:
  for target,backup in reversed(installed):
   failed=stage/(target.name+"-failed-"+uuid.uuid4().hex)
   if target.exists():os.rename(target,failed)
   if backup and backup.exists():os.rename(backup,target)
  raise
 print(json.dumps({"changed":any(changes.values()),"import_verified":True,"packages":result}))
finally:shutil.rmtree(stage)
'''

def manifest():
    runtime=HERE.parents[1]/'bridge/DeviceRuntime'
    packages={}
    for name in ('zero_sky_compat','zero_sky_core'):
        source=runtime/name
        files={}
        for path in source.rglob('*'):
            if not path.is_file() or path.suffix not in ('.py','.json','.gpg'):
                continue
            raw=path.read_bytes()
            files[path.relative_to(source).as_posix()]={'data':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}
        if '__init__.py' not in files:
            raise RuntimeError(name+' source is incomplete')
        packages[name]=files
    for required in ('bootsplash.py','control_install_service.py','sileo_package_service.py','package_integration.py'):
        if required not in packages['zero_sky_core']:
            raise RuntimeError('Core source is incomplete: '+required)
    return {'packages':packages}

def sync(namespace):
    result=namespace['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM),input_data=json.dumps(manifest()).encode(),timeout=60)
    return json.loads(result.stdout)

def sync_host_worker(value):
    worker=next(Path(a) for a in value['ProgramArguments'] if a.endswith('/crypstore_worker.py'))
    target=worker.parent/'zero_sky_compat'
    if target.is_symlink():raise RuntimeError('Worker dependency directory cannot be a symlink')
    files=manifest()['packages']['zero_sky_compat']
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
