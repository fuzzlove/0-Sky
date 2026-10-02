"""Replace an ABI-broken Procursus launchctl with the mounted SRD helper."""
import argparse
import asyncio
import json
import shlex

from device_python import ensure_device_python
from repair_device_connection import profiles, usb_identity, worker_namespace


EXPECTED_HELPER_SHA256 = 'a2d095b681cd4bf1ac819a7052b5b376516ed663bd989edc60d25297fa1e9bbc'
PROGRAM = r'''import glob, hashlib, json, os, pathlib, shutil, subprocess, sys
expected=sys.argv[1]
target=pathlib.Path('/var/jb/usr/bin/launchctl')
helpers=glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd')+glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd')
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
def check(path):
 version=subprocess.run([str(path),'version'],capture_output=True,timeout=8)
 if version.returncode or b'Darwin Bootstrapper Version' not in version.stdout:return False
 print_job=subprocess.run([str(path),'print','system/com.liquidskysecurity.trollstorelite-srd-bridge'],capture_output=True,timeout=8)
 return print_job.returncode==0
valid=[pathlib.Path(p) for p in helpers if sha(p)==expected and check(p)]
if len(valid)!=1:raise SystemExit('Expected exactly one mounted, healthy trusted launch helper')
helper=valid[0]
if target.is_symlink() or not target.is_file():raise SystemExit('Unexpected launchctl path')
before=sha(target)
if before==expected:
 if not check(target):raise SystemExit('Current helper bytes do not function')
 print(json.dumps({'changed':False,'sha256':before,'helper':str(helper)}));raise SystemExit(0)
backup=target.with_name('launchctl.0sky-backup-'+before[:16])
if backup.exists():
 if backup.is_symlink() or sha(backup)!=before:raise SystemExit('Backup collision')
else:
 shutil.copy2(target,backup)
 if sha(backup)!=before:raise SystemExit('Backup verification failed')
stat=target.stat();tmp=target.with_name('launchctl.0sky-new-'+str(os.getpid()))
try:
 with open(helper,'rb') as source,open(tmp,'xb') as dest:shutil.copyfileobj(source,dest,1024*1024)
 os.chmod(tmp,stat.st_mode & 0o7777);os.chown(tmp,stat.st_uid,stat.st_gid)
 if sha(tmp)!=expected:raise RuntimeError('Copied helper differs from mounted trusted code')
 os.replace(tmp,target)
 if not check(target):raise RuntimeError('Replacement failed version or existing service check')
 print(json.dumps({'changed':True,'sha256':sha(target),'backup':str(backup),'backup_sha256':before,'helper':str(helper),'existing_bridge_job_alive':True}))
except BaseException:
 if target.exists() and sha(target)==expected and backup.exists() and sha(backup)==before:
  shutil.copy2(backup,tmp);os.replace(tmp,target)
  if sha(target)!=before:raise RuntimeError('Launchctl rollback verification failed')
 raise
finally:
 if tmp.exists():tmp.unlink()
'''


if __name__ == '__main__':
    ensure_device_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    args = parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _, profile = profiles()[args.udid]
    command = '/var/jb/usr/bin/python3 -c ' + shlex.quote(PROGRAM) + ' ' + shlex.quote(EXPECTED_HELPER_SHA256)
    result = worker_namespace(profile)['ssh'](command, timeout=90)
    print(json.dumps(json.loads(result.stdout), indent=2))
