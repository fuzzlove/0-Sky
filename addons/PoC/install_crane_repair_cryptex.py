#!/usr/bin/env python3
"""Install the reviewed paid Crane v2 adapter through a transactional SRD job."""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, plistlib, shutil, sys, tempfile
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
PACKAGE=ROOT/'converted/crane-paid-ios27/com.opa334.crane_1.3.9+0sky8_iphoneos-arm64.deb'
BRIDGE=ROOT/'bridge/DeviceRuntime/trollstorelite-srd-bridge.py'
MANAGER=ROOT/'bridge/0SkyBridge/Resources/Scripts/kit/automation/tools/srd-runtime-manager/srd_runtime_manager.py'
LAUNCHCTL=HERE/'localfence-repair-v2/runtime-root/usr/bin/launchctl-srd'
KIT=HERE/'srdsh-work/components/zero-sky/kit/srdssh/payload-root'
INSTALLER=ROOT/'bridge/KitScripts/runtime-generation'
IDENTIFIER='com.liquidsky.crane.repair8'
VERSION='1.0.0'

def sha(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()

DEVICE_PROGRAM=r'''import hashlib,importlib.util,json,os,pathlib,plistlib,re,shutil,stat,subprocess,time,traceback
M=pathlib.Path(os.environ['CRYPTEX_MOUNT_PATH'])
PKG=M/'share/crane-0sky8.deb';NEW_BRIDGE=M/'share/trollstorelite-srd-bridge.py';NEW_MANAGER=M/'share/srd-runtime-manager.py'
BRIDGE=pathlib.Path('/var/jb/usr/local/libexec/trollstorelite-srd-bridge.py')
MANAGER=pathlib.Path('/var/jb/usr/local/libexec/srd-runtime-manager.py')
REPORT=pathlib.Path('/var/jb/var/log/0sky-crane-repair8.json');PAUSE=pathlib.Path('/var/mobile/pl/srd-runtime-paused')
PACKAGE='com.opa334.crane';LABEL='com.liquidskysecurity.trollstorelite-srd-bridge'
RUNTIME_LABEL='user/501/codes.openai.research.preferenceloader-monitor'
CTL=M/'usr/bin/launchctl-srd';JOB=pathlib.Path('/var/jb/Library/LaunchDaemons/'+LABEL+'.plist')
EXPECTED=json.loads((M/'share/expected.json').read_text())
ENV=os.environ.copy();ENV['PATH']=('/var/jb/usr/local/bin:/var/jb/usr/bin:/var/jb/bin:'
 '/var/jb/usr/sbin:/var/jb/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin')
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def run(a,timeout=120,check=True):
 p=subprocess.run([str(x) for x in a],env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
 if check and p.returncode:raise RuntimeError(pathlib.Path(str(a[0])).name+' failed: '+p.stderr.decode(errors='replace')[-1000:])
 return p
def atomic(path,data,mode,uid=0,gid=0):
 tmp=path.with_name('.'+path.name+'.0sky-repair8')
 if tmp.exists():tmp.unlink()
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
 try:
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.chown(tmp,uid,gid);os.chmod(tmp,mode);os.replace(tmp,path)
 finally:
  if tmp.exists():tmp.unlink()
def module_at(path,name):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def launch_pid(label):
 p=run([CTL,'print',label],timeout=10,check=False)
 if p.returncode:return None
 m=re.search(rb'\bpid\s*=\s*(\d+)',p.stdout)
 return int(m.group(1)) if m else None
def restart_runtime_manager():
 before=launch_pid(RUNTIME_LABEL)
 p=run([CTL,'kickstart','-k',RUNTIME_LABEL],timeout=20,check=False)
 if p.returncode:raise RuntimeError('runtime manager kickstart failed: '+p.stderr.decode(errors='replace')[-600:])
 for _ in range(80):
  now=launch_pid(RUNTIME_LABEL)
  if now and now!=before:return {'before_pid':before,'after_pid':now}
  time.sleep(.25)
 raise RuntimeError('runtime manager did not restart into the transaction-safe build')
def restart_bridge():
 if not JOB.is_file() or JOB.is_symlink():raise RuntimeError('exact Bridge launch job is unavailable')
 job=plistlib.loads(JOB.read_bytes())
 if job.get('Label')!=LABEL or job.get('ProgramArguments')!=['/var/jb/usr/bin/python3',str(BRIDGE)]:raise RuntimeError('Bridge launch contract differs')
 loaded=run([CTL,'print','system/'+LABEL],timeout=10,check=False)
 if loaded.returncode==0:run([CTL,'bootout','system/'+LABEL],timeout=20)
 run([CTL,'bootstrap','system',JOB],timeout=20)
 for _ in range(30):
  try:
   import http.client
   c=http.client.HTTPConnection('127.0.0.1',48654,timeout=2);c.request('GET','/health');r=c.getresponse();data=json.loads(r.read(65536));c.close()
   if r.status==200 and data.get('ok') is True:return True
  except Exception:pass
  time.sleep(.25)
 raise RuntimeError('Bridge health probe failed after restart')
for path,key in ((PKG,'package'),(NEW_BRIDGE,'bridge'),(NEW_MANAGER,'manager'),(CTL,'launchctl')):
 if not path.is_file() or path.is_symlink() or digest(path)!=EXPECTED[key]:raise SystemExit('sealed repair input mismatch: '+key)
if (not BRIDGE.is_file() or BRIDGE.is_symlink() or not MANAGER.is_file() or MANAGER.is_symlink()):raise SystemExit('existing device runtime is unavailable')
original_bridge=BRIDGE.read_bytes();bridge_metadata=BRIDGE.stat();original_manager=MANAGER.read_bytes();manager_metadata=MANAGER.stat()
result={'status':'STARTED','package':PACKAGE,'started':time.time(),'transaction_committed':False}
REPORT.parent.mkdir(parents=True,exist_ok=True)
PAUSE.parent.mkdir(parents=True,exist_ok=True);PAUSE.touch(mode=0o600,exist_ok=True)
try:
 atomic(MANAGER,NEW_MANAGER.read_bytes(),stat.S_IMODE(manager_metadata.st_mode),manager_metadata.st_uid,manager_metadata.st_gid)
 atomic(BRIDGE,NEW_BRIDGE.read_bytes(),stat.S_IMODE(bridge_metadata.st_mode),bridge_metadata.st_uid,bridge_metadata.st_gid)
 result['runtime_manager_restart']=restart_runtime_manager()
 installed=run(['/var/jb/usr/bin/dpkg','--install',PKG],timeout=300)
 run(['/var/jb/usr/bin/apt-get','check','-o','Dpkg::Use-Pty=0'],timeout=120)
 expected_files={
  '/var/jb/usr/local/bin/cranehelperd_start':EXPECTED['starter'],
  '/var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSupport.dylib':EXPECTED['support'],
  '/var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSB.dylib':EXPECTED['springboard'],
  '/var/jb/usr/lib/libcrane.dylib':EXPECTED['libcrane'],
 }
 for raw,expected in expected_files.items():
  p=pathlib.Path(raw)
  if not p.is_file() or p.is_symlink() or digest(p)!=expected:raise RuntimeError('installed Crane file mismatch: '+raw)
 manifest=json.loads(pathlib.Path('/var/jb/usr/share/0-sky/package-adapters/com.opa334.crane.json').read_text())
 if manifest.get('adapter')!='crane-family-v2':raise RuntimeError('Crane v2 adapter manifest is absent')
 validation=run(['/var/jb/usr/bin/python3','-c','import runpy,sys;runpy.run_path(sys.argv[1],run_name="bridge_validation")',BRIDGE],timeout=30)
 bridge=module_at(BRIDGE,'osky_bridge_repair8')
 payload=bridge.package_payload(PACKAGE)
 service=bridge.activate_package_adapter(PACKAGE,payload)
 if service.get('result')!='PASS':raise RuntimeError('Crane helper service verification failed')
 run(['/var/jb/usr/bin/python3',MANAGER,'clear-quarantine','--package',PACKAGE],timeout=30)
 PAUSE.unlink(missing_ok=True)
 run(['/var/jb/usr/bin/python3',MANAGER,'sync'],timeout=30)
 runtime=bridge.tweak_runtime_validation(PACKAGE,payload,timeout=55)
 if runtime.get('result')=='FAIL':raise RuntimeError('Crane runtime verification failed: '+str(runtime.get('detail'))[:500])
 result.update(status='INSTALLED_AND_VERIFIED',transaction_committed=True,service=service,runtime=runtime,
  package_sha256=digest(PKG),bridge_sha256=digest(BRIDGE),starter_sha256=EXPECTED['starter'])
 atomic(REPORT,(json.dumps(result,indent=2,sort_keys=True)+'\n').encode(),0o600)
 restart_bridge();result['bridge_health']=True
 atomic(REPORT,(json.dumps(result,indent=2,sort_keys=True)+'\n').encode(),0o600)
except BaseException as error:
 result.update(status='FAILED_REPAIR_REQUIRED',error=type(error).__name__+': '+str(error),traceback=traceback.format_exc()[-4000:])
 try:
  PAUSE.unlink(missing_ok=True)
  run(['/var/jb/usr/bin/python3',MANAGER,'sync'],timeout=30,check=False)
  restart_bridge();result['failure_recovery_verified']=True
 except BaseException as recovery_error:
  result['failure_recovery_verified']=False;result['recovery_error']=type(recovery_error).__name__+': '+str(recovery_error)
 atomic(REPORT,(json.dumps(result,indent=2,sort_keys=True)+'\n').encode(),0o600)
'''

def build(work:Path)->Path:
    for p in (PACKAGE,BRIDGE,MANAGER,LAUNCHCTL):
        if not p.is_file():raise FileNotFoundError(p)
    root=work/'root';(root/'usr/bin').mkdir(parents=True);(root/'share').mkdir();(root/'Library/LaunchDaemons').mkdir(parents=True)
    for name in ('toybox','cryptex-run'):
        shutil.copy2(KIT/'usr/bin'/name,root/'usr/bin'/name)
    shutil.copy2(LAUNCHCTL,root/'usr/bin/launchctl-srd')
    shutil.copy2(PACKAGE,root/'share/crane-0sky8.deb');shutil.copy2(BRIDGE,root/'share/trollstorelite-srd-bridge.py');shutil.copy2(MANAGER,root/'share/srd-runtime-manager.py')
    expected={'package':sha(PACKAGE),'bridge':sha(BRIDGE),'manager':sha(MANAGER),'launchctl':sha(LAUNCHCTL),
              'starter':'53a8f431f5c06b89cbcff7e4e4cb846de4481811549b37cce34edf65a616fcd2',
              'support':'1cbd343957156e4668510dc2bff814d37896d028fa9d4a6c0b5b8d1d84f19159',
              'springboard':'2448ee43ab7ebe53322f117d1335171048337f127d9f1a3139b2c48e15badc30',
              'libcrane':'a5a10059a4d9af20d03676d525e8d2cffbe37185227ae0090a9c54ffa7ccd595'}
    (root/'share/expected.json').write_text(json.dumps(expected,sort_keys=True)+'\n')
    (root/'share/repair.py').write_text(DEVICE_PROGRAM)
    start=root/'usr/bin/crane-repair-start';start.write_text('#!/bin/sh\nexec /var/jb/usr/bin/python3 "$CRYPTEX_MOUNT_PATH/share/repair.py" >>/var/jb/var/log/0sky-crane-repair8.stdout.log 2>&1\n');start.chmod(0o755)
    launch={'Label':IDENTIFIER,'ProgramArguments':['/usr/bin/cryptex-run','toybox','sh','-c','exec "$CRYPTEX_MOUNT_PATH/usr/bin/toybox" sh "$CRYPTEX_MOUNT_PATH/usr/bin/crane-repair-start"'],'RunAtLoad':True,'KeepAlive':False,'ProcessType':'Interactive'}
    (root/'Library/LaunchDaemons/crane-repair.plist').write_bytes(plistlib.dumps(launch))
    shutil.copy2(ROOT/'bridge/KitScripts/automation/CrypStoreAutomation/native-install/generate_trust_cache.py',work/'generate_trust_cache.py')
    sys.path.insert(0,str(INSTALLER));from install_cryptex_native import build as build_cryptex
    return Path(build_cryptex(root,IDENTIFIER,VERSION,work))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--udid',required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--build-only',action='store_true');args=ap.parse_args()
    args.output.mkdir(parents=True,mode=0o700)
    manifest=build(args.output)
    record={'identifier':IDENTIFIER,'version':VERSION,'udid':args.udid,'manifest':str(manifest),'package_sha256':sha(PACKAGE)}
    (args.output/'record.json').write_text(json.dumps(record,indent=2)+'\n')
    if not args.build_only:
        sys.path.insert(0,str(INSTALLER));from install_cryptex_native import install
        asyncio.run(install(manifest,IDENTIFIER,args.udid));record['installed']=True
        (args.output/'record.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))
if __name__=='__main__':main()
