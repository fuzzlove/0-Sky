"""Device-side TrollRecorder launchd service reconciliation program."""

PROGRAM = r'''import glob,hashlib,json,os,pathlib,plistlib,re,subprocess,sys,time
bundle_id,registered_app,cryptex_app=sys.argv[1:]
if bundle_id!='wiki.qaq.trapp':raise SystemExit('Unexpected bundle')
label='wiki.qaq.trservices';service='wiki.qaq.trapp.xpc'
app=pathlib.Path(registered_app);container=app.parent
if app.is_symlink() or container.is_symlink() or container.parent!=pathlib.Path('/private/var/containers/Bundle/Application'):
 raise SystemExit('Unsafe MCM app path')
with (app/'Info.plist').open('rb') as f:info=plistlib.load(f)
with (container/'.com.apple.mobile_container_manager.metadata.plist').open('rb') as f:metadata=plistlib.load(f)
marker=container/'_TrollStore'
if info.get('CFBundleIdentifier')!=bundle_id or info.get('CFBundleExecutable')!='TRApp' or metadata.get('MCMMetadataIdentifier')!=bundle_id or marker.is_symlink() or not marker.is_file() or marker.stat().st_size!=0:
 raise SystemExit('TrollRecorder MCM ownership verification failed')
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
binary=app/'TRCallMonitor';mounted=pathlib.Path(cryptex_app)/'TRCallMonitor'
if not binary.is_file() or sha(binary)!=sha(mounted):raise SystemExit('Daemon differs from authorized Cryptex')
expected_helper='a2d095b681cd4bf1ac819a7052b5b376516ed663bd989edc60d25297fa1e9bbc'
helpers=glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd')+glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd')
trusted=[p for p in helpers if sha(p)==expected_helper]
if len(trusted)==1:ctl=trusted[0]
else:
 ctl='/var/jb/usr/bin/launchctl'
 if sha(ctl)!=expected_helper:raise SystemExit('No trusted SRD launchctl helper')
version=subprocess.run([ctl,'version'],capture_output=True,timeout=8)
if version.returncode:raise SystemExit('SRD launchctl helper cannot start')
plist=pathlib.Path('/var/jb/Library/LaunchDaemons/'+label+'.plist')
data={'Label':label,'ProgramArguments':[str(binary)],'UserName':'root','RunAtLoad':True,'KeepAlive':False,'MachServices':{service:True},'0SkyManaged':True}
def job():
 result=subprocess.run([ctl,'print','system/'+label],capture_output=True,timeout=8)
 text=result.stdout.decode(errors='replace')
 path=re.search(r'^\s*program = (.+)$',text,re.M)
 pid=re.search(r'^\s*pid = ([0-9]+)$',text,re.M)
 return {'loaded':result.returncode==0,'program':path.group(1).strip() if path else None,'pid':int(pid.group(1)) if pid else None}
def save(payload):
 temporary=plist.with_name(plist.name+'.0sky-'+str(os.getpid()))
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
 try:
  with os.fdopen(fd,'wb') as f:f.write(payload);f.flush();os.fsync(f.fileno())
  os.replace(temporary,plist)
 finally:
  if temporary.exists():temporary.unlink()
old=plist.read_bytes() if plist.exists() else None
old_data=plistlib.loads(old) if old else None
if old_data and (old_data.get('Label')!=label or not (old_data.get('0SkyManaged') is True or old_data.get('0SkyTest') is True)):
 if old_data.get('ProgramArguments')==[str(binary)] and job()['pid']:
  print(json.dumps({'vendor_job_healthy':True,'job':job()}));raise SystemExit(0)
 raise SystemExit('Existing vendor daemon job is not managed by 0-Sky')
before=job()
if before['program']==str(binary) and before['pid']:
 if old_data!=data:save(plistlib.dumps(data))
 print(json.dumps({'action':'promoted' if old_data!=data else 'unchanged','job':job(),'plist':str(plist)}));raise SystemExit(0)
changed=False
try:
 if before['loaded']:
  stopped=subprocess.run([ctl,'bootout','system/'+label],capture_output=True,timeout=12)
  if stopped.returncode:raise RuntimeError('Could not retire prior TrollRecorder job: '+stopped.stderr.decode(errors='replace')[-350:])
 save(plistlib.dumps(data));changed=True
 started=subprocess.run([ctl,'bootstrap','system',str(plist)],capture_output=True,timeout=12)
 if started.returncode:raise RuntimeError('Could not bootstrap TrollRecorder: '+started.stderr.decode(errors='replace')[-350:])
 current={}
 for _ in range(16):
  time.sleep(.5);current=job()
  if current['program']==str(binary) and current['pid']:break
 if current.get('program')!=str(binary) or not current.get('pid'):raise RuntimeError('TrollRecorder daemon did not stay running')
 print(json.dumps({'action':'created' if old is None else 'replaced','job':current,'plist':str(plist)}))
except BaseException:
 if changed:
  subprocess.run([ctl,'bootout','system/'+label],capture_output=True,timeout=12)
  if old is None:
   if plist.exists():plist.unlink()
  else:
   save(old)
   if before['loaded']:subprocess.run([ctl,'bootstrap','system',str(plist)],capture_output=True,timeout=12)
 raise
'''
