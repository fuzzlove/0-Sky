"""Restore installer ownership metadata for a verified SRD-managed container."""
import argparse,asyncio,json,shlex
from repair_device_connection import HERE,profiles,usb_identity,worker_namespace,atomic_write
from device_python import ensure_device_python

PROGRAM=r'''import glob,hashlib,json,os,pathlib,plistlib,subprocess,sys
mode=sys.argv[1];bundle='wiki.qaq.trapp'
listing=subprocess.run(['/var/jb/usr/bin/uicache','-l'],capture_output=True,text=True,timeout=30)
matches=[s.split(' : ',1)[1] for s in listing.stdout.splitlines() if s.startswith(bundle+' : ')]
if len(matches)!=1:raise SystemExit('Ambiguous app container')
app=pathlib.Path(matches[0]);container=app.parent
if app.is_symlink() or container.is_symlink() or container.parent!=pathlib.Path('/private/var/containers/Bundle/Application'):
 raise SystemExit('Unexpected app container')
info=plistlib.loads((app/'Info.plist').read_bytes());metadata=plistlib.loads((container/'.com.apple.mobile_container_manager.metadata.plist').read_bytes())
if info.get('CFBundleIdentifier')!=bundle or metadata.get('MCMMetadataIdentifier')!=bundle:raise SystemExit('Container identity mismatch')
state=json.loads(pathlib.Path('/var/jb/var/lib/crypstore/'+bundle+'.json').read_text())
identifier=state.get('cryptex_identifier')
if identifier!='codes.rambo.research.crypstore.1a1bde13d647efdf':raise SystemExit('Not the SRD-managed generation')
mounts=glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/'+identifier+'.*/Applications/TRApp.app/TRApp')
main=app/'TRApp'
if len(mounts)!=1 or hashlib.sha256(main.read_bytes()).digest()!=hashlib.sha256(pathlib.Path(mounts[0]).read_bytes()).digest():
 raise SystemExit('Installed code differs from authorized Cryptex')
marker=container/'_TrollStore';existed=marker.exists()
if marker.is_symlink():raise SystemExit('Unsafe ownership marker')
if existed and marker.read_bytes()!=b'':raise SystemExit('Unexpected marker contents')
if mode=='apply' and not existed:
 fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644);os.close(fd)
 stat=container.stat();os.chown(marker,stat.st_uid,stat.st_gid)
if mode=='remove' and existed:marker.unlink()
print(json.dumps({'container':str(container),'marker':str(marker),'marker_existed':existed,'marker_exists':marker.exists(),'created':mode=='apply' and not existed,'removed':mode=='remove' and existed,'authorized_code_matches':True}))
'''

if __name__=='__main__':
 ensure_device_python();p=argparse.ArgumentParser();p.add_argument('--udid',required=True);group=p.add_mutually_exclusive_group();group.add_argument('--apply',action='store_true');group.add_argument('--remove',action='store_true');a=p.parse_args()
 asyncio.run(usb_identity(a.udid));_,value=profiles()[a.udid]
 mode='apply' if a.apply else 'remove' if a.remove else 'inspect'
 r=worker_namespace(value)['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM)+' '+mode,timeout=45)
 report={'udid':a.udid,**json.loads(r.stdout)}
 atomic_write(HERE/'installer-verification/trollrecorder-marker.json',json.dumps(report,indent=2).encode());print(json.dumps(report,indent=2))
