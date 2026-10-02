"""Verify and remove only the temporary installer verification artifacts."""
import argparse,asyncio,json,shlex
from repair_device_connection import HERE,profiles,usb_identity,worker_namespace,atomic_write
from device_python import ensure_device_python

PROGRAM=r'''import http.client,json,pathlib,plistlib,subprocess,time
package='com.liquidsky.install-check';bundle='com.liquidsky.InstallCheck'
marker=pathlib.Path('/var/jb/usr/share/0-sky-install-check/marker.txt')
proof={'deb_marker':marker.read_text() if marker.exists() else None}
listing=subprocess.run(['/var/jb/usr/bin/uicache','-l'],capture_output=True,text=True,timeout=30)
proof['app_registration']=[s for s in listing.stdout.splitlines() if s.startswith(bundle+' : ')]
if proof['deb_marker']!='DEB installation verified\n' or len(proof['app_registration'])!=1:
 raise SystemExit('Fixture postconditions missing; refusing cleanup without evidence')
app=pathlib.Path(proof['app_registration'][0].split(' : ',1)[1])
info=plistlib.loads((app/'Info.plist').read_bytes())
if info.get('CFBundleIdentifier')!=bundle:raise SystemExit('Fixture app identity mismatch')
token=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
c=http.client.HTTPConnection('127.0.0.1',48654,timeout=300)
c.request('POST','/v1/trollstore',json.dumps({'arguments':['uninstall',bundle]}),{'Content-Type':'application/json','X-TrollStore-Bridge-Token':token})
r=c.getresponse();value=json.loads(r.read(1048576));c.close()
proof['app_removal']={'http_status':r.status,**value}
if value.get('status')!=0:raise SystemExit(json.dumps(proof))
# The Control package removal route accepts tweaks only; this fixture is data.
result=subprocess.run(['/var/jb/usr/bin/dpkg','--remove',package],capture_output=True,text=True,timeout=60)
proof['deb_removal']={'status':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
if result.returncode:raise SystemExit(json.dumps(proof))
listing=subprocess.run(['/var/jb/usr/bin/uicache','-l'],capture_output=True,text=True,timeout=30)
proof['fixtures_absent']=not marker.exists() and not any(s.startswith(bundle+' : ') for s in listing.stdout.splitlines())
print(json.dumps(proof))
'''

if __name__=='__main__':
 ensure_device_python();p=argparse.ArgumentParser(description=__doc__);p.add_argument('--udid',required=True);a=p.parse_args()
 asyncio.run(usb_identity(a.udid));_,value=profiles()[a.udid]
 result=worker_namespace(value)['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(PROGRAM),timeout=400)
 report={'udid':a.udid,**json.loads(result.stdout)}
 atomic_write(HERE/'installer-verification/cleanup-result.json',json.dumps(report,indent=2).encode())
 print(json.dumps(report,indent=2));raise SystemExit(0 if report['fixtures_absent'] else 2)
