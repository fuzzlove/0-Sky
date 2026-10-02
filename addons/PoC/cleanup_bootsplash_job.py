#!/usr/bin/env python3
"""Remove only the superseded 0-Sky-managed splash plist from an SRD."""
import argparse
import json
import shlex

from repair_device_connection import profiles, worker_namespace

PROGRAM = r'''import glob,json,pathlib,plistlib,subprocess
label='com.liquidskysecurity.0sky-bootsplash'
path=pathlib.Path('/var/jb/Library/LaunchDaemons/'+label+'.plist')
if not path.exists():
 print(json.dumps({'removed':False,'reason':'absent'}));raise SystemExit(0)
if path.is_symlink():raise SystemExit('Refusing symbolic-link job')
job=plistlib.loads(path.read_bytes())
if job.get('Label')!=label or job.get('0SkyManaged') is not True or job.get('ProgramArguments')!=['/var/jb/usr/bin/python3','/var/jb/usr/local/libexec/bootsplash-launch.py']:
 raise SystemExit('Refusing to remove nonmatching job')
helpers=glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd')+glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd')
helper=helpers[0] if len(helpers)==1 else '/var/jb/usr/bin/launchctl'
loaded=subprocess.run([helper,'print','system/'+label],capture_output=True,timeout=8).returncode==0
if loaded:
 result=subprocess.run([helper,'bootout','system/'+label],capture_output=True,timeout=12)
 if result.returncode:raise SystemExit('Managed job unload failed')
path.unlink()
print(json.dumps({'removed':True,'was_loaded':loaded}))'''

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    args = parser.parse_args()
    namespace = worker_namespace(profiles()[args.udid][1])
    result = namespace['ssh']('/var/jb/usr/bin/python3 -c ' + shlex.quote(PROGRAM),
                              timeout=25)
    print(json.dumps({'udid': args.udid, **json.loads(result.stdout)}, indent=2))
