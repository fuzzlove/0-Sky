#!/usr/bin/env python3
"""Read one SRD's nonsecret 0-Sky startup diagnostics."""
import argparse
import json
import shlex

from repair_device_connection import profiles, worker_namespace

PROGRAM = r'''import glob,json,pathlib,subprocess
label='com.liquidskysecurity.0sky-bootsplash'
helpers=glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd')+glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd')
helper=helpers[0] if len(helpers)==1 else '/var/jb/usr/bin/launchctl'
job=subprocess.run([helper,'print','system/'+label],capture_output=True,text=True,timeout=8)
log=pathlib.Path('/var/jb/var/log/0sky/bootsplash.jsonl')
rows=[]
if log.is_file():
 for line in log.read_text(errors='replace').splitlines()[-10:]:
  try:
   value=json.loads(line)
   if 'bootsplash launcher ' in value.get('message',''):
    rows.append({'timestamp':value.get('timestamp'),'message':value.get('message'),
                 'fields':value.get('fields')})
  except ValueError:pass
processes=subprocess.run(['/bin/ps','-axo','pid=,command='],capture_output=True,text=True,timeout=8)
link=[x.strip() for x in processes.stdout.splitlines()
      if x.strip().split()[-1].endswith('/ZeroSky')]
print(json.dumps({'job_loaded':job.returncode==0,'job_last_exit':next((x.strip() for x in job.stdout.splitlines() if 'last exit code' in x),None),
 'link_processes':link[:2],'events':rows[-5:]}))'''

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--instance-name')
    args = parser.parse_args()
    result = worker_namespace(profiles(instance_name=args.instance_name)[args.udid][1])['ssh'](
        '/var/jb/usr/bin/python3 -c ' + shlex.quote(PROGRAM), timeout=20)
    print(json.dumps(json.loads(result.stdout), indent=2))
