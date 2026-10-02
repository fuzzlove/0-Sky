"""Persist an exact-device USB route after proving a recovery SSH service."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import subprocess
import time
import uuid
from repair_device_connection import atomic_write, profiles, HERE
from recovery_ssh import channel
from device_python import ensure_device_python

def restart(path):
    value=plistlib.loads(path.read_bytes())
    target=f"gui/{os.getuid()}/{value['Label']}"
    subprocess.run(['/bin/launchctl','bootout',target],capture_output=True,timeout=15)
    deadline=time.monotonic()+15
    while subprocess.run(['/bin/launchctl','print',target],capture_output=True,timeout=5).returncode==0:
        if time.monotonic()>deadline: raise RuntimeError('Service did not unload')
        time.sleep(.2)
    result=subprocess.run(['/bin/launchctl','bootstrap',f'gui/{os.getuid()}',str(path)],capture_output=True,timeout=20)
    if result.returncode: raise RuntimeError('Service restart failed: '+result.stderr.decode()[:500])

def configure(udid, instance_name=None, remote_port=22024):
    remote_port=str(int(remote_port))
    with channel(udid,instance_name,int(remote_port)) as ssh:
        if ssh('id -u').stdout.strip()!=b'0': raise RuntimeError('Recovery server is not root')
    worker,value=profiles(instance_name=instance_name)[udid]
    env=value['EnvironmentVariables']
    port=env['CRYPSTORE_DEVICE_PORT']
    config=Path(env['CRYPSTORE_INSTANCE_DIR'])/'config.json'
    changes={}
    matches=[]
    for path in worker.parent.glob('com.liquidskysecurity.crypstore-usbmux.*.plist'):
        tunnel=plistlib.loads(path.read_bytes())
        args=tunnel.get('ProgramArguments',[])
        if (args[1:5]==['-s','127.0.0.1','-u',udid] and len(args)==6 and
                args[5].split(':',1)[0]==port):
            matches.append(path)
            tunnel['ProgramArguments'][-1]=port+':'+remote_port
            tunnel.setdefault('EnvironmentVariables',{})['CRYPSTORE_DEVICE_REMOTE_PORT']=remote_port
            changes[path]=plistlib.dumps(tunnel)
    if len(matches)!=1: raise RuntimeError('Expected one exact-device persistent USB job')
    env['CRYPSTORE_DEVICE_REMOTE_PORT']=remote_port
    updated=plistlib.dumps(value)
    if updated!=worker.read_bytes(): changes[worker]=updated
    data=json.loads(config.read_bytes())
    if data.get('udid')!=udid: raise RuntimeError('Profile identity mismatch')
    data['ssh_remote_port']=remote_port
    encoded=(json.dumps(data,indent=2,sort_keys=True)+'\n').encode()
    if encoded!=config.read_bytes(): changes[config]=encoded
    if not changes: return {'changed':False,'remote_port':int(remote_port)}
    backup=HERE/'connection-repair'/('route-before-'+uuid.uuid4().hex)
    backup.mkdir(mode=0o700)
    originals={p:p.read_bytes() for p in changes}
    for i,(p,raw) in enumerate(originals.items()): atomic_write(backup/(str(i)+'-'+p.name),raw)
    atomic_write(backup/'index.json',json.dumps([str(p) for p in changes]).encode())
    try:
        for p,raw in changes.items(): atomic_write(p,raw)
        restart(matches[0]);restart(worker)
    except Exception:
        for p,raw in originals.items(): atomic_write(p,raw)
        restart(matches[0]);restart(worker)
        raise
    return {'changed':True,'remote_port':int(remote_port),'backup':str(backup)}

if __name__=='__main__':
    ensure_device_python()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid',required=True)
    parser.add_argument('--instance-name')
    parser.add_argument('--remote-port',type=int,default=22024)
    args=parser.parse_args()
    print(json.dumps(configure(args.udid,args.instance_name,args.remote_port),indent=2))
