#!/usr/bin/env python3
"""Stage the reviewed Sileo APT broker on one exact, paired research device."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import shlex

from repair_device_connection import profiles, usb_identity, worker_namespace


ROOT = Path(__file__).resolve().parents[2]
FILES = (
    (ROOT / "bridge/DeviceRuntime/zero_sky_core/apt_source_manifest.json",
     "/var/jb/usr/local/libexec/zero_sky_core/apt_source_manifest.json"),
    (ROOT / "bridge/DeviceRuntime/zero_sky_core/sileo_package_service.py",
     "/var/jb/usr/local/libexec/zero_sky_core/sileo_package_service.py"),
    (ROOT / "bridge/DeviceRuntime/trollstorelite-srd-bridge.py",
     "/var/jb/usr/local/libexec/trollstorelite-srd-bridge.py"),
)
STAGE = r'''import ast,hashlib,json,os,pathlib,stat,sys,tempfile
target=pathlib.Path(sys.argv[1]);digest=sys.argv[2]
payload=sys.stdin.buffer.read()
if len(payload)>1024*1024 or hashlib.sha256(payload).hexdigest()!=digest:raise SystemExit('source hash mismatch')
if target.suffix=='.json':
 data=json.loads(payload)
 if data.get('schema_version')!=1 or not isinstance(data.get('sources'),list):raise SystemExit('source manifest invalid')
else:ast.parse(payload.decode('utf-8'))
if target.is_symlink() or (target.exists() and not target.is_file()):raise SystemExit('target is symbolic or not a file')
if not target.exists() and target.name not in ('sileo_package_service.py','apt_source_manifest.json'):raise SystemExit('existing Bridge target is absent')
old=target.read_bytes() if target.exists() else None
backup=target.with_name(target.name+'.0sky-sileo-prior')
if backup.is_symlink():raise SystemExit('prior UAT backup is symbolic')
if backup.exists() and (not backup.is_file() or backup.stat().st_uid!=0):raise SystemExit('prior UAT backup is unsafe')
if (target.exists() and target.stat().st_uid!=0) or target.parent.stat().st_uid!=0:raise SystemExit('target directory is not root-owned')
fd,name=tempfile.mkstemp(prefix='.0sky-sileo-',dir=target.parent)
try:
 with os.fdopen(fd,'wb') as stream:stream.write(payload);stream.flush();os.fsync(stream.fileno())
 os.chown(name,0,0);os.chmod(name,0o644)
 if old is not None and not backup.exists():backup.write_bytes(old);os.chown(backup,0,0);os.chmod(backup,0o600)
 os.replace(name,target)
finally:
 if os.path.exists(name):os.unlink(name)
print(json.dumps({'result':'STAGED','new_sha256':digest,'old_sha256':hashlib.sha256(old).hexdigest() if old is not None else None}))'''
RESTART = r'''import json,os,signal,subprocess,time
rows=subprocess.check_output(['/bin/ps','-axo','pid=,command='],text=True).splitlines()
expected='/var/jb/usr/bin/python3 /var/jb/usr/local/libexec/trollstorelite-srd-bridge.py'
pids=[]
for row in rows:
 parts=row.strip().split(None,1)
 if len(parts)==2 and parts[1]==expected:pids.append(int(parts[0]))
if len(pids)!=1:raise SystemExit('expected exactly one Bridge process')
os.kill(pids[0],signal.SIGTERM)
time.sleep(3)
print(json.dumps({'result':'RESTART_REQUESTED'}))'''


def run(instance: str, udid: str) -> dict:
    selected = profiles(instance_name=instance)
    device = asyncio.run(usb_identity(udid))
    if udid not in selected or device["udid"] != udid:
        raise RuntimeError("EXACT_USB_PROFILE_MISMATCH")
    worker = worker_namespace(selected[udid][1])
    report = {"device": udid[-8:], "result": "STARTED", "files": []}
    for source, target in FILES:
        data = source.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        command = "/var/jb/usr/bin/python3 -c " + shlex.quote(STAGE) + " " + \
                  shlex.quote(target) + " " + shlex.quote(digest)
        response = worker["ssh"](command, input_data=data, timeout=30, check=False)
        if response.returncode:
            raise RuntimeError("SILEO_BRIDGE_STAGE_FAILED: " +
                               response.stderr.decode(errors="replace")[-200:])
        report["files"].append(json.loads(response.stdout))
    compiled = worker["ssh"](
        "/var/jb/usr/bin/python3 -m py_compile " + " ".join(shlex.quote(target)
         for _, target in FILES if target.endswith('.py')), timeout=20, check=False)
    if compiled.returncode:
        raise RuntimeError("SILEO_BRIDGE_DEVICE_COMPILE_FAILED")
    restart = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(RESTART),
                            timeout=20, check=False)
    if restart.returncode:
        raise RuntimeError("SILEO_BRIDGE_RESTART_FAILED")
    status = worker["ssh"](
        "/var/jb/usr/bin/python3 -c " + shlex.quote(
            "import socket,time\n"
            "for attempt in range(12):\n"
            " try:\n"
            "  connection=socket.create_connection(('127.0.0.1',48654),2);connection.close();print('BRIDGE_PORT_OPEN');break\n"
            " except OSError:\n"
            "  time.sleep(2)\n"
            "else:raise SystemExit('BRIDGE_PORT_UNAVAILABLE')"),
        timeout=30, check=False)
    if status.returncode:
        raise RuntimeError("SILEO_BRIDGE_HEALTHCHECK_FAILED")
    provision = worker["ssh"](
        "/var/jb/usr/bin/python3 /var/jb/usr/local/libexec/trollstorelite-srd-bridge.py "
        "--provision-sileo-bridge", input_data=json.dumps(
            {"udid": udid, "model": device["product"]},
            separators=(",", ":")).encode(), timeout=30, check=False)
    if provision.returncode:
        raise RuntimeError("SILEO_BRIDGE_PROVISION_FAILED: " +
                           provision.stdout.decode(errors="replace")[-200:])
    report.update(result="BROKER_STAGED_AND_AUTHENTICATED",
                  credential=json.loads(provision.stdout).get("result"))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instance")
    parser.add_argument("udid")
    args = parser.parse_args()
    print(json.dumps(run(args.instance, args.udid), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
