#!/usr/bin/env python3
"""Controlled Doodle lock-screen runtime trial on one paired SRD.

Only the boolean enabled preference is changed. Pattern and credential data
stay on the device and are never included in reports or SSH output.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import shlex
import sys
import time

from repair_device_connection import profiles, usb_identity, worker_namespace


EXPECTED_VERSION = "1:1.1+0sky27.2"
EXPECTED_DYLIB_SHA256 = "64eae513d7a96e691ba177660141fcaa26327d0b3b5f862338584b28f7522086"

DEVICE_CODE = r'''import hashlib,json,os,pathlib,plistlib,stat,subprocess,sys,tempfile,time
action=sys.argv[1]
pref=pathlib.Path('/var/mobile/Library/Preferences/com.nahtedetihw.doodleprefs.plist')
dylib=pathlib.Path('/var/jb/Library/MobileSubstrate/DynamicLibraries/Doodle.dylib')
query=subprocess.run(['/var/jb/usr/bin/dpkg-query','-W','-f=${Version}',
                      'com.nahtedetihw.doodle'],capture_output=True,text=True)
version=query.stdout.strip() if query.returncode==0 else None
digest=hashlib.sha256(dylib.read_bytes()).hexdigest() if dylib.is_file() else None
def springboard_pid():
    result=subprocess.run(['/bin/ps','-A','-o','pid=','-o','comm='],
                          capture_output=True,text=True)
    for line in result.stdout.splitlines():
        columns=line.split(None,1)
        if len(columns)==2 and columns[1].endswith('/SpringBoard'):
            return int(columns[0])
    return None
if pref.is_symlink() or not pref.is_file() or not stat.S_ISREG(pref.lstat().st_mode):
    raise SystemExit('PREFERENCE_FILE_UNSAFE')
data=plistlib.loads(pref.read_bytes())
paths=data.get('paths')
valid=isinstance(paths,list) and len(paths)==3 and all(
    isinstance(path,list) and 8<=len(path)<=1024 and all(
        isinstance(point,dict) and isinstance(point.get('x'),(int,float)) and
        isinstance(point.get('y'),(int,float)) for point in path) for path in paths)
result={'version':version,'dylib_sha256':digest,'enabled':data.get('enabled') is True,
        'pattern_count':len(paths) if isinstance(paths,list) else None,
        'pattern_valid':valid,'springboard_pid':springboard_pid(),
        'legacy_credential_present':'passcodeData' in data}
if action in ('enable','disable'):
    if version!='1:1.1+0sky27.2' or digest!='64eae513d7a96e691ba177660141fcaa26327d0b3b5f862338584b28f7522086':
        raise SystemExit('UNREVIEWED_DOODLE_BUILD')
    if action=='enable' and not valid:
        raise SystemExit('PATTERN_NOT_READY')
    expected=action=='enable'
    if result['enabled']!=expected:
        data['enabled']=expected
        old=pref.stat()
        fd,name=tempfile.mkstemp(prefix='.doodle-uat-',dir=str(pref.parent))
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(plistlib.dumps(data,fmt=plistlib.FMT_BINARY))
                stream.flush();os.fsync(stream.fileno())
            os.chown(name,old.st_uid,old.st_gid)
            os.chmod(name,old.st_mode&0o777)
            os.replace(name,pref)
            directory=os.open(str(pref.parent),os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if os.path.exists(name): os.unlink(name)
        subprocess.run(['/var/jb/usr/bin/killall','-TERM','cfprefsd'],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['/var/jb/usr/bin/killall','-TERM','SpringBoard'],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        result['changed']=True
    else:
        result['changed']=False
elif action=='finalize':
    if version!='1:1.1+0sky27.2' or digest!='64eae513d7a96e691ba177660141fcaa26327d0b3b5f862338584b28f7522086' or not result['enabled'] or not valid or result['legacy_credential_present']:
        raise SystemExit('RUNTIME_UAT_PREFLIGHT_FAILED')
    checks=json.load(sys.stdin)
    required=('native_authentication','pattern_unlock','wrong_pattern_rejected',
              'keypad_fallback','repeat_pattern_unlock','springboard_stable')
    if not isinstance(checks,dict) or any(checks.get(key) is not True for key in required):
        raise SystemExit('UAT_OBSERVATIONS_INCOMPLETE')
    base=pathlib.Path('/var/jb/var/lib/srd-runtime')
    registry=json.loads((base/'registry.json').read_text())
    state=json.loads((base/'injection-state.json').read_text())
    if any(item.get('package')=='com.nahtedetihw.doodle' for item in registry.get('quarantined',[])):
        raise SystemExit('DOODLE_RUNTIME_QUARANTINED')
    if not any(item.get('pid')==result['springboard_pid'] and
               item.get('sha256')==digest and str(item.get('dylib','')).endswith('/Doodle.dylib')
               for item in state.get('loaded',{}).values()):
        raise SystemExit('DOODLE_NOT_LOADED_IN_SPRINGBOARD')
    receipt={'schema':1,'package_version':version,'dylib_sha256':digest,
             'device_model':sys.argv[2],'ios_build':sys.argv[3],
             'verified_at':time.time(),**{key:True for key in required}}
    destination=pathlib.Path('/var/mobile/Library/Preferences/com.0sky.doodle-uat.plist')
    if destination.is_symlink(): raise SystemExit('UAT_RECEIPT_PATH_UNSAFE')
    fd,name=tempfile.mkstemp(prefix='.doodle-uat-receipt-',dir=str(destination.parent))
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(plistlib.dumps(receipt,fmt=plistlib.FMT_BINARY))
            stream.flush();os.fsync(stream.fileno())
        owner=pref.stat();os.chown(name,owner.st_uid,owner.st_gid);os.chmod(name,0o600)
        os.replace(name,destination)
    finally:
        if os.path.exists(name):os.unlink(name)
    result['receipt_written']=True
print(json.dumps(result))'''


def remote(worker: dict, action: str, *, identity: dict | None = None,
           observations: dict | None = None) -> dict:
    command = "/var/jb/usr/bin/python3 -c " + shlex.quote(DEVICE_CODE) + " " + action
    if action == "finalize":
        if not identity or observations is None:
            raise ValueError("finalize requires device identity and UAT observations")
        command += " " + shlex.quote(identity["product"]) + " " + shlex.quote(identity["build"])
    response = worker["ssh"](command, input_data=json.dumps(observations).encode()
                             if observations is not None else None, timeout=45, check=False)
    if response.returncode:
        raise RuntimeError("device UAT operation failed: " +
                           response.stderr.decode("utf-8", "replace")[-300:])
    return json.loads(response.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "enable", "disable", "finalize"))
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--observations", type=Path,
                        help="JSON record of researcher-observed UAT checks; required for finalize")
    args = parser.parse_args()
    if args.report and (args.report.exists() or args.report.is_symlink()):
        raise FileExistsError("refusing to overwrite prior UAT evidence")
    identity = asyncio.run(usb_identity(args.udid))
    selected = profiles(instance_name=args.instance)
    if args.udid not in selected:
        raise RuntimeError("paired worker does not match exact USB identity")
    worker = worker_namespace(selected[args.udid][1])
    before = remote(worker, "status")
    if args.action == "enable" and (before["enabled"] or not before["pattern_valid"] or
                                    before["version"] != EXPECTED_VERSION or
                                    before["dylib_sha256"] != EXPECTED_DYLIB_SHA256):
        raise RuntimeError("Doodle runtime trial preflight failed")
    observations = json.loads(args.observations.read_text()) if args.observations else None
    if args.action == "finalize" and (observations is None or
                                      before["version"] != EXPECTED_VERSION or
                                      before["dylib_sha256"] != EXPECTED_DYLIB_SHA256):
        raise RuntimeError("Doodle UAT receipt preflight failed")
    try:
        operation = remote(worker, args.action, identity=identity,
                           observations=observations)
        after = operation
        if args.action in ("enable", "disable") and operation["changed"]:
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                time.sleep(2)
                after = remote(worker, "status")
                if (after["springboard_pid"] and
                        after["springboard_pid"] != before["springboard_pid"]):
                    break
            if not after["springboard_pid"] or after["springboard_pid"] == before["springboard_pid"]:
                raise RuntimeError("SpringBoard did not restart")
    except Exception as error:
        if args.action == "enable":
            try:
                remote(worker, "disable")
            except Exception as rollback_error:
                error.add_note("Doodle disable rollback failed: " +
                               type(rollback_error).__name__)
        raise
    report = {"schema": 1, "device": identity, "action": args.action,
              "before": before, "operation": operation, "after": after,
              "result": "SPRINGBOARD_RESTARTED_RUNTIME_PENDING" if args.action == "enable"
                        else "DISABLED" if args.action == "disable"
                        else "VERIFIED_LOCAL_UAT_RECEIPT" if args.action == "finalize"
                        else "OBSERVED"}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
