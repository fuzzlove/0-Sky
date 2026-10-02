#!/usr/bin/env python3
"""Read-only, exact-device persistence check for the private Doodle port."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import shlex

from doodle_runtime_uat import EXPECTED_DYLIB_SHA256, EXPECTED_VERSION, remote
from repair_device_connection import profiles, usb_identity, worker_namespace


DEVICE_CODE = r'''import json,pathlib,plistlib,stat,sys
model,build,pid,digest,version=sys.argv[1:]
base=pathlib.Path('/var/jb/var/lib/srd-runtime')
receipt_path=pathlib.Path('/var/mobile/Library/Preferences/com.0sky.doodle-uat.plist')
def read(path,parser,limit):
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('missing or unsafe evidence: '+path.name)
    if path.stat().st_size>limit: raise ValueError('oversized evidence: '+path.name)
    return parser(path.read_bytes())
registry=read(base/'registry.json',json.loads,2*1024*1024)
state=read(base/'injection-state.json',json.loads,2*1024*1024)
receipt=read(receipt_path,plistlib.loads,64*1024)
checks=('native_authentication','pattern_unlock','wrong_pattern_rejected',
        'keypad_fallback','repeat_pattern_unlock','springboard_stable')
receipt_valid=(receipt.get('schema')==1 and
    receipt.get('package_version')==version and
    receipt.get('dylib_sha256')==digest and
    receipt.get('device_model')==model and
    receipt.get('ios_build')==build and
    all(receipt.get(key) is True for key in checks))
quarantined=any(item.get('package')=='com.nahtedetihw.doodle'
    for item in registry.get('quarantined',[]))
loaded=any(item.get('pid')==int(pid) and item.get('sha256')==digest and
    str(item.get('dylib','')).endswith('/Doodle.dylib')
    for item in state.get('loaded',{}).values())
print(json.dumps({'receipt_valid':receipt_valid,'registry_quarantined':quarantined,
                  'loaded_in_current_springboard':loaded}))'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("refusing to overwrite prior persistence evidence")
    identity = asyncio.run(usb_identity(args.udid))
    selected = profiles(instance_name=args.instance)
    if args.udid not in selected:
        raise RuntimeError("paired worker does not match exact USB identity")
    worker = worker_namespace(selected[args.udid][1])
    status = remote(worker, "status")
    if (status["version"] != EXPECTED_VERSION or
            status["dylib_sha256"] != EXPECTED_DYLIB_SHA256):
        raise RuntimeError("installed Doodle build differs from reviewed artifact")
    command = "/var/jb/usr/bin/python3 -c " + shlex.quote(DEVICE_CODE)
    for value in (identity["product"], identity["build"],
                  str(status["springboard_pid"]), EXPECTED_DYLIB_SHA256,
                  EXPECTED_VERSION):
        command += " " + shlex.quote(value)
    response = worker["ssh"](command, timeout=45, check=False)
    if response.returncode:
        raise RuntimeError("device persistence probe failed: " +
                           response.stderr.decode("utf-8", "replace")[-300:])
    checks = json.loads(response.stdout)
    passed = (status["enabled"] and status["pattern_valid"] and
              not status["legacy_credential_present"] and
              bool(status["springboard_pid"]) and
              checks == {"receipt_valid": True, "registry_quarantined": False,
                         "loaded_in_current_springboard": True})
    report = {"schema": 1, "device": identity, "status": status,
              "checks": checks, "result": "PASS" if passed else "FAIL",
              "gesture_after_reboot": "RESEARCHER_OBSERVATION_PENDING"}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
