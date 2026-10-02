#!/usr/bin/env python3
"""Install one private Doodle port on an exact paired SRD with rollback evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import sys
import uuid

from repair_device_connection import profiles, usb_identity, worker_namespace
import asyncio


PACKAGE = "com.nahtedetihw.doodle"
PORT_VERSION = "1:1.1+0sky27.2"
ORIGINAL_VERSION = "1.2"
ORIGINAL_SHA256 = "4725c0170e89413308b8434e4f1e80fc7357880e628d87af76c9e45920aa656a"


def remote(worker: dict, code: str, *, data: bytes | None = None, timeout: int = 60) -> dict:
    result = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(code),
                           input_data=data, timeout=timeout, check=False)
    stdout = result.stdout.decode("utf-8", "replace")
    if result.returncode:
        raise RuntimeError(f"device command exited {result.returncode}: " +
                           result.stderr.decode("utf-8", "replace")[-500:])
    return json.loads(stdout)


def state(worker: dict) -> dict:
    code = r'''import hashlib,json,pathlib,subprocess,plistlib
name='com.nahtedetihw.doodle'
query=subprocess.run(['/var/jb/usr/bin/dpkg-query','-W','-f=${Version}',name],capture_output=True,text=True)
path=pathlib.Path('/var/jb/Library/MobileSubstrate/DynamicLibraries/Doodle.dylib')
prefs=pathlib.Path('/var/mobile/Library/Preferences/com.nahtedetihw.doodleprefs.plist')
try: values=plistlib.loads(prefs.read_bytes()) if prefs.is_file() else {}
except (ValueError,plistlib.InvalidFileException): values={'invalid':True}
result={'version':query.stdout.strip() if query.returncode==0 else None,
 'dylib_sha256':hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
 'old_preference_executable':pathlib.Path('/var/jb/Library/PreferenceBundles/doodleprefs.bundle/doodleprefs').exists(),
 'enabled':values.get('enabled',False),'preferences_present':prefs.is_file(),
 'preferences_invalid':values.get('invalid',False)}
print(json.dumps(result))
'''
    return remote(worker, code)


def stage(worker: dict, path: Path, remote_path: str) -> str:
    payload = path.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    code = r'''import hashlib,json,os,pathlib,sys
path=pathlib.Path(sys.argv[1]); data=sys.stdin.buffer.read()
if len(data)>20_000_000 or len(data)<64: raise SystemExit(2)
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as stream: stream.write(data);stream.flush();os.fsync(stream.fileno())
print(json.dumps({'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'size':path.stat().st_size}))
'''
    command = "/var/jb/usr/bin/python3 -c " + shlex.quote(code) + " " + shlex.quote(remote_path)
    result = worker["ssh"](command, input_data=payload, timeout=90, check=False)
    if result.returncode:
        raise RuntimeError("device package staging failed")
    value = json.loads(result.stdout)
    if value.get("sha256") != digest:
        raise RuntimeError("device package transfer hash mismatch")
    return digest


def install(worker: dict, remote_path: str) -> dict:
    code = r'''import json,pathlib,sys,urllib.error,urllib.request
token=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
request=urllib.request.Request('http://127.0.0.1:48654/v1/trollstore',
 data=json.dumps({'arguments':['install-deb',sys.argv[1]]}).encode(),
 headers={'Content-Type':'application/json','X-TrollStore-Bridge-Token':token},method='POST')
try:
 with urllib.request.urlopen(request,timeout=1100) as response: value=json.load(response)
except urllib.error.HTTPError as error: value=json.load(error)
print(json.dumps({'status':value.get('status'), 'package':value.get('package'),
 'version':value.get('version'),'stderr':str(value.get('stderr') or '')[-1600:],
 'stdout':str(value.get('stdout') or '')[-1600:]}))
'''
    command = "/var/jb/usr/bin/python3 -c " + shlex.quote(code) + " " + shlex.quote(remote_path)
    result = worker["ssh"](command, timeout=1200, check=False)
    if result.returncode:
        raise RuntimeError("device Bridge install request exited " + str(result.returncode))
    return json.loads(result.stdout)


def cleanup(worker: dict, paths: list[str]) -> None:
    for path in paths:
        worker["ssh"]("rm -f -- " + shlex.quote(path), timeout=20, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--build-report", type=Path, required=True)
    parser.add_argument("--rollback-package", type=Path, required=True)
    parser.add_argument("--rollback-report", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("refusing to overwrite prior transaction evidence")
    package = args.package.resolve(strict=True)
    rollback = args.rollback_package.resolve(strict=True)
    manifest = json.loads(args.build_report.read_text())
    rollback_manifest = (json.loads(args.rollback_report.read_text())
                         if args.rollback_report else
                         {"package": PACKAGE, "version": ORIGINAL_VERSION,
                          "package_sha256": ORIGINAL_SHA256})
    if (manifest.get("package") != PACKAGE or manifest.get("version") != PORT_VERSION or
            manifest.get("package_sha256") != hashlib.sha256(package.read_bytes()).hexdigest() or
            rollback_manifest.get("package") != PACKAGE or
            hashlib.sha256(rollback.read_bytes()).hexdigest() != rollback_manifest.get("package_sha256")):
        raise ValueError("package or rollback artifact differs from reviewed manifest")
    identity = asyncio.run(usb_identity(args.udid))
    selected = profiles(instance_name=args.instance)
    if args.udid not in selected:
        raise RuntimeError("paired worker does not match exact USB identity")
    worker = worker_namespace(selected[args.udid][1])
    before = state(worker)
    if before["version"] != rollback_manifest["version"]:
        raise RuntimeError("installed Doodle version changed before transaction")
    if before["enabled"] is not False or before["preferences_invalid"]:
        raise RuntimeError("Doodle must be disabled with readable preferences before install")
    token = uuid.uuid4().hex
    new_path = "/var/mobile/tmp/0sky-doodle-" + token + ".deb"
    old_path = "/var/mobile/tmp/0sky-doodle-rollback-" + token + ".deb"
    report = {"schema": 1, "device": identity, "before": before,
              "package_sha256": manifest["package_sha256"],
              "candidate_sha256": manifest["candidate_sha256"],
              "result": "UNTESTED", "rollback": "NOT_NEEDED"}
    try:
        stage(worker, package, new_path)
        response = install(worker, new_path)
        report["install_response"] = response
        after = state(worker)
        report["after"] = after
        if (response.get("status") != 0 or after["version"] != PORT_VERSION or
                after["dylib_sha256"] != manifest["candidate_sha256"] or
                after["old_preference_executable"] or after["enabled"] is not False):
            raise RuntimeError("package, trust refresh, or post-install verification failed")
        report["result"] = "INSTALLED_DISABLED_RUNTIME_UNVERIFIED"
    except Exception as error:
        report["result"] = "FAILED"
        report["error"] = type(error).__name__ + ": " + str(error)[:700]
        current = state(worker)
        if current["version"] != rollback_manifest["version"]:
            try:
                stage(worker, rollback, old_path)
                report["rollback_response"] = install(worker, old_path)
                restored = state(worker)
                report["restored"] = restored
                report["rollback"] = "VERIFIED" if restored["version"] == rollback_manifest["version"] else "FAILED"
            except Exception as rollback_error:
                report["rollback"] = "FAILED: " + type(rollback_error).__name__
        else:
            report["rollback"] = "NOT_NEEDED"
    finally:
        cleanup(worker, [new_path, old_path])
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["result"] == "INSTALLED_DISABLED_RUNTIME_UNVERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
