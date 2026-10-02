#!/usr/bin/env python3
"""Install the reviewed private Doodle port on a device with no prior Doodle."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import shlex
import uuid

from repair_device_connection import profiles, usb_identity, worker_namespace
from install_doodle_private_uat import cleanup, install, stage, state

PACKAGE = "com.nahtedetihw.doodle"
VERSION = "1:1.1+0sky27.2"


def remove(worker: dict) -> dict:
    code = r'''import json,pathlib,urllib.error,urllib.request
token=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
request=urllib.request.Request('http://127.0.0.1:48654/v1/trollstore',
 data=json.dumps({'arguments':['remove-package','com.nahtedetihw.doodle']}).encode(),
 headers={'Content-Type':'application/json','X-TrollStore-Bridge-Token':token},method='POST')
try:
 with urllib.request.urlopen(request,timeout=600) as response:value=json.load(response)
except urllib.error.HTTPError as error:value=json.load(error)
print(json.dumps({'status':value.get('status'),'stderr':str(value.get('stderr') or '')[-1000:]}))'''
    response = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(code),
                             timeout=650, check=False)
    if response.returncode:
        raise RuntimeError("paired removal request failed")
    return json.loads(response.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--build-report", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("refusing to overwrite prior transaction evidence")
    payload = args.package.resolve(strict=True)
    manifest = json.loads(args.build_report.read_text())
    if (manifest.get("package") != PACKAGE or manifest.get("version") != VERSION or
            manifest.get("package_sha256") != hashlib.sha256(payload.read_bytes()).hexdigest()):
        raise ValueError("Doodle payload differs from reviewed manifest")
    identity = asyncio.run(usb_identity(args.udid))
    selected = profiles(instance_name=args.instance)
    if args.udid not in selected:
        raise RuntimeError("paired worker does not match exact USB identity")
    worker = worker_namespace(selected[args.udid][1])
    before = state(worker)
    if before["version"] is not None or before["preferences_present"]:
        raise RuntimeError("fresh-install preflight found existing Doodle state")
    remote_path = "/var/mobile/tmp/0sky-doodle-fresh-" + uuid.uuid4().hex + ".deb"
    report = {"schema": 1, "device": identity, "before": before,
              "package_sha256": manifest["package_sha256"],
              "candidate_sha256": manifest["candidate_sha256"],
              "result": "UNTESTED", "rollback": "NOT_NEEDED"}
    try:
        stage(worker, payload, remote_path)
        response = install(worker, remote_path)
        report["install_response"] = response
        after = state(worker)
        report["after"] = after
        if (response.get("status") != 0 or after["version"] != VERSION or
                after["dylib_sha256"] != manifest["candidate_sha256"] or
                after["old_preference_executable"] or after["enabled"] is not False):
            raise RuntimeError("Doodle package or disabled post-install state failed verification")
        report["result"] = "INSTALLED_DISABLED_RUNTIME_UNVERIFIED"
    except Exception as error:
        report["result"] = "FAILED"
        report["error"] = type(error).__name__ + ": " + str(error)[:400]
        try:
            current = state(worker)
            if current["version"] is not None:
                report["rollback_response"] = remove(worker)
            report["rollback"] = "VERIFIED" if state(worker)["version"] is None else "FAILED"
        except Exception as rollback_error:
            report["rollback"] = "FAILED: " + type(rollback_error).__name__
    finally:
        cleanup(worker, [remote_path])
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["result"] == "INSTALLED_DISABLED_RUNTIME_UNVERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
