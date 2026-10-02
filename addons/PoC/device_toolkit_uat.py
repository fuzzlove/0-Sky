#!/usr/bin/env python3
"""Run the deployed toolkit's smoke/UAT endpoints on one exact paired SRD."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path
import shlex
import sys
import uuid
import zipfile

from repair_device_connection import profiles, usb_identity, worker_namespace


HERE = Path(__file__).resolve().parent
OPERATIONS = {"runToolkitSmoke", "runToolkitUAT", "getResearchToolkit", "getToolkitReport"}
REMOTE = r'''
import json,sys,time,urllib.error,urllib.request
from pathlib import Path
operation=sys.argv[1]
if operation not in ('runToolkitSmoke','runToolkitUAT','getResearchToolkit','getToolkitReport'):
 raise RuntimeError('unapproved toolkit operation')
token=Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
payload={'protocolVersion':1,'requestId':'toolkit-uat-'+str(int(time.time()*1000)),
         'timestamp':time.time(),'operation':operation,'parameters':{}}
request=urllib.request.Request('http://127.0.0.1:48654/v1/core',
 data=json.dumps(payload).encode(),headers={'X-TrollStore-Bridge-Token':token,
 'Content-Type':'application/json'})
try:
 with urllib.request.urlopen(request,timeout=240) as response: print(response.read().decode())
except urllib.error.HTTPError as error:
 print(error.read().decode())
'''


def call(worker: dict, operation: str, timeout: int = 270) -> dict:
    if operation not in OPERATIONS:
        raise ValueError("unapproved toolkit UAT operation")
    remote = "/var/jb/usr/bin/python3 - " + shlex.quote(operation)
    result = worker["ssh"](remote, input_data=REMOTE.encode(), timeout=timeout,
                           check=False)
    if result.returncode:
        raise RuntimeError("paired device UAT request failed (exit " +
                           str(result.returncode) + ")")
    envelope = json.loads(result.stdout)
    if envelope.get("success") is not True:
        raise RuntimeError("toolkit UAT endpoint failed: " +
                           str(envelope.get("errorCode") or envelope.get("errorMessage"))[:180])
    return envelope["result"]


def run(instance: str, udid: str) -> dict:
    profiles_by_id = profiles(instance_name=instance)
    if udid not in profiles_by_id or asyncio.run(usb_identity(udid))["udid"] != udid:
        raise RuntimeError("exact USB device and paired profile do not match")
    worker = worker_namespace(profiles_by_id[udid][1])
    directory = HERE / "0sky-uat" / udid[-8:].lower()
    directory.mkdir(parents=True, exist_ok=True)
    smoke = call(worker, "runToolkitSmoke")
    uat = call(worker, "runToolkitUAT")
    snapshot = call(worker, "getResearchToolkit")
    report = call(worker, "getToolkitReport")
    contents = base64.b64decode(report["base64"], validate=True)
    if hashlib.sha256(contents).hexdigest() != report["sha256"]:
        raise RuntimeError("device toolkit report SHA-256 mismatch")
    output = directory / ("device-integrated-" + uuid.uuid4().hex + ".zip")
    output.write_bytes(contents)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("device toolkit evidence archive is damaged")
    for name, value in (("integrated-smoke.json", smoke),
                        ("integrated-uat.json", uat),
                        ("integrated-snapshot.json", snapshot)):
        (directory / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    return {"device": udid[-8:], "components": len(snapshot.get("components", [])),
            "smoke": smoke.get("overall"),
            "smoke_counts": smoke.get("smoke", {}).get("counts"),
            "uat": uat.get("overall"),
            "uat_counts": uat.get("uat", {}).get("counts"),
            "host_connected": snapshot.get("environment", {}).get("host_connected"),
            "evidence": str(output)}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: device_toolkit_uat.py INSTANCE EXACT_UDID")
    print(json.dumps(run(sys.argv[1], sys.argv[2]), sort_keys=True))
