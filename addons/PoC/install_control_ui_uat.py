#!/usr/bin/env python3
"""Install a reviewed Control build through one paired Mac worker for device UAT.

This exercises the same transactional Bridge backend used by Link. The release
button and embedded-payload path are separate UAT requirements.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import uuid

from repair_device_connection import profiles, usb_identity, worker_namespace


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime/zero_sky_core"))
from control_payload import load_manifest, verify_manifest  # noqa: E402


def remote_json(worker: dict, code: str, *, data: bytes | None = None,
                timeout: int = 30) -> dict:
    result = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(code),
                           input_data=data, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError("paired device request failed (exit " +
                           str(result.returncode) + "): " +
                           result.stderr.decode("utf-8", "replace")[:220])
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("paired device returned an invalid result")
    return value


def submit(worker: dict, ipa: bytes, digest: str, entitlements: dict,
           job_id: str, *, operation: str = "control-install") -> None:
    if operation not in {"control-install", "link-install"}:
        raise ValueError("unreviewed first-party install operation")
    request = {"job_id": job_id, "operation": operation,
               "original_name": "0-Sky Control source UAT" if operation == "control-install"
                                else "0-Sky Link source UAT", "source_sha256": digest,
               "required_entitlements": entitlements, "created_at": int(time.time())}
    code = f'''
import hashlib,json,os,pathlib,sys
root=pathlib.Path('/var/jb/var/spool/crypstore/jobs')
job=root/{job_id!r}
expected={digest!r}
request={request!r}
data=sys.stdin.buffer.read(64*1024*1024+1)
if len(data)>64*1024*1024 or hashlib.sha256(data).hexdigest()!=expected:
 raise RuntimeError('reviewed Control payload size or digest differs')
root.mkdir(parents=True,exist_ok=True)
job.mkdir(mode=0o700)
payload=job/'input.ipa'
with payload.open('xb') as stream:
 stream.write(data);stream.flush();os.fsync(stream.fileno())
payload.chmod(0o600)
pending=job/'request.json.tmp'
with pending.open('x') as stream:
 json.dump(request,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
pending.chmod(0o600)
os.replace(pending,job/'request.json')
print(json.dumps({{'queued':True,'job_id':job.name}}))
'''
    result = remote_json(worker, code, data=ipa, timeout=90)
    if result.get("queued") is not True or result.get("job_id") != job_id:
        raise RuntimeError("transactional Control job was not queued")


def await_result(worker: dict, job_id: str, timeout: float = 900) -> dict:
    code = f'''
import json,pathlib
path=pathlib.Path('/var/jb/var/spool/crypstore/jobs')/{job_id!r}/'result.json'
print(json.dumps({{'ready':path.is_file(),'result':json.loads(path.read_text()) if path.is_file() else None}}))
'''
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = remote_json(worker, code)
        if value.get("ready") is True:
            result = value.get("result")
            if not isinstance(result, dict) or not isinstance(result.get("status"), int):
                raise RuntimeError("Mac installer result is malformed")
            return result
        time.sleep(2)
    raise RuntimeError("Mac Control transaction timed out; inspect the queued job")


def verify_device(worker: dict, version: str, build: str) -> dict:
    code = f'''
import json,pathlib,plistlib,subprocess
bundle='com.liquidsky.CrypStore'
rows=subprocess.check_output(['/var/jb/usr/bin/uicache','-l'],text=True).splitlines()
matches=[line.split(' : ',1)[1].strip() for line in rows if line.startswith(bundle+' : ')]
if len(matches)!=1: raise RuntimeError('Control registration missing or ambiguous')
app=pathlib.Path(matches[0]);info=plistlib.loads((app/'Info.plist').read_bytes())
binary=app/info['CFBundleExecutable']
result={{'registered':True,'bundle_id':info['CFBundleIdentifier'],
        'version':info['CFBundleShortVersionString'],'build':info['CFBundleVersion'],
        'executable':binary.is_file(),'toolkit_ui':b'Security Toolkit UAT' in binary.read_bytes()}}
print(json.dumps(result))
'''
    result = remote_json(worker, code)
    if (result.get("bundle_id") != "com.liquidsky.CrypStore" or
            result.get("version") != version or result.get("build") != build or
            result.get("executable") is not True or result.get("toolkit_ui") is not True):
        raise RuntimeError("installed Control identity or toolkit UI differs")
    return result


def run(instance: str, udid: str, ipa_path: Path, manifest_path: Path) -> dict:
    selected = profiles(instance_name=instance)
    if udid not in selected or asyncio.run(usb_identity(udid))["udid"] != udid:
        raise RuntimeError("exact USB identity and paired worker profile differ")
    if ipa_path.is_symlink() or not ipa_path.is_file() or ipa_path.stat().st_size > 64 * 1024 * 1024:
        raise RuntimeError("reviewed Control IPA is absent or unsafe")
    manifest = load_manifest(manifest_path)
    verify_manifest(ipa_path, manifest)
    identity = manifest["identity"]
    worker = worker_namespace(selected[udid][1])
    worker["preflight_workspace"](ipa_path)
    with tempfile.TemporaryDirectory(prefix="0sky-control-uat-compat-") as folder:
        extract = Path(folder)
        subprocess.run(["/usr/bin/ditto", "-x", "-k", str(ipa_path), str(extract)],
                       capture_output=True, timeout=120, check=True)
        compatibility = worker["evaluate_control_compatibility"](extract)
        if compatibility.get("result") not in ("COMPATIBLE", "COMPATIBLE_WITH_ADAPTATION"):
            raise RuntimeError("Control compatibility did not pass preflight")
    with tempfile.TemporaryDirectory(prefix="0sky-control-uat-snapshot-") as folder:
        previous = worker["snapshot_native_control"](Path(folder))
        if previous is None:
            raise RuntimeError("existing Control rollback source is absent")
    contents = ipa_path.read_bytes()
    digest = hashlib.sha256(contents).hexdigest()
    if digest != manifest["ipa_sha256"]:
        raise RuntimeError("Control package digest differs after preflight")
    job_id = str(uuid.uuid4())
    submit(worker, contents, digest, manifest["permissions"]["required_entitlements"], job_id)
    response = await_result(worker, job_id)
    evidence_path = ipa_path.parent.parent / ("transaction-" + udid[-8:].lower() + ".json")
    evidence_path.write_text(json.dumps(response, sort_keys=True, indent=2) + "\n",
                             encoding="utf-8")
    if response["status"] != 0:
        raise RuntimeError("Control transaction failed: " +
                           str(response.get("stderr", "unknown failure"))[:250] +
                           "; rollback=" + str(response.get("rollback", "UNKNOWN")))
    verified = verify_device(worker, identity["CFBundleShortVersionString"],
                             identity["CFBundleVersion"])
    return {"device": udid[-8:], "job_id": job_id, "installed": verified,
            "compatibility": {"result": compatibility["result"],
                              "issue_codes": sorted({item["code"] for item in compatibility["issues"]})},
            "transaction_evidence_file": str(evidence_path),
            "transaction_checks": {key: response.get("evidence", {}).get(key)
                                   for key in ("installation", "registration", "launch")},
            "rollback": response.get("rollback", "UNKNOWN")}


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: install_control_ui_uat.py INSTANCE EXACT_UDID IPA MANIFEST")
    print(json.dumps(run(sys.argv[1], sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])),
                     sort_keys=True))
