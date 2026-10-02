#!/usr/bin/env python3
"""Install the reviewed Link/Control bundle through the paired rollback worker."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import uuid
import zipfile

from install_control_ui_uat import await_result, remote_json, submit
from repair_device_connection import profiles, usb_identity, worker_namespace


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.release_sanitize import audit  # noqa: E402
from tools.verify_link_ipa import verify as verify_link_ipa  # noqa: E402


def verify_device(worker: dict, expected_control_build: str,
                  expected_control_sha256: str) -> dict:
    code = r'''
import json,pathlib,plistlib,subprocess,sys
sys.path.insert(0,'/var/jb/usr/local/libexec')
from zero_sky_core.control_payload import load_manifest,verify_manifest
bundle='codes.liquidsky.research.zerosky'
rows=subprocess.check_output(['/var/jb/usr/bin/uicache','-l'],text=True).splitlines()
matches=[line.split(' : ',1)[1].strip() for line in rows if line.startswith(bundle+' : ')]
if len(matches)!=1: raise RuntimeError('Link registration is absent or ambiguous')
app=pathlib.Path(matches[0]);info=plistlib.loads((app/'Info.plist').read_bytes())
binary=app/info['CFBundleExecutable']
manifest=load_manifest(app/'ControlPayload/manifest.json')
payload=app/manifest['payload_path']
verify_manifest(payload,manifest)
result={'registered':True,'bundle_id':info['CFBundleIdentifier'],
        'version':info['CFBundleShortVersionString'],'build':info['CFBundleVersion'],
        'executable':binary.is_file(),'install_button':b'Install 0-Sky Control' in binary.read_bytes(),
        'control_payload_build':manifest['identity']['CFBundleVersion'],
        'control_payload_sha256':manifest['ipa_sha256'],'payload_verified':True}
print(json.dumps(result))
'''
    value = remote_json(worker, code, timeout=60)
    if (value.get("bundle_id") != "codes.liquidsky.research.zerosky" or
            value.get("version") != "1.9.0" or value.get("build") != "48" or
            value.get("registered") is not True or value.get("executable") is not True or
            value.get("install_button") is not True or
            value.get("control_payload_build") != expected_control_build or
            value.get("control_payload_sha256") != expected_control_sha256 or
            value.get("payload_verified") is not True):
        raise RuntimeError("installed Link identity or bundled Control differs")
    return value


def install_status(worker: dict) -> dict:
    code = r'''
import json,pathlib,urllib.error,urllib.request
token=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
request=urllib.request.Request('http://127.0.0.1:48654/v1/control/install/status',
 headers={'X-TrollStore-Bridge-Token':token})
try:
 with urllib.request.urlopen(request,timeout=40) as response:
  value=json.load(response);print(json.dumps({'http_status':response.status,
      'action':value.get('decision',{}).get('action'),
      'code':value.get('decision',{}).get('code'),
      'explanation':value.get('decision',{}).get('explanation')}))
except urllib.error.HTTPError as error:
 value=json.loads(error.read());print(json.dumps({'http_status':error.code,
      'code':value.get('code'),'explanation':value.get('explanation')}))
'''
    value = remote_json(worker, code, timeout=50)
    if value.get("http_status") != 200:
        raise RuntimeError("bundled Control status is unavailable: " +
                           str(value.get("code"))[:100])
    return value


def run(instance: str, udid: str, ipa_path: Path) -> dict:
    selected = profiles(instance_name=instance)
    if udid not in selected or asyncio.run(usb_identity(udid))["udid"] != udid:
        raise RuntimeError("exact USB identity and paired profile differ")
    if ipa_path.is_symlink() or not ipa_path.is_file() or ipa_path.stat().st_size > 64 * 1024 * 1024:
        raise RuntimeError("reviewed Link IPA is absent or unsafe")
    verify_link_ipa(ipa_path, require_control=True)
    if audit([ipa_path]):
        raise RuntimeError("Link IPA failed the PII release gate")
    with zipfile.ZipFile(ipa_path) as archive:
        bundled_manifest = json.loads(
            archive.read("Payload/ZeroSky.app/ControlPayload/manifest.json")
        )
    expected_control_build = bundled_manifest["identity"]["CFBundleVersion"]
    expected_control_sha256 = bundled_manifest["ipa_sha256"]
    worker = worker_namespace(selected[udid][1])
    worker["preflight_workspace"](ipa_path)
    with tempfile.TemporaryDirectory(prefix="0sky-link-uat-compat-") as folder:
        extract = Path(folder)
        subprocess.run(["/usr/bin/ditto", "-x", "-k", str(ipa_path), str(extract)],
                       capture_output=True, timeout=120, check=True)
        compatibility = worker["evaluate_control_compatibility"](extract)
        if compatibility.get("result") not in ("COMPATIBLE", "COMPATIBLE_WITH_ADAPTATION"):
            raise RuntimeError("Link compatibility did not pass preflight")
    with tempfile.TemporaryDirectory(prefix="0sky-link-uat-snapshot-") as folder:
        previous = worker["snapshot_native_control"](
            Path(folder), "codes.liquidsky.research.zerosky")
        if previous is None:
            raise RuntimeError("existing Link rollback source is absent")
    contents = ipa_path.read_bytes()
    digest = hashlib.sha256(contents).hexdigest()
    entitlements = plistlib.loads((ROOT / "link/entitlements.plist").read_bytes())
    job_id = str(uuid.uuid4())
    submit(worker, contents, digest, entitlements, job_id, operation="link-install")
    response = await_result(worker, job_id)
    evidence_path = ipa_path.parent.parent / ("link-transaction-" + udid[-8:].lower() + ".json")
    evidence_path.write_text(json.dumps(response, sort_keys=True, indent=2) + "\n",
                             encoding="utf-8")
    if response["status"] != 0:
        raise RuntimeError("Link transaction failed: " +
                           str(response.get("stderr", "unknown failure"))[:250] +
                           "; rollback=" + str(response.get("rollback", "UNKNOWN")))
    verified = verify_device(worker, expected_control_build,
                             expected_control_sha256)
    status = install_status(worker)
    return {"device": udid[-8:], "job_id": job_id, "installed": verified,
            "control_install_status": status,
            "compatibility": {"result": compatibility["result"],
                              "issue_codes": sorted({item["code"] for item in compatibility["issues"]})},
            "transaction_checks": {key: response.get("evidence", {}).get(key)
                                   for key in ("installation", "registration", "launch")},
            "rollback": response.get("rollback", "UNKNOWN"),
            "transaction_evidence_file": str(evidence_path)}


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: install_link_ui_uat.py INSTANCE EXACT_UDID IPA")
    print(json.dumps(run(sys.argv[1], sys.argv[2], Path(sys.argv[3])), sort_keys=True))
