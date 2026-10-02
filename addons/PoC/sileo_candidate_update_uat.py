#!/usr/bin/env python3
"""Replace the reviewed Sileo UAT candidate while preserving its data container."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import shlex
import time
import uuid

import security_test_fixture_install as native
import sileo_candidate_uat as sileo
from repair_device_connection import profiles, usb_identity, worker_namespace


def installed_hash(worker: dict, app: dict) -> str:
    path = app.get("Path")
    if not isinstance(path, str) or not path.startswith("/private/var/containers/Bundle/Application/"):
        raise RuntimeError("SILEO_REGISTERED_PATH_INVALID")
    result = worker["ssh"]("sha256sum " + shlex.quote(path + "/Sileo"),
                           timeout=20, check=False)
    if result.returncode:
        raise RuntimeError("SILEO_EXECUTABLE_HASH_UNAVAILABLE")
    digest = result.stdout.decode(errors="replace").split()[0]
    if len(digest) != 64:
        raise RuntimeError("SILEO_EXECUTABLE_HASH_INVALID")
    return digest


def canonical_data_container(worker: dict) -> str:
    """Resolve MCM ownership on the device; lockdown's Container URL can be stale."""
    script = r'''import json,pathlib,plistlib,sys
root=pathlib.Path('/private/var/mobile/Containers/Data/Application')
matches=[]
for item in root.iterdir():
 if item.is_symlink() or not item.is_dir():continue
 metadata=item/'.com.apple.mobile_container_manager.metadata.plist'
 if metadata.is_symlink() or not metadata.is_file():continue
 try:info=plistlib.loads(metadata.read_bytes())
 except (OSError,ValueError):continue
 if info.get('MCMMetadataIdentifier')==sys.argv[1]:matches.append(str(item))
if len(matches)!=1:raise SystemExit('expected one Sileo MCM data container')
print(json.dumps(matches[0]))'''
    result = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(script) +
                           " " + shlex.quote(sileo.BUNDLE_ID), timeout=25, check=False)
    if result.returncode:
        raise RuntimeError("SILEO_DATA_CONTAINER_OWNERSHIP_UNAVAILABLE")
    value = json.loads(result.stdout)
    if (not isinstance(value, str) or
            not value.startswith("/private/var/mobile/Containers/Data/Application/") or
            len(Path(value).name) != 36):
        raise RuntimeError("SILEO_DATA_CONTAINER_PATH_INVALID")
    return value


def snapshot_action(worker: dict, action: str, container: str, token: str) -> dict:
    helper = Path(__file__).with_name("sileo_data_snapshot.py")
    result = worker["ssh"](
        "/var/jb/usr/bin/python3 - " + " ".join(shlex.quote(value) for value in
                                      (action, container, token)),
        input_data=helper.read_bytes(), timeout=120, check=False)
    if result.returncode:
        raise RuntimeError("SILEO_DATA_" + action.upper() + "_FAILED: " +
                           result.stderr.decode(errors="replace")[-300:])
    value = json.loads(result.stdout)
    expected = "SNAPSHOT_VERIFIED" if action == "backup" else "DATA_RESTORED_AND_VERIFIED"
    if value.get("result") != expected or value.get("token") != token:
        raise RuntimeError("SILEO_DATA_" + action.upper() + "_VERIFY_FAILED")
    return {"result": value["result"], "files": value["files"], "bytes": value["bytes"]}


def synchronize_broker_cache(worker: dict, udid: str, model: str) -> str:
    """Recreate Sileo's source and installed-package view after data restoration."""
    result = worker["ssh"](
        "/var/jb/usr/bin/python3 /var/jb/usr/local/libexec/trollstorelite-srd-bridge.py "
        "--provision-sileo-bridge", input_data=json.dumps(
            {"udid": udid, "model": model}, separators=(",", ":")).encode(),
        timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("SILEO_BROKER_CACHE_SYNC_FAILED")
    response = json.loads(result.stdout)
    if response.get("result") != "SILEO_BRIDGE_CREDENTIAL_PROVISIONED":
        raise RuntimeError("SILEO_BROKER_CACHE_SYNC_UNVERIFIED")
    return "SIGNED_SOURCES_AND_DPKG_STATUS_MIRRORED"


def stop_registered_app(worker: dict, app: dict) -> None:
    path = app.get("Path")
    if not isinstance(path, str) or not path.startswith("/private/var/containers/Bundle/Application/"):
        raise RuntimeError("SILEO_REGISTERED_PATH_INVALID")
    script = r'''import os,signal,subprocess,sys,time
expected=sys.argv[1].removeprefix('/private')+'/Sileo'
rows=subprocess.check_output(['/bin/ps','-axo','pid=,command='],text=True).splitlines()
matches=[]
for row in rows:
 parts=row.strip().split(None,1)
 if len(parts)==2 and parts[1].split(' ',1)[0] in (expected,'/private'+expected):
  matches.append(int(parts[0]))
if len(matches)>1:raise SystemExit('ambiguous Sileo process')
for pid in matches:os.kill(pid,signal.SIGTERM)
time.sleep(1)
'''
    result = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(script) +
                           " " + shlex.quote(path), timeout=20, check=False)
    if result.returncode:
        raise RuntimeError("SILEO_PROCESS_STOP_FAILED")


def launch_healthcheck(worker: dict, app: dict, pause=time.sleep) -> str:
    """Require one live, stable Sileo process after LaunchServices opens it."""
    path = app.get("Path")
    if not isinstance(path, str) or not path.startswith(
            "/private/var/containers/Bundle/Application/"):
        raise RuntimeError("SILEO_REGISTERED_PATH_INVALID")
    opened = worker["ssh"]("/var/jb/usr/bin/uiopen --bundleid " + sileo.BUNDLE_ID,
                           timeout=20, check=False)
    if opened.returncode:
        raise RuntimeError("SILEO_LAUNCH_REQUEST_FAILED")
    expected = path.removeprefix("/private") + "/Sileo"
    script = r'''import json,subprocess,sys
expected=sys.argv[1]
rows=subprocess.check_output(['/bin/ps','-axo','pid=,command='],text=True).splitlines()
matches=[]
for row in rows:
 parts=row.strip().split(None,1)
 if len(parts)==2 and parts[1].split(' ',1)[0] in (expected,'/private'+expected):
  matches.append(int(parts[0]))
print(json.dumps(matches))'''
    processes = []
    for delay in (3, 7):
        pause(delay)
        result = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(script) +
                               " " + shlex.quote(expected), timeout=20, check=False)
        if result.returncode:
            raise RuntimeError("SILEO_PROCESS_QUERY_FAILED")
        matches = json.loads(result.stdout)
        if not isinstance(matches, list) or len(matches) != 1 or not isinstance(matches[0], int):
            raise RuntimeError("SILEO_LAUNCH_NOT_STABLE")
        processes.append(matches[0])
    if processes[0] != processes[1]:
        raise RuntimeError("SILEO_PROCESS_RESTARTED_DURING_HEALTHCHECK")
    return "LAUNCH_PROCESS_STABLE_10_SECONDS"


def queue_and_wait(worker: dict, ipa: Path, data: bytes, digest: str) -> dict:
    sileo.configure_native(ipa)
    job = native.queue(worker, data, digest)
    result = native.await_result(worker, job)
    worker["ssh"]("rm -f -- " + shlex.quote(native.SPOOL + "/" + job + "/input.ipa"),
                  timeout=20, check=False)
    return {"job_id": job, "status": result.get("status"),
            "error": str(result.get("stderr") or "")[-400:]}


def run(instance: str, udid: str, old_ipa: Path, new_ipa: Path) -> dict:
    selected = profiles(instance_name=instance)
    device = asyncio.run(usb_identity(udid))
    if udid not in selected or device["udid"] != udid:
        raise RuntimeError("EXACT_USB_PROFILE_MISMATCH")
    old_data, old_digest = sileo.checked_payload(old_ipa)
    new_data, new_digest = sileo.checked_payload(new_ipa)
    if old_digest == new_digest:
        raise RuntimeError("SILEO_UPDATE_IDENTICAL")
    # The shared native worker defaults to the security-test fixture identity.
    # Resolve the exact Sileo Cryptex before checking or replacing anything.
    sileo.configure_native(old_ipa)
    worker = worker_namespace(selected[udid][1])
    before = sileo.query_candidate(udid)
    generations = asyncio.run(native.cryptex_versions(udid))
    if (before.get("CFBundleIdentifier", sileo.BUNDLE_ID) != sileo.BUNDLE_ID or
            before.get("CFBundleShortVersionString") != sileo.VERSION or
            len(generations) != 1):
        raise RuntimeError("SILEO_UPDATE_PRIOR_STATE_INVALID")
    prior_data_container = canonical_data_container(worker)
    previous_code = installed_hash(worker, before)
    stop_registered_app(worker, before)
    snapshot_token = uuid.uuid4().hex
    snapshot = snapshot_action(worker, "backup", prior_data_container, snapshot_token)
    report = {"device": udid[-8:], "bundle_id": sileo.BUNDLE_ID,
              "prior_cryptex_version": generations[0], "prior_executable_sha256": previous_code,
              "old_payload_sha256": old_digest, "new_payload_sha256": new_digest,
              "data_snapshot": snapshot, "data_snapshot_token": snapshot_token,
              "result": "UPDATE_STARTED"}
    try:
        update = queue_and_wait(worker, new_ipa, new_data, new_digest)
    except (OSError, RuntimeError, ValueError) as error:
        report.update(result="INDETERMINATE", error_code=type(error).__name__,
                      rollback="NOT_ATTEMPTED_WHILE_JOB_MAY_BE_RUNNING")
        return report
    report["update_job"] = update
    try:
        if update["status"] != 0:
            raise RuntimeError("SILEO_UPDATE_WORKER_FAILED")
        report["stage"] = "QUERY_NEW_REGISTRATION"
        after = sileo.query_candidate(udid)
        report["stage"] = "QUERY_NEW_CRYPTEX"
        observed = asyncio.run(native.cryptex_versions(udid))
        new_generations = [value for value in observed if value != generations[0]]
        report["stage"] = "HASH_NEW_EXECUTABLE"
        current_code = installed_hash(worker, after)
        report["stage"] = "RESOLVE_NEW_DATA_CONTAINER"
        current_data_container = canonical_data_container(worker)
        report["stage"] = "STOP_NEW_APP"
        stop_registered_app(worker, after)
        report["stage"] = "RESTORE_USER_DATA"
        restored_data = snapshot_action(worker, "restore", current_data_container,
                                        snapshot_token)
        report["data_restore"] = restored_data
        report["source_cache"] = synchronize_broker_cache(
            worker, udid, device["product"])
        report["stage"] = "VERIFY_NEW_INSTALLATION"
        if (after.get("CFBundleShortVersionString") != sileo.VERSION or
                current_code == previous_code or len(new_generations) != 1):
            report["verification_observed"] = {
                "data_container_preserved": current_data_container == prior_data_container,
                "executable_changed": current_code != previous_code,
                "new_cryptex_count": len(new_generations),
            }
            raise RuntimeError("SILEO_UPDATE_VERIFY_FAILED")
        report["stage"] = "LAUNCH_HEALTHCHECK"
        report["launch_health"] = launch_healthcheck(worker, after)
        report.update(result="INSTALLED_LAUNCH_VERIFIED", runtime_state="PARTIAL_UAT",
                      new_cryptex_version=new_generations[0],
                      new_executable_sha256=current_code,
                      data_container_preserved=current_data_container == prior_data_container,
                      data_restored_and_verified=True,
                      prior_cryptex_retained=generations[0] in observed,
                      rollback="NOT_NEEDED")
        return report
    except Exception as error:
        report.update(result="UPDATE_FAILED", error_code=type(error).__name__,
                      error_detail=str(error).split(":", 1)[0][:100],
                      rollback="IN_PROGRESS")
        try:
            existing = sileo.query_candidate(udid)
            if (existing and installed_hash(worker, existing) == previous_code and
                    generations[0] in asyncio.run(native.cryptex_versions(udid))):
                stop_registered_app(worker, existing)
                report["data_restore"] = snapshot_action(
                    worker, "restore", canonical_data_container(worker), snapshot_token)
                report["source_cache"] = synchronize_broker_cache(
                    worker, udid, device["product"])
                report["prior_launch_health"] = launch_healthcheck(worker, existing)
                report["rollback"] = "PRIOR_APP_STILL_REGISTERED_AND_VERIFIED"
                return report
            restore = queue_and_wait(worker, old_ipa, old_data, old_digest)
            report["restore_job"] = restore
            restored = sileo.query_candidate(udid)
            if restore["status"] != 0 or installed_hash(worker, restored) != previous_code:
                raise RuntimeError("SILEO_PRIOR_CANDIDATE_RESTORE_FAILED")
            stop_registered_app(worker, restored)
            report["data_restore"] = snapshot_action(
                worker, "restore", canonical_data_container(worker), snapshot_token)
            report["source_cache"] = synchronize_broker_cache(
                worker, udid, device["product"])
            report["prior_launch_health"] = launch_healthcheck(worker, restored)
            report["rollback"] = "PRIOR_APP_RESTORED_AND_VERIFIED"
        except Exception as restore_error:
            report["rollback"] = "FAILED"
            report["rollback_error_code"] = type(restore_error).__name__
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instance")
    parser.add_argument("udid")
    parser.add_argument("--old-ipa", type=Path, required=True)
    parser.add_argument("--new-ipa", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.instance, args.udid, args.old_ipa, args.new_ipa)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["result"] == "INSTALLED_LAUNCH_VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
