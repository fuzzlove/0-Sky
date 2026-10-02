#!/usr/bin/env python3
"""Verify Control's paired Crane target handoff without foreground UI automation."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path, PurePosixPath
import shlex
import time
import uuid

from crane_functional_uat import (atomic_write, cleanup_remote_container,
                                  fixture_metadata, mobile_bootstrap_context,
                                  run_crane_control)
from repair_device_connection import profiles, usb_identity, worker_namespace


BUNDLE = "com.liquidsky.SecurityTest"
PACKAGE = "com.opa334.crane"


def core(worker: dict, operation: str, parameters: dict) -> dict:
    payload = {"protocolVersion": 1, "requestId": str(uuid.uuid4()),
               "timestamp": time.time(), "operation": operation,
               "parameters": parameters}
    program = r'''import http.client,json,pathlib,sys
payload=json.loads(sys.stdin.read());body=json.dumps(payload,separators=(",",":"))
token=pathlib.Path("/var/jb/etc/trollstorelite-srd-bridge.token").read_text().strip()
c=http.client.HTTPConnection("127.0.0.1",48654,timeout=120)
c.request("POST","/v1/core",body,{"Content-Type":"application/json","Content-Length":str(len(body.encode())),"X-TrollStore-Bridge-Token":token})
r=c.getresponse();print(json.dumps({"http":r.status,"body":json.loads(r.read())},sort_keys=True))
'''
    result = worker["ssh"](
        "/var/jb/usr/bin/python3 -c " + shlex.quote(program),
        input_data=json.dumps(payload).encode(), timeout=150, check=True)
    response = json.loads(result.stdout)
    envelope = response.get("body")
    if response.get("http") != 200 or not isinstance(envelope, dict) or not envelope.get("success"):
        raise RuntimeError("Control core rejected Crane target update: " +
                           str((envelope or {}).get("errorMessage") or response)[:500])
    return envelope["result"]


def handoff_value(worker: dict, data_root: str) -> str | None:
    root = PurePosixPath(data_root)
    path = root / "Library/0Sky/Crane/active-container"
    program = f'''import json,pathlib
p=pathlib.Path({str(path)!r})
print(json.dumps({{"exists":p.is_file() and not p.is_symlink(),"value":p.read_text().strip() if p.is_file() and not p.is_symlink() else None}}))
'''
    result = worker["ssh"](
        "/var/jb/usr/bin/python3 -c " + shlex.quote(program), timeout=30, check=True)
    value = json.loads(result.stdout)
    return value.get("value") if value.get("exists") else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance-name", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    identity = asyncio.run(usb_identity(args.udid))
    if identity.get("udid") != args.udid:
        raise RuntimeError("exact USB identity changed")
    configured = profiles(instance_name=args.instance_name)
    if set(configured) != {args.udid}:
        raise RuntimeError("paired worker profile differs from the selected device")
    worker = worker_namespace(configured[args.udid][1])
    data_root, fixture_version = fixture_metadata(args.udid)
    launchctl = mobile_bootstrap_context(worker)
    report = {"device": identity, "bundle_id": BUNDLE,
              "fixture_version": fixture_version, "result": "FAIL",
              "rollback": "PENDING", "checked_at": int(time.time())}
    prepared = None
    cleanup_errors: list[str] = []
    try:
        inventory = core(worker, "getTweakTargetApps", {"package": PACKAGE})
        selected_before = inventory.get("selected") or []
        if selected_before:
            raise RuntimeError("Crane target UAT requires an initially empty controlled allowlist")
        fixture = next((item for item in inventory.get("applications", [])
                        if item.get("bundleID") == BUNDLE), None)
        if not fixture or fixture.get("compatibility") != "COMPATIBLE_WITH_ADAPTER":
            raise RuntimeError("controlled fixture is not adapter compatible")
        prepared = run_crane_control(worker, launchctl, {
            "operation": "prepare", "suffix": uuid.uuid4().hex[:8]})
        temporary = prepared["temporary"]
        enabled = core(worker, "setTweakTargets", {
            "package": PACKAGE, "bundleIDs": [BUNDLE],
            "dataRoots": {BUNDLE: data_root}})
        observed = handoff_value(worker, data_root)
        if enabled.get("selected") != [BUNDLE] or observed != temporary:
            raise RuntimeError("paired Crane enable handoff did not commit exact active container")
        report["enable"] = {"selected": enabled["selected"],
                            "handoff": "MATCHED_ACTIVE_CONTAINER"}
        disabled = core(worker, "setTweakTargets", {
            "package": PACKAGE, "bundleIDs": [],
            "dataRoots": {BUNDLE: data_root}})
        observed_after = handoff_value(worker, data_root)
        if disabled.get("selected") or observed_after is not None:
            raise RuntimeError("paired Crane disable handoff did not restore the default state")
        report["disable"] = {"selected": disabled["selected"],
                             "handoff": "ABSENT_DEFAULT"}
        report["result"] = "PASS"
    except Exception as error:
        report["error"] = str(error)
    finally:
        if prepared:
            try:
                try:
                    core(worker, "setTweakTargets", {
                        "package": PACKAGE, "bundleIDs": [],
                        "dataRoots": {BUNDLE: data_root}})
                except Exception as error:
                    cleanup_errors.append("target rollback: " + str(error))
                restored = run_crane_control(worker, launchctl, {
                    "operation": "restore", "original": prepared["original"],
                    "temporary": prepared["temporary"]})
                report["crane_restore"] = restored
                if restored.get("bridge_cleanup_required"):
                    report["paired_cleanup"] = cleanup_remote_container(
                        worker, data_root, prepared["selected_home"], prepared["temporary"])
                    report["metadata_cleanup"] = run_crane_control(worker, launchctl, {
                        "operation": "remove_metadata",
                        "identifiers": [prepared["temporary"]]})
                report["restore_verification"] = run_crane_control(
                    worker, launchctl, {"operation": "verify_restore",
                    "original": prepared["original"], "temporary": prepared["temporary"]})
            except Exception as error:
                cleanup_errors.append("Crane rollback: " + str(error))
        report["rollback_errors"] = cleanup_errors
        report["rollback"] = "PASS" if not cleanup_errors else "FAILED"
        if cleanup_errors:
            report["result"] = "FAIL"
    atomic_write(args.output.resolve(),
                 (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["result"] == "PASS" and report["rollback"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
