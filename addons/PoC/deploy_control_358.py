#!/usr/bin/env python3
"""Atomically update Control inventory support and install one verified Control IPA."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import shlex
import sys
import time
import uuid

from repair_device_connection import profiles, ssh_probe, usb_identity, worker_namespace


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime/zero_sky_core"))
from control_payload import create_manifest, verify_manifest  # noqa: E402


REMOTE_APPCTL = "/var/jb/usr/local/libexec/crypstore-appctl.py"
REMOTE_SPOOL = "/var/jb/var/spool/crypstore/jobs"


def remote_python(namespace: dict, expression: str, *, timeout: int = 60):
    command = "/var/jb/usr/bin/python3 -c " + shlex.quote(expression)
    result = namespace["ssh"](command, timeout=timeout, check=True)
    return result.stdout.decode("utf-8", "replace")


def install_appctl(namespace: dict, source: Path) -> dict:
    data = source.read_bytes()
    expected = hashlib.sha256(data).hexdigest()
    temporary = REMOTE_APPCTL + ".new." + uuid.uuid4().hex
    committed = False
    had_existing = namespace["ssh"](
        "test -f " + shlex.quote(REMOTE_APPCTL), timeout=30, check=False
    ).returncode == 0
    namespace["ssh"]("cat > " + shlex.quote(temporary), input_data=data,
                     timeout=90, check=True)
    try:
        observed = remote_python(namespace,
            "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path(" +
            repr(temporary) + ").read_bytes()).hexdigest())").strip()
        if observed != expected:
            raise RuntimeError("uploaded app inventory helper hash differs")
        remote_python(namespace,
            "p=" + repr(temporary) + ";compile(open(p,'rb').read(),p,'exec');print('OK')")
        backup = "/var/jb/var/lib/crypstore/backups/crypstore-appctl.py." + expected[:16]
        command = " && ".join([
            "mkdir -p /var/jb/var/lib/crypstore/backups",
            "if test -f " + shlex.quote(REMOTE_APPCTL) + "; then cp -p " +
                shlex.quote(REMOTE_APPCTL) + " " + shlex.quote(backup) + "; fi",
            "chmod 755 " + shlex.quote(temporary),
            "mv " + shlex.quote(temporary) + " " + shlex.quote(REMOTE_APPCTL),
        ])
        namespace["ssh"](command, timeout=60, check=True)
        committed = True
        output = namespace["ssh"](
            "/var/jb/usr/bin/python3 " + shlex.quote(REMOTE_APPCTL) + " list --json",
            timeout=90, check=True).stdout
        inventory = json.loads(output)
        if not isinstance(inventory.get("applications"), list) or not isinstance(
                inventory.get("tweaks"), list):
            raise RuntimeError("updated app inventory helper returned an invalid schema")
    except Exception:
        namespace["ssh"]("rm -f " + shlex.quote(temporary), timeout=30, check=False)
        if committed:
            restore = ("cp -p " + shlex.quote(backup) + " " + shlex.quote(REMOTE_APPCTL)
                       if had_existing else "rm -f " + shlex.quote(REMOTE_APPCTL))
            namespace["ssh"](restore, timeout=60, check=False)
        raise
    return {"sha256": expected, "backup": backup,
            "applications": len(inventory["applications"]),
            "tweaks": len(inventory["tweaks"])}


def queue_control(namespace: dict, ipa: Path, manifest: dict) -> dict:
    job_id = str(uuid.uuid4())
    remote_root = REMOTE_SPOOL + "/" + job_id
    namespace["ssh"]("mkdir -m 700 -p " + shlex.quote(remote_root),
                     timeout=30, check=True)
    try:
        data = ipa.read_bytes()
        namespace["ssh"]("cat > " + shlex.quote(remote_root + "/input.ipa"),
                         input_data=data, timeout=600, check=True)
        request = {
            "job_id": job_id,
            "operation": "control-install",
            "original_name": "0-Sky Control",
            "source_sha256": manifest["ipa_sha256"],
            "required_entitlements": manifest["permissions"]["required_entitlements"],
            "created_at": int(time.time()),
        }
        payload = (json.dumps(request, sort_keys=True) + "\n").encode()
        namespace["ssh"]("cat > " + shlex.quote(remote_root + "/request.json"),
                         input_data=payload, timeout=30, check=True)
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            result = namespace["ssh"]("cat " + shlex.quote(remote_root + "/result.json"),
                                      timeout=30, check=False)
            if result.returncode == 0 and result.stdout.strip():
                value = json.loads(result.stdout)
                if not isinstance(value, dict) or not isinstance(value.get("status"), int):
                    raise RuntimeError("Control worker returned an invalid result")
                return {"job_id": job_id, **value}
            time.sleep(2)
        raise TimeoutError("Control installation did not complete within 30 minutes")
    except Exception:
        namespace["ssh"]("rm -rf " + shlex.quote(remote_root), timeout=30, check=False)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--ipa", required=True, type=Path)
    parser.add_argument("--appctl", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    selected = profiles(instance_name=args.instance)
    if set(selected) != {args.udid}:
        raise RuntimeError("exact paired worker profile does not match requested UDID")
    identity = asyncio.run(usb_identity(args.udid))
    if identity["udid"] != args.udid:
        raise RuntimeError("USB device identity changed")
    namespace = worker_namespace(selected[args.udid][1])
    probe = ssh_probe(namespace)
    if not probe["connected"]:
        raise RuntimeError("pinned root SSH connection is unavailable")

    entitlements = ROOT / "control/TrollStoreLite/entitlements.plist"
    manifest = create_manifest(args.ipa, entitlements)
    verify_manifest(args.ipa, manifest)
    if manifest["identity"].get("CFBundleIdentifier") != "com.liquidsky.CrypStore":
        raise RuntimeError("refusing to deploy a non-Control payload")

    appctl_result = install_appctl(namespace, args.appctl)
    install_result = queue_control(namespace, args.ipa, manifest)
    evidence = {
        "device": identity,
        "instance": args.instance,
        "payload": {"identity": manifest["identity"],
                    "sha256": manifest["ipa_sha256"]},
        "inventory_helper": appctl_result,
        "installation": install_result,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"device": args.udid[-8:],
                      "version": manifest["identity"]["CFBundleShortVersionString"],
                      "apps": appctl_result["applications"],
                      "tweaks": appctl_result["tweaks"],
                      "status": install_result.get("status"),
                      "rollback": install_result.get("rollback")}, sort_keys=True))
    return 0 if install_result.get("status") == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
