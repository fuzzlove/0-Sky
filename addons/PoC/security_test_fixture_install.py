#!/usr/bin/env python3
"""Install the controlled 0-Sky test app through the paired research-app worker."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shlex
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile

from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.services.cryptexd import CryptexdService

from repair_device_connection import profiles, usb_identity, worker_namespace


HERE = Path(__file__).resolve().parent
IPA = HERE.parents[1] / "tools/security_test_app/dist/0-Sky-Security-Test-1.0.0.ipa"
BUNDLE_ID = "com.liquidsky.SecurityTest"
EXECUTABLE = "ZeroSkySecurityTest"
APP = "ZeroSkySecurityTest.app"
IDENTIFIER = "codes.rambo.research.crypstore." + hashlib.sha256(BUNDLE_ID.encode()).hexdigest()[:16]
SPOOL = "/var/jb/var/spool/crypstore/jobs"


def checked_payload() -> tuple[bytes, str]:
    if IPA.is_symlink() or not IPA.is_file():
        raise RuntimeError("REVIEWED_TEST_IPA_MISSING")
    data = IPA.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    receipt = (IPA.parent / "SHA256SUMS").read_text().split()
    if receipt != [digest, IPA.name]:
        raise RuntimeError("TEST_IPA_HASH_RECEIPT_MISMATCH")
    with zipfile.ZipFile(IPA) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("TEST_IPA_ARCHIVE_CORRUPT")
        names = archive.namelist()
        prefix = "Payload/" + APP + "/"
        if (len(names) != len(set(names)) or len(names) > 32 or
                any(name.startswith("/") or ".." in Path(name).parts or
                    (name not in {"Payload/", "Payload/" + APP + "/"} and
                     not name.startswith(prefix)) or
                    (item.external_attr >> 16) & 0o170000 == 0o120000 or
                    item.file_size > 32 * 1024 * 1024
                    for item in archive.infolist() for name in (item.filename,))):
            raise RuntimeError("TEST_IPA_UNSAFE_MEMBER")
        info = plistlib.loads(archive.read(prefix + "Info.plist"))
        binary = archive.read(prefix + EXECUTABLE)
        if (info.get("CFBundleIdentifier") != BUNDLE_ID or
                info.get("CFBundleExecutable") != EXECUTABLE or
                info.get("CFBundleShortVersionString") != "1.0.0" or
                binary[:4] != b"\xcf\xfa\xed\xfe"):
            raise RuntimeError("TEST_IPA_IDENTITY_OR_ARCH_MISMATCH")
        with tempfile.TemporaryDirectory(prefix="0sky-test-verification-") as folder:
            archive.extractall(folder)
            app = Path(folder) / "Payload" / APP
            signed = subprocess.run(["/usr/bin/codesign", "--verify", "--deep",
                                     "--strict", str(app)], capture_output=True,
                                    timeout=30, check=False)
            if signed.returncode:
                raise RuntimeError("TEST_IPA_SIGNATURE_INVALID")
    return data, digest


def query_app(udid: str) -> dict:
    completed = subprocess.run(
        [sys.executable, "-m", "pymobiledevice3",
         "apps", "query", BUNDLE_ID, "--native", "--udid", udid],
        capture_output=True, text=True, timeout=30, check=False)
    if completed.returncode:
        raise RuntimeError("TEST_APP_INVENTORY_UNAVAILABLE")
    return json.loads(completed.stdout).get(BUNDLE_ID, {})


async def cryptex_versions(udid: str) -> list[str]:
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid:
            raise RuntimeError("REMOTEXPC_IDENTITY_CHANGED")
        rows = await asyncio.wait_for(CryptexdService(rsd).copy_installed(), timeout=20)
    return [item.version for item in rows if item.identifier == IDENTIFIER]


async def retire_fixture_cryptex(udid: str, version: str) -> None:
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid:
            raise RuntimeError("REMOTEXPC_IDENTITY_CHANGED")
        await asyncio.wait_for(CryptexdService(rsd).uninstall(IDENTIFIER, version),
                               timeout=60)


def rollback_partial(udid: str) -> str:
    """Remove only the fixture identity, which preflight established absent."""
    installed = query_app(udid)
    versions = asyncio.run(cryptex_versions(udid))
    if len(versions) > 1:
        raise RuntimeError("AMBIGUOUS_TEST_FIXTURE_CRYPTEX")
    if installed:
        completed = subprocess.run(
            [sys.executable, "-m", "pymobiledevice3", "apps", "uninstall",
             BUNDLE_ID, "--native", "--udid", udid], capture_output=True,
            text=True, timeout=90, check=False)
        if completed.returncode or query_app(udid):
            raise RuntimeError("TEST_FIXTURE_APP_ROLLBACK_FAILED")
    if versions:
        asyncio.run(retire_fixture_cryptex(udid, versions[0]))
    if query_app(udid) or asyncio.run(cryptex_versions(udid)):
        raise RuntimeError("TEST_FIXTURE_ROLLBACK_NOT_CLEAN")
    return "VERIFIED" if installed or versions else "NOT_NEEDED"


def remote(worker: dict, command: str, *, data: bytes | None = None,
           timeout: int = 30) -> bytes:
    result = worker["ssh"](command, input_data=data, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError("PINNED_SSH_TRANSFER_FAILED")
    return result.stdout


def queue(worker: dict, data: bytes, digest: str) -> str:
    job = uuid.uuid4().hex
    root = SPOOL + "/" + job
    remote(worker, "mkdir -m 700 -- " + shlex.quote(root))
    submission_started = False
    try:
        remote(worker, "cat > " + shlex.quote(root + "/input.ipa"), data=data, timeout=90)
        observed = remote(worker, "sha256sum " + shlex.quote(root + "/input.ipa")).decode()
        if observed.split()[0] != digest:
            raise RuntimeError("TEST_IPA_TRANSFER_HASH_MISMATCH")
        request = {"job_id": job, "operation": "install",
                   "original_name": IPA.name, "source_sha256": digest,
                   "created_at": int(time.time())}
        remote(worker, "cat > " + shlex.quote(root + "/request.json.tmp"),
               data=(json.dumps(request, sort_keys=True) + "\n").encode())
        submission_started = True
        remote(worker, "mv -- " + shlex.quote(root + "/request.json.tmp") + " " +
               shlex.quote(root + "/request.json"))
    except Exception:
        if not submission_started:
            worker["ssh"]("rm -rf -- " + shlex.quote(root), timeout=20, check=False)
        raise
    return job


def await_result(worker: dict, job: str, seconds: int = 600) -> dict:
    path = SPOOL + "/" + job + "/result.json"
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = worker["ssh"]("if [ -f " + shlex.quote(path) + " ]; then cat " +
                               shlex.quote(path) + "; fi", timeout=20, check=False)
        if result.returncode == 0 and result.stdout.strip():
            value = json.loads(result.stdout)
            if not isinstance(value, dict):
                raise RuntimeError("TEST_FIXTURE_RESULT_MALFORMED")
            return value
        time.sleep(3)
    raise RuntimeError("TEST_FIXTURE_WORKER_RESULT_TIMEOUT")


def run(instance: str, udid: str, *, apply: bool) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9-]{20,80}", udid):
        raise RuntimeError("INVALID_EXACT_UDID")
    selected = profiles(instance_name=instance)
    if udid not in selected or asyncio.run(usb_identity(udid))["udid"] != udid:
        raise RuntimeError("EXACT_USB_PROFILE_MISMATCH")
    data, digest = checked_payload()
    installed = query_app(udid)
    versions = asyncio.run(cryptex_versions(udid))
    if installed or versions:
        raise RuntimeError("TEST_FIXTURE_ALREADY_PRESENT_OR_PARTIAL")
    report = {"device_suffix": udid[-8:], "bundle_id": BUNDLE_ID,
              "payload_sha256": digest, "prior_app_absent": True,
              "prior_cryptex_absent": True,
              "result": "PREFLIGHT_PASS"}
    if not apply:
        return report
    worker = worker_namespace(selected[udid][1])
    job = queue(worker, data, digest)
    report["job"] = job
    try:
        value = await_result(worker, job)
    except (OSError, RuntimeError, ValueError):
        report.update(result="INDETERMINATE", error_code="WORKER_RESULT_UNAVAILABLE",
                      rollback="NOT_ATTEMPTED_WHILE_JOB_MAY_BE_RUNNING")
        return report
    report["worker_status"] = value.get("status")
    if value.get("status") != 0:
        report.update(result="INSTALL_FAILED", error_code="WORKER_INSTALL_FAILED")
        try:
            report["rollback"] = rollback_partial(udid)
        except Exception as error:
            report["rollback"] = "FAILED"
            report["rollback_error_code"] = type(error).__name__
        return report
    current = query_app(udid)
    versions = asyncio.run(cryptex_versions(udid))
    if (current.get("CFBundleIdentifier", BUNDLE_ID) != BUNDLE_ID or
            current.get("CFBundleShortVersionString") != "1.0.0" or
            len(versions) != 1):
        report.update(result="VERIFY_FAILED", error_code="REGISTRATION_OR_TRUST_MISMATCH")
        try:
            report["rollback"] = rollback_partial(udid)
        except Exception as error:
            report["rollback"] = "FAILED"
            report["rollback_error_code"] = type(error).__name__
        return report
    report.update(result="INSTALLED_AND_REGISTERED", cryptex_version=versions[0],
                  rollback="NOT_NEEDED")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instance")
    parser.add_argument("udid")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    result = run(args.instance, args.udid, apply=args.apply)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] in {"PREFLIGHT_PASS", "INSTALLED_AND_REGISTERED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
