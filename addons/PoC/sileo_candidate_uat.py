#!/usr/bin/env python3
"""Transactional side-by-side UAT of the reviewed Sileo SRD candidate."""
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
import zipfile

import security_test_fixture_install as native
from repair_device_connection import profiles, usb_identity, worker_namespace


BUNDLE_ID = "com.amywhile.sileo"
APP = "Sileo.app"
EXECUTABLE = "Sileo"
VERSION = "2.5.1"
IDENTIFIER = "codes.rambo.research.crypstore." + hashlib.sha256(BUNDLE_ID.encode()).hexdigest()[:16]


def checked_payload(ipa: Path) -> tuple[bytes, str]:
    if ipa.is_symlink() or not ipa.is_file():
        raise RuntimeError("SILEO_CANDIDATE_MISSING")
    data = ipa.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    receipt = json.loads(Path(str(ipa) + ".json").read_text())
    if (receipt.get("artifact_sha256") != digest or
            receipt.get("bundle_id") != BUNDLE_ID or
            receipt.get("signature") != "ad-hoc SRD test candidate"):
        raise RuntimeError("SILEO_CANDIDATE_PROVENANCE_MISMATCH")
    with zipfile.ZipFile(ipa) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("SILEO_CANDIDATE_ARCHIVE_CORRUPT")
        members = archive.infolist()
        names = [member.filename for member in members]
        prefix = "Payload/" + APP + "/"
        if (len(names) != len(set(names)) or len(names) > 3000 or
                any(name.startswith("/") or ".." in Path(name).parts or
                    (name not in {"Payload/", "Payload/" + APP + "/"} and
                     not name.startswith(prefix)) or
                    (member.external_attr >> 16) & 0o170000 == 0o120000 or
                    member.file_size > 64 * 1024 * 1024
                    for member in members for name in (member.filename,))):
            raise RuntimeError("SILEO_CANDIDATE_UNSAFE_MEMBER")
        info = plistlib.loads(archive.read(prefix + "Info.plist"))
        executable = archive.read(prefix + EXECUTABLE)
        for name, metadata in receipt.get("bundled_runtime_libraries", {}).items():
            if name not in {"liblzma.5.dylib", "libzstd.1.dylib", "libiosexec.1.dylib"}:
                raise RuntimeError("SILEO_CANDIDATE_LIBRARY_MISMATCH")
            member = archive.getinfo(prefix + "Frameworks/" + name)
            mode = (member.external_attr >> 16) & 0o777
            if (mode & 0o444 != 0o444 or
                    hashlib.sha256(archive.read(prefix + "Frameworks/" + name)).hexdigest()
                    != metadata.get("signed_sha256")):
                raise RuntimeError("SILEO_CANDIDATE_LIBRARY_UNREADABLE_OR_MISMATCHED")
        if len(receipt.get("bundled_runtime_libraries", {})) != 3:
            raise RuntimeError("SILEO_CANDIDATE_LIBRARIES_MISSING")
        if (info.get("CFBundleIdentifier") != BUNDLE_ID or
                info.get("CFBundleExecutable") != EXECUTABLE or
                info.get("CFBundleShortVersionString") != VERSION or
                executable[:4] != b"\xcf\xfa\xed\xfe"):
            raise RuntimeError("SILEO_CANDIDATE_IDENTITY_MISMATCH")
        with tempfile.TemporaryDirectory(prefix="0sky-sileo-candidate-check-") as directory:
            archive.extractall(directory)
            app = Path(directory) / "Payload" / APP
            verified = subprocess.run(["/usr/bin/codesign", "--verify", "--deep",
                                       "--strict", str(app)], capture_output=True,
                                      timeout=30, check=False)
            if verified.returncode:
                raise RuntimeError("SILEO_CANDIDATE_SIGNATURE_INVALID")
    return data, digest


def configure_native(ipa: Path) -> None:
    # Reuse the existing exact-identity SRD transaction/rollback implementation.
    native.IPA = ipa
    native.BUNDLE_ID = BUNDLE_ID
    native.EXECUTABLE = EXECUTABLE
    native.APP = APP
    native.IDENTIFIER = IDENTIFIER


def query_candidate(udid: str) -> dict:
    # Apple's USB installation proxy remains available when the native app
    # inventory tunnel stalls after a Cryptex registration.
    result = subprocess.run(
        [sys.executable, "-m", "pymobiledevice3", "apps", "query", BUNDLE_ID,
         "--udid", udid], capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("SILEO_CANDIDATE_INVENTORY_UNAVAILABLE")
    return json.loads(result.stdout).get(BUNDLE_ID, {})


def rollback_candidate(udid: str) -> str:
    installed = query_candidate(udid)
    versions = asyncio.run(native.cryptex_versions(udid))
    if len(versions) > 1:
        raise RuntimeError("AMBIGUOUS_SILEO_CANDIDATE_CRYPTEX")
    if installed:
        removed = subprocess.run(
            [sys.executable, "-m", "pymobiledevice3", "apps", "uninstall", BUNDLE_ID,
             "--udid", udid], capture_output=True, text=True, timeout=90, check=False)
        if removed.returncode or query_candidate(udid):
            raise RuntimeError("SILEO_CANDIDATE_APP_ROLLBACK_FAILED")
    if versions:
        asyncio.run(native.retire_fixture_cryptex(udid, versions[0]))
    if query_candidate(udid) or asyncio.run(native.cryptex_versions(udid)):
        raise RuntimeError("SILEO_CANDIDATE_ROLLBACK_NOT_CLEAN")
    return "VERIFIED" if installed or versions else "NOT_NEEDED"


def run(instance: str, udid: str, ipa: Path, apply: bool) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9-]{20,80}", udid):
        raise RuntimeError("INVALID_EXACT_UDID")
    selected = profiles(instance_name=instance)
    if udid not in selected or asyncio.run(usb_identity(udid))["udid"] != udid:
        raise RuntimeError("EXACT_USB_PROFILE_MISMATCH")
    data, digest = checked_payload(ipa)
    configure_native(ipa)
    installed = query_candidate(udid)
    generations = asyncio.run(native.cryptex_versions(udid))
    if installed or generations:
        raise RuntimeError("SILEO_CANDIDATE_ALREADY_PRESENT_OR_PARTIAL")
    report = {"device": udid[-8:], "bundle_id": BUNDLE_ID,
              "source_sha256": digest, "prior_candidate_absent": True,
              "prior_existing_sileo_preserved": True, "result": "PREFLIGHT_PASS"}
    if not apply:
        return report
    worker = worker_namespace(selected[udid][1])
    job = native.queue(worker, data, digest)
    report["job_id"] = job
    try:
        result = native.await_result(worker, job)
    except (OSError, RuntimeError, ValueError) as error:
        report.update(result="INDETERMINATE", error_code=type(error).__name__,
                      rollback="NOT_ATTEMPTED_WHILE_JOB_MAY_BE_RUNNING")
        return report
    staged = native.SPOOL + "/" + job + "/input.ipa"
    worker["ssh"]("rm -f -- " + shlex.quote(staged), timeout=20, check=False)
    report["worker_status"] = result.get("status")
    if result.get("status") != 0:
        report.update(result="INSTALL_FAILED", error_code="WORKER_INSTALL_FAILED",
                      error=str(result.get("stderr") or "")[-500:])
        try:
            report["rollback"] = rollback_candidate(udid)
        except Exception as error:
            report["rollback"] = "FAILED"
            report["rollback_error_code"] = type(error).__name__
        return report
    current = query_candidate(udid)
    generations = asyncio.run(native.cryptex_versions(udid))
    if (current.get("CFBundleIdentifier", BUNDLE_ID) != BUNDLE_ID or
            current.get("CFBundleShortVersionString") != VERSION or
            not current.get("CFBundleExecutable") or len(generations) != 1):
        report.update(result="VERIFY_FAILED", error_code="REGISTRATION_OR_TRUST_MISMATCH")
        try:
            report["rollback"] = rollback_candidate(udid)
        except Exception as error:
            report["rollback"] = "FAILED"
            report["rollback_error_code"] = type(error).__name__
        return report
    report.update(result="INSTALLED_LAUNCH_VERIFIED", cryptex_version=generations[0],
                  rollback="NOT_NEEDED", runtime_state="PARTIAL_UAT")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instance")
    parser.add_argument("udid")
    parser.add_argument("--ipa", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    result = run(args.instance, args.udid, args.ipa, args.apply)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["result"] in {"PREFLIGHT_PASS", "INSTALLED_LAUNCH_VERIFIED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
