#!/usr/bin/env python3
"""Converge an existing 0-Sky host profile without reinstalling the SRD.

The profile is the per-instance public config.json plus a pinned device SSH
host key. Apple Lockdown pairing and the device-side 0-Sky pairing marker are
separate states and are never created or removed here.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any


class RepairError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def emit(state: str, stage: str, detail: str = "") -> None:
    print(f"[host-profile] [{state}] {stage}{': ' + detail if detail else ''}", flush=True)


def command(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    start = time.monotonic()
    emit("START", "command", " ".join(argv[:2]))
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        emit("TIMEOUT", "command", f"elapsed={time.monotonic() - start:.2f}s")
        raise RepairError("ERR_PROFILE_TIMEOUT", "bounded external probe timed out") from error
    emit("PASS" if result.returncode == 0 else "FAIL", "command",
         f"exit={result.returncode} elapsed={time.monotonic() - start:.2f}s")
    return result


def alias_for(udid: str) -> str:
    return "0sky-device-" + hashlib.sha256(udid.encode()).hexdigest()[:24]


def check_identity(udid: str, instance: str, port: int) -> None:
    if not re.fullmatch(r"[A-Za-z0-9-]{20,80}", udid):
        raise RepairError("ERR_WRONG_DEVICE", "invalid exact device UDID")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", instance):
        raise RepairError("ERR_PROFILE_PARSE", "invalid instance name")
    if not 1024 <= port <= 65535:
        raise RepairError("ERR_PROFILE_PARSE", "invalid local SSH port")


def secure_file(path: Path, *, required: bool = True) -> bool:
    if not path.exists():
        if required:
            raise RepairError("ERR_PROFILE_STALE", f"required host file is missing: {path.name}")
        return False
    if path.is_symlink() or not path.is_file():
        raise RepairError("ERR_PROFILE_PERMISSION", f"unsafe host file type: {path.name}")
    stat = path.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise RepairError("ERR_PROFILE_PERMISSION", f"unsafe owner or mode: {path.name}")
    if stat.st_size == 0:
        raise RepairError("ERR_PROFILE_PARSE", f"empty host file: {path.name}")
    return True


def validate_pin(path: Path, udid: str) -> None:
    secure_file(path)
    alias = alias_for(udid)
    records = 0
    for raw in path.read_text(encoding="ascii").splitlines():
        fields = raw.split()
        if len(fields) != 3 or fields[0] != alias or fields[1] not in {
            "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
        }:
            raise RepairError("ERR_PROFILE_VALIDATION", "host-key pin has an invalid record")
        try:
            if len(base64.b64decode(fields[2], validate=True)) < 32:
                raise ValueError("short key")
        except (ValueError, binascii.Error) as error:
            raise RepairError("ERR_PROFILE_VALIDATION", "host-key pin is malformed") from error
        records += 1
    if records == 0:
        raise RepairError("ERR_PROFILE_VALIDATION", "host-key pin has no records")


def read_config(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise RepairError("ERR_PROFILE_PERMISSION", "config path is not a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RepairError("ERR_PROFILE_PARSE", "config JSON is not parseable") from error
    if not isinstance(value, dict):
        raise RepairError("ERR_PROFILE_PARSE", "config JSON is not an object")
    return value


def expected_config(udid: str, instance: str, port: int, key: Path, support: Path) -> dict[str, Any]:
    return {
        "schema": 2,
        "instance": instance,
        "udid": udid,
        "ssh_host": "127.0.0.1",
        "ssh_port": str(port),
        "ssh_key": str(key),
        "ssh_known_hosts": str(support / "instances" / instance / "device-known-hosts"),
        "ssh_host_alias": alias_for(udid),
    }


def validate_config(value: dict[str, Any] | None, expected: dict[str, Any]) -> None:
    if value is None:
        raise RepairError("ERR_PROFILE_STALE", "config is missing")
    for field in ("udid", "instance", "ssh_port", "ssh_host", "ssh_key"):
        if field in value and str(value[field]) != str(expected[field]):
            raise RepairError("ERR_PROFILE_IDENTITY_MISMATCH", f"config {field} belongs to another endpoint")
    mismatched = sorted(key for key, wanted in expected.items() if value.get(key) != wanted)
    if mismatched:
        raise RepairError("ERR_PROFILE_STALE", "config is incomplete or stale" +
                          f"; mismatched {', '.join(mismatched)}")


def atomic_install(path: Path, data: dict[str, Any]) -> str:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.is_symlink() or parent.stat().st_uid != os.getuid():
        raise RepairError("ERR_PROFILE_PERMISSION", "instance directory is unsafe")
    os.chmod(parent, 0o700)
    temporary = parent / f".config.{os.getpid()}.{time.time_ns()}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        validate_config(read_config(temporary), data)
        quarantine = ""
        if path.exists():
            quarantine_path = parent / f"config.invalid.{time.strftime('%Y%m%d-%H%M%S')}.{time.time_ns()}.json"
            os.replace(path, quarantine_path)
            os.chmod(quarantine_path, 0o600)
            quarantine = str(quarantine_path)
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return quarantine
    finally:
        if temporary.exists():
            temporary.unlink()


def verify_live(udid: str, port: int, key: Path, pin: Path,
                support: Path, instance: str) -> None:
    emit("START", "verifying USB and existing Apple pairing")
    idevice_id = shutil.which("idevice_id")
    idevicepair = shutil.which("idevicepair")
    usb_active = bool(idevice_id and idevicepair and
                      udid in command([idevice_id, "-l"], 15).stdout.splitlines())
    if usb_active:
        paired = command([idevicepair, "-u", udid, "validate"], 60)
        if paired.returncode != 0:
            raise RepairError("ERR_PAIRING_INVALID", "Apple pairing did not validate for selected UDID")
        emit("PASS", "existing Apple pairing over USB")
    else:
        emit("SKIP", "USB pairing probe", "selected device is not on USB; verifying Wi-Fi")
        receipt = support / "instances" / instance / "pairing-state.json"
        secure_file(receipt)
        try:
            state = json.loads(receipt.read_text(encoding="utf-8"))
            fingerprint = state["mac_identity_fingerprint"]
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise RepairError("ERR_PAIRING_INVALID", "wireless pairing receipt is invalid") from error
        if state.get("device_udid") != udid or not re.fullmatch(r"SHA256:[A-Za-z0-9+/=]{32,}", fingerprint):
            raise RepairError("ERR_PROFILE_IDENTITY_MISMATCH", "wireless pairing receipt belongs to another identity")
        python = support / "instances" / instance / "venv/bin/python3"
        script = Path(__file__).resolve().parents[1] / "bridge/HostTools/apple_device_transport.py"
        checked = command([str(python), str(script), "verify-wireless", "--support", str(support),
                           "--target", udid, "--host-fingerprint", fingerprint], 60)
        try:
            wireless = json.loads(checked.stdout)
        except ValueError as error:
            raise RepairError("ERR_WIRELESS_PAIRING", "wireless verification gave invalid JSON") from error
        relationship = wireless.get("relationship", {})
        if checked.returncode != 0 or wireless.get("status") != "ready" or relationship.get("deviceIdentifier") != udid:
            raise RepairError("ERR_WIRELESS_PAIRING", "exact-device wireless pairing did not validate")
        emit("PASS", "existing Apple pairing over Wi-Fi", "exact UDID and Mac identity verified")
        if state.get("wireless", {}).get("status") != "ready":
            temporary = receipt.with_name(f".pairing-state.{os.getpid()}.{time.time_ns()}.tmp")
            state["wireless"] = wireless
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, receipt)
            emit("PASS", "wireless pairing receipt", "verified state committed")

    # Use the existing pairing helper's exact-UDID forward and key parser. It
    # never replaces a mismatched pin unless a separate explicit repair mode is
    # selected; this command deliberately does not expose that mode.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge" / "HostTools"))
    from pair import device_host_alias, ensure_device_host_key_pin, exact_iproxy_present, ssh_base, ssh

    if usb_active:
        if not exact_iproxy_present(udid, str(port)):
            raise RepairError("ERR_WRONG_DEVICE", "loopback forward is not bound to selected UDID")
        emit("PASS", "exact-device SSH forward")
        ssh_host, ssh_port = "127.0.0.1", str(port)
    else:
        emit("SKIP", "USB SSH forward", "using verified exact-device Wi-Fi route")
        ssh_host, ssh_port = f"{udid}.coredevice.local", "22"
    emit("START", "checking existing host-key pin")
    existing = pin.exists()
    if existing:
        validate_pin(pin, udid)
        emit("PASS", "existing host-key pin")
    else:
        if not usb_active:
            raise RepairError("ERR_PROFILE_STALE", "first device host-key pin requires exact-device USB enrollment")
        emit("START", "pinning host key through exact-device USB forward")
        ensure_device_host_key_pin(host="127.0.0.1", port=str(port), udid=udid,
                                   known_hosts=pin, allow_create=True)
        validate_pin(pin, udid)
        emit("PASS", "host-key pin installed")
    base = ssh_base(ssh_host, ssh_port, key, known_hosts=pin,
                    host_alias=device_host_alias(udid))
    emit("START", "verifying root SSH")
    try:
        result = ssh(base, "id -u", timeout=20)
    except subprocess.TimeoutExpired as error:
        raise RepairError("ERR_PROFILE_TIMEOUT", "root SSH probe timed out") from error
    except RuntimeError as error:
        raise RepairError("ERR_SSH_AUTH", "pinned root SSH authentication failed") from error
    if result.stdout.strip() != b"0":
        raise RepairError("ERR_ROOT_UNAVAILABLE", "SSH did not return uid 0")
    emit("PASS", "root SSH")


def repair(udid: str, instance: str, port: int, key: Path, support: Path, *, live: bool) -> str:
    check_identity(udid, instance, port)
    key = key.expanduser().resolve()
    secure_file(key)
    support = support.expanduser().resolve()
    directory = support / "instances" / instance
    if directory.is_symlink():
        raise RepairError("ERR_PROFILE_PERMISSION", "instance directory is a symlink")
    path = directory / "config.json"
    pin = directory / "device-known-hosts"
    expected = expected_config(udid, instance, port, key, support)
    emit("START", "checking existing profile")
    current: dict[str, Any] | None = None
    parse_error: RepairError | None = None
    try:
        current = read_config(path)
    except RepairError as error:
        if error.code != "ERR_PROFILE_PARSE":
            raise
        parse_error = error
    try:
        if parse_error is not None:
            raise parse_error
        validate_config(current, expected)
        validate_pin(pin, udid)
        if path.stat().st_mode & 0o077:
            raise RepairError("ERR_PROFILE_PERMISSION", "config mode is too broad")
        emit("PASS", "existing profile validated")
    except RepairError as error:
        if error.code == "ERR_PROFILE_IDENTITY_MISMATCH":
            raise
        emit("FAIL", "existing profile validation", error.code)
        validation_error = error
    else:
        # Transport failures cannot invalidate a structurally sound profile.
        # Keep it intact so a transient SSH or CoreDevice issue is resumable.
        if live:
            verify_live(udid, port, key, pin, support, instance)
        emit("SKIP", "profile creation", "valid profile reused")
        return "REUSE"
    if not live:
        raise validation_error
    verify_live(udid, port, key, pin, support, instance)
    emit("START", "writing temporary profile")
    updated = {**(current or {}), **expected}
    quarantined = atomic_install(path, updated)
    if quarantined:
        emit("PASS", "quarantined previous profile", "private instance directory")
    validate_config(read_config(path), expected)
    validate_pin(pin, udid)
    secure_file(path)
    emit("PASS", "installed profile validation")
    return "REPAIR"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--support", type=Path, default=Path.home() / "Library/Application Support/0-Sky")
    parser.add_argument("--live", action="store_true", help="verify exact USB, Apple pairing, SSH and repair host files")
    args = parser.parse_args()
    emit("START", "preflight")
    try:
        action = repair(args.udid, args.instance, args.port, args.ssh_key, args.support, live=args.live)
    except (RepairError, OSError, UnicodeError) as error:
        code = error.code if isinstance(error, RepairError) else "ERR_PROFILE_CREATION"
        emit("FAIL", "host-profile", code)
        print(f"FIRST_FAILING_TRANSITION=HOST_PROFILE_{code}", file=sys.stderr)
        print(f"SANITIZED_ERROR={str(error) if isinstance(error, RepairError) else type(error).__name__}", file=sys.stderr)
        return 2
    emit("PASS", "host-profile complete", action)
    print("HOST_PROFILE_CLASS=C")
    print("HOST_PROFILE_IMPLEMENTATION=0-Sky per-instance config.json and pinned SSH device host key")
    print(f"ACTION_TAKEN={action}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
