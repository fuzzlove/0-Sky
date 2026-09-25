#!/usr/bin/env python3
"""Install only a missing 0-Sky Control app using the existing device broker."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from repair_host_profile import RepairError, emit, repair
from repair_host_worker import verify_kit_file


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stage_control_ipa(source: Path, directory: Path) -> Path:
    target_dir = directory / "packages"
    target_dir.mkdir(mode=0o700, exist_ok=True)
    destination = target_dir / source.name
    expected = sha256(source)
    if destination.exists():
        if destination.is_symlink() or not destination.is_file() or sha256(destination) != expected:
            raise RepairError("ERR_PROFILE_STALE", "existing Control IPA differs from verified kit")
        emit("SKIP", "Control IPA staging", "verified copy reused")
        return destination
    temporary = target_dir / f".{source.name}.{os.getpid()}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, output)
            output.flush()
            os.fsync(output.fileno())
        if sha256(temporary) != expected:
            raise RepairError("ERR_PROFILE_VALIDATION", "staged Control IPA hash mismatch")
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    emit("PASS", "Control IPA staging")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--ssh-key", required=True, type=Path)
    parser.add_argument("--support", type=Path, default=Path.home() / "Library/Application Support/0-Sky")
    parser.add_argument("--kit", type=Path, default=Path(__file__).resolve().parents[1] /
                        "bridge/0SkyBridge/Resources/Scripts/kit")
    args = parser.parse_args()
    try:
        support = args.support.expanduser().resolve()
        kit = args.kit.resolve()
        repair(args.udid, args.instance, args.port, args.ssh_key, support, live=True)
        directory = support / "instances" / args.instance
        ipa = verify_kit_file(kit, "packages/Commissary-Universal.ipa")
        stage_control_ipa(ipa, directory)
        python = directory / "venv/bin/python3"
        if not python.is_file():
            raise RepairError("ERR_PROFILE_STALE", "isolated host worker runtime is missing")
        installer = kit / "host-mac/bootstrap_device.py"
        if not installer.is_file():
            raise RepairError("ERR_PROFILE_STALE", "bundled device bootstrap helper is missing")
        argv = [str(python), str(installer), "--support", str(support),
                "--instance-name", args.instance, "--apps-only", "--commissary"]
        emit("START", "installing missing Control app", "packages remain unchanged")
        start = time.monotonic()
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=1900, check=False)
        except subprocess.TimeoutExpired as error:
            raise RepairError("ERR_PROFILE_TIMEOUT", "Control app installer timed out") from error
        emit("PASS" if result.returncode == 0 else "FAIL", "Control installer",
             f"exit={result.returncode} elapsed={time.monotonic() - start:.2f}s")
        if result.returncode:
            # The child may include remote command text or diagnostic output.
            # Keep stdout/stderr separate in memory, but expose only its exit
            # status here; the device and host logs remain available in place.
            raise RepairError("ERR_PROFILE_CREATION", "Control app installer exited nonzero")
        print("CONTROL_ACTION=INSTALLED_AND_VERIFIED")
        return 0
    except (RepairError, OSError) as error:
        code = error.code if isinstance(error, RepairError) else "ERR_PROFILE_CREATION"
        emit("FAIL", "Control repair", code)
        print(f"FIRST_FAILING_TRANSITION=0SKY_CONTROL_{code}", file=sys.stderr)
        print(f"SANITIZED_ERROR={str(error) if isinstance(error, RepairError) else type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
