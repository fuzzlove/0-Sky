#!/usr/bin/env python3
"""Restore only the missing 0-Sky Mac worker for one verified SRD profile.

This stages the existing bundled worker and its pinned offline Python runtime.
It never installs device packages, resumes queued device jobs, or alters Apple
pairing. The selected device's profile and root SSH path must already validate.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import time

from repair_host_profile import RepairError, alias_for, command, emit, repair


def verify_kit_file(kit: Path, relative: str) -> Path:
    source = kit / relative
    if not source.is_file() or source.is_symlink():
        raise RepairError("ERR_PROFILE_CREATION", f"bundled worker file missing: {relative}")
    manifest = kit / "SHA256SUMS"
    expected = None
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1].removeprefix("./") == relative:
            expected = parts[0]
            break
    if expected is None:
        raise RepairError("ERR_PROFILE_VALIDATION", f"worker manifest omits {relative}")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if digest != expected:
        raise RepairError("ERR_PROFILE_VALIDATION", f"bundled worker hash mismatch: {relative}")
    return source


def stage_directory(source: Path, destination: Path, required: str) -> None:
    if destination.exists():
        if destination.is_symlink() or not (destination / required).is_file():
            raise RepairError("ERR_PROFILE_STALE", f"existing {destination.name} directory is incomplete")
        emit("SKIP", f"staging {destination.name}", "existing directory reused")
        return
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    if temporary.exists():
        raise RepairError("ERR_PROFILE_STALE", f"stale temporary {destination.name} directory exists")
    emit("START", f"staging {destination.name}")
    shutil.copytree(source, temporary, symlinks=False)
    if not (temporary / required).is_file():
        raise RepairError("ERR_PROFILE_VALIDATION", f"staged {destination.name} is incomplete")
    os.replace(temporary, destination)
    emit("PASS", f"staging {destination.name}")


def ensure_venv(directory: Path, wheelhouse: Path, requirements: Path) -> Path:
    python = directory / "venv/bin/python3"
    imports = "import pymobiledevice3,cryptography,zstandard,Crypto"
    if python.is_file():
        check = command([str(python), "-c", imports], 20)
        if check.returncode == 0:
            emit("SKIP", "Python runtime", "existing environment reused")
            return python
        raise RepairError("ERR_PROFILE_STALE", "existing instance Python environment is incomplete")
    emit("START", "creating isolated Python runtime")
    created = command([sys.executable, "-m", "venv", str(directory / "venv")], 120)
    if created.returncode != 0:
        raise RepairError("ERR_PROFILE_CREATION", "unable to create instance Python environment")
    installed = command([str(python), "-m", "pip", "install", "--no-index",
                         "--find-links", str(wheelhouse), "--requirement", str(requirements)], 600)
    if installed.returncode != 0:
        raise RepairError("ERR_PROFILE_CREATION", "offline Python dependency installation failed")
    check = command([str(python), "-c", imports], 20)
    if check.returncode != 0:
        raise RepairError("ERR_PROFILE_VALIDATION", "instance Python imports failed")
    emit("PASS", "isolated Python runtime")
    return python


def no_actionable_jobs(base: list[str]) -> None:
    from pair import ssh
    probe = ("/var/jb/usr/bin/python3 -c 'import glob,os; "
             "p=glob.glob(\"/var/jb/var/spool/crypstore/jobs/*/request.json\")+"
             "glob.glob(\"/var/jb/var/spool/crypstore/jobs/*/processing.json\"); "
             "print(sum(not os.path.isfile(os.path.join(os.path.dirname(x),"
             "\"result.json\")) for x in p))'")
    result = ssh(base, probe, timeout=20)
    if result.stdout.strip() != b"0":
        raise RepairError("ERR_PROFILE_STALE", "uncompleted device jobs require separate review before worker start")
    emit("PASS", "queued-job preflight", "no actionable jobs")


def ensure_bluetooth_token(directory: Path, base: list[str]) -> Path:
    """Obtain the existing device token through the already pinned SSH path."""
    from pair import ssh
    result = ssh(base, "cat /var/jb/etc/trollstorelite-srd-bridge.token", timeout=20)
    token = result.stdout.decode("ascii", errors="ignore").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise RepairError("ERR_BRIDGE_CONNECTION", "device Bluetooth token is missing or malformed")
    token_dir = directory / "bluetooth"
    token_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(token_dir, 0o700)
    destination = token_dir / "token"
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise RepairError("ERR_PROFILE_PERMISSION", "unsafe existing Bluetooth token file")
        if destination.read_text(encoding="ascii").strip() == token:
            os.chmod(destination, 0o600)
            emit("SKIP", "Bluetooth token", "existing device token reused")
            return destination
    temporary = token_dir / f".token.{os.getpid()}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write(token + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    emit("PASS", "Bluetooth token", "device token installed with mode 0600")
    return destination


def install_agent(label: str, program: list[str], environment: dict[str, str],
                  logs: Path, agents: Path) -> None:
    agents.mkdir(parents=True, exist_ok=True)
    path = agents / f"{label}.plist"
    payload = {
        "Label": label, "ProgramArguments": program,
        "EnvironmentVariables": environment,
        "RunAtLoad": True, "KeepAlive": True,
        "ProcessType": "Interactive", "ThrottleInterval": 5,
        "StandardOutPath": str(logs / f"{label}.stdout.log"),
        "StandardErrorPath": str(logs / f"{label}.stderr.log"),
    }
    encoded = plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False)
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RepairError("ERR_PROFILE_PERMISSION", f"unsafe LaunchAgent: {label}")
        existing = plistlib.loads(path.read_bytes())
        if existing == payload:
            emit("SKIP", f"LaunchAgent {label}", "definition reused")
        elif existing.get("EnvironmentVariables", {}).get("CRYPSTORE_DEVICE_UDID") != environment["CRYPSTORE_DEVICE_UDID"]:
            raise RepairError("ERR_WRONG_DEVICE", f"LaunchAgent {label} belongs to another device")
        else:
            raise RepairError("ERR_PROFILE_STALE", f"LaunchAgent {label} differs; inspect it before replacing")
    else:
        temporary = agents / f".{label}.{os.getpid()}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        emit("PASS", f"LaunchAgent {label}", "definition installed")
    linted = command(["/usr/bin/plutil", "-lint", str(path)], 10)
    if linted.returncode != 0:
        raise RepairError("ERR_PROFILE_VALIDATION", f"LaunchAgent {label} failed plist validation")
    target = f"gui/{os.getuid()}/{label}"
    active = command(["/bin/launchctl", "print", target], 10)
    if active.returncode == 0 and "state = running" in active.stdout:
        emit("SKIP", f"starting {label}", "already running")
        return
    started = command(["/bin/launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)], 15)
    if started.returncode != 0:
        raise RepairError("ERR_PROFILE_CREATION", f"LaunchAgent {label} did not start")
    emit("PASS", f"starting {label}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--support", type=Path, default=Path.home() / "Library/Application Support/0-Sky")
    parser.add_argument("--kit", type=Path, default=Path(__file__).resolve().parents[1] /
                        "bridge/0SkyBridge/Resources/Scripts/kit")
    args = parser.parse_args()
    try:
        support = args.support.expanduser().resolve()
        key = args.ssh_key.expanduser().resolve()
        kit = args.kit.resolve()
        action = repair(args.udid, args.instance, args.port, key, support, live=True)
        emit("PASS", "profile prerequisite", action)
        directory = support / "instances" / args.instance
        verify_kit_file(kit, "automation/CrypStoreAutomation/crypstore_worker.py")
        verify_kit_file(kit, "automation/CrypStoreAutomation/device_bridge_supervisor")
        verify_kit_file(kit, "host-mac/zero-sky-bluetooth-tunnel")
        stage_directory(kit / "automation", directory / "automation",
                        "CrypStoreAutomation/crypstore_worker.py")
        stage_directory(kit / "host-mac", directory / "host-mac", "apple_device_pairing.py")
        python = ensure_venv(directory, kit / "host-mac/wheelhouse",
                             kit / "host-mac/requirements-lock.txt")
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge" / "HostTools"))
        from pair import ssh_base
        base = ssh_base("127.0.0.1", str(args.port), key,
                        known_hosts=directory / "device-known-hosts",
                        host_alias=alias_for(args.udid))
        no_actionable_jobs(base)
        bluetooth_token = ensure_bluetooth_token(directory, base)
        bluetooth_port = 36000 + (int(hashlib.sha256(args.udid.encode()).hexdigest()[:8], 16) % 20000)
        bluetooth_state = directory / "bluetooth/state.json"
        fingerprint = command(["/usr/bin/ssh-keygen", "-lf", str(key), "-E", "sha256"], 10)
        parts = fingerprint.stdout.split()
        if fingerprint.returncode != 0 or len(parts) < 2 or not parts[1].startswith("SHA256:"):
            raise RepairError("ERR_PROFILE_VALIDATION", "Mac SSH key fingerprint unavailable")
        logs = directory / "logs"
        logs.mkdir(mode=0o700, exist_ok=True)
        os.chmod(logs, 0o700)
        env = {
            "CRYPSTORE_INSTANCE_DIR": str(directory),
            "CRYPSTORE_DEVICE_HOST": "127.0.0.1",
            "CRYPSTORE_DEVICE_PORT": str(args.port),
            "CRYPSTORE_DEVICE_USER": "root",
            "CRYPSTORE_DEVICE_KEY": str(key),
            "CRYPSTORE_DEVICE_UDID": args.udid,
            "CRYPSTORE_DEVICE_KNOWN_HOSTS": str(directory / "device-known-hosts"),
            "CRYPSTORE_DEVICE_HOST_ALIAS": alias_for(args.udid),
            "CRYPSTORE_HOST_KEY_FINGERPRINT": parts[1],
            "SRD_PYTHON": str(python),
        }
        label = f"com.liquidskysecurity.crypstore-worker.{args.instance}"
        install_agent(label, [str(python), str(directory / "automation/CrypStoreAutomation/crypstore_worker.py"),
                              "--interval", "2"], env, logs, Path.home() / "Library/LaunchAgents")
        bridge_env = {**env,
                      "CRYPSTORE_WIRELESS_SSH": "1",
                      "CRYPSTORE_BLUETOOTH_PORT": str(bluetooth_port),
                      "CRYPSTORE_BLUETOOTH_STATE": str(bluetooth_state)}
        bluetooth_helper = directory / "host-mac/zero-sky-bluetooth-tunnel"
        bridge_helper = directory / "automation/CrypStoreAutomation/device_bridge_supervisor"
        for helper in (bluetooth_helper, bridge_helper):
            if not helper.is_file() or helper.is_symlink():
                raise RepairError("ERR_BRIDGE_CONNECTION", f"unsafe bridge helper: {helper.name}")
            helper.chmod(helper.stat().st_mode | 0o100)
        install_agent(f"com.liquidskysecurity.crypstore-bluetooth.{args.instance}",
                      [str(bluetooth_helper), "--token-file", str(bluetooth_token),
                       "--listen-port", str(bluetooth_port), "--state-file", str(bluetooth_state)],
                      bridge_env, logs, Path.home() / "Library/LaunchAgents")
        install_agent(f"com.liquidskysecurity.crypstore-device-bridge.{args.instance}",
                      [str(bridge_helper)], bridge_env, logs, Path.home() / "Library/LaunchAgents")
        print("HOST_WORKER_ACTION=STAGED_AND_STARTED")
        return 0
    except (RepairError, OSError, ValueError, plistlib.InvalidFileException) as error:
        code = error.code if isinstance(error, RepairError) else "ERR_PROFILE_CREATION"
        emit("FAIL", "host worker", code)
        print(f"FIRST_FAILING_TRANSITION=HOST_WORKER_{code}", file=sys.stderr)
        print(f"SANITIZED_ERROR={str(error) if isinstance(error, RepairError) else type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
