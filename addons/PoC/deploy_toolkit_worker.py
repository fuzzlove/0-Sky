#!/usr/bin/env python3
"""Update exact paired Mac workers and verify fresh device host-tool heartbeats."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from repair_device_connection import profiles, worker_namespace


SOURCE = Path(__file__).resolve().parents[2] / (
    "bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py")


def atomic_bytes(target: Path, contents: bytes, mode: int) -> None:
    if target.is_symlink():
        raise RuntimeError("worker target is a symbolic link")
    temporary = target.with_name("." + target.name + ".toolkit-" + str(os.getpid()))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def verify_heartbeat(profile: dict, after: float, timeout: float = 40) -> dict:
    worker = worker_namespace(profile)
    code = ("import json; from pathlib import Path; "
            "d=json.loads(Path('/var/jb/var/run/crypstore-worker.json').read_text()); "
            "print(json.dumps({'timestamp':d.get('timestamp'), "
            "'pairing':d.get('apple_pairing_verified'), "
            "'identity':d.get('host_identity_verified'), "
            "'tools':d.get('host_tools',{})}))")
    remote = "/var/jb/usr/bin/python3 -c " + shlex.quote(code)
    deadline = time.monotonic() + timeout
    last_error = "heartbeat unavailable"
    while time.monotonic() < deadline:
        result = worker["ssh"](remote, timeout=15, check=False)
        if result.returncode == 0:
            try:
                value = json.loads(result.stdout)
                if (isinstance(value, dict) and value.get("timestamp", 0) >= after and
                        value.get("pairing") is True and value.get("identity") is True and
                        isinstance(value.get("tools"), dict) and value["tools"]):
                    return {"detected": sorted(key for key, row in value["tools"].items()
                                               if row.get("detected") is True),
                            "reported": sorted(value["tools"])}
                last_error = "heartbeat has no fresh verified host inventory"
            except (ValueError, TypeError) as error:
                last_error = type(error).__name__
        else:
            last_error = "paired SSH heartbeat read failed (exit " + str(result.returncode) + ")"
        time.sleep(2)
    raise RuntimeError(last_error)


def update(instance: str) -> dict:
    selected = profiles(instance_name=instance)
    if len(selected) != 1:
        raise RuntimeError("expected one exact paired worker profile")
    _, (agent, profile) = next(iter(selected.items()))
    worker_path = next(Path(value) for value in profile["ProgramArguments"]
                       if value.endswith("/crypstore_worker.py"))
    if not worker_path.is_file() or worker_path.is_symlink():
        raise RuntimeError("active worker source is absent or unsafe")
    old = worker_path.read_bytes()
    new = SOURCE.read_bytes()
    if old == new:
        return {"instance": instance, "changed": False,
                "heartbeat": verify_heartbeat(profile, time.time() - 15)}
    backup = worker_path.with_name(worker_path.name + ".before-toolkit-" +
                                   time.strftime("%Y%m%d-%H%M%S"))
    if backup.exists():
        raise RuntimeError("worker backup name already exists")
    backup.write_bytes(old)
    backup.chmod(0o600)
    mode = worker_path.stat().st_mode & 0o777
    target = f"gui/{os.getuid()}/{profile['Label']}"
    changed_at = time.time()
    try:
        atomic_bytes(worker_path, new, mode)
        subprocess.run(["/bin/launchctl", "kickstart", "-k", target],
                       capture_output=True, timeout=20, check=True)
        heartbeat = verify_heartbeat(profile, changed_at)
    except Exception:
        atomic_bytes(worker_path, old, mode)
        subprocess.run(["/bin/launchctl", "kickstart", "-k", target],
                       capture_output=True, timeout=20, check=False)
        raise
    return {"instance": instance, "changed": True, "backup": str(backup),
            "heartbeat": heartbeat}


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: deploy_toolkit_worker.py INSTANCE [INSTANCE...]")
    if not SOURCE.is_file() or SOURCE.is_symlink():
        raise RuntimeError("reviewed worker source is unavailable")
    for instance in sys.argv[1:]:
        print(json.dumps(update(instance), sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
