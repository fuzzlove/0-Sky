#!/usr/bin/env python3
"""Converge enrolled Mac workers on the canonical 0-Sky pairing backend."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from repair_device_connection import profiles

ROOT = Path(__file__).resolve().parents[2]
NAMES = ("pair.py", "apple_device_transport.py")
HOST = ROOT / "bridge/HostTools"
BUNDLED = ROOT / "bridge/0SkyBridge/Resources/Scripts/kit/host-mac"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def launch_target(label: str) -> str:
    if not re.fullmatch(r"com\.liquidskysecurity\.crypstore-worker\.[a-z0-9-]+", label):
        raise RuntimeError("Unexpected worker launch label")
    return f"gui/{os.getuid()}/{label}"


def restart(target: str) -> None:
    completed = subprocess.run(["/bin/launchctl", "kickstart", "-k", target],
                               capture_output=True, text=True, timeout=20)
    if completed.returncode:
        raise RuntimeError("Worker restart failed: " + completed.stderr[-350:])
    for _ in range(20):
        state = subprocess.run(["/bin/launchctl", "print", target],
                               capture_output=True, text=True, timeout=10)
        if state.returncode == 0 and re.search(r"\bpid = [0-9]+", state.stdout):
            return
        time.sleep(.5)
    raise RuntimeError("Worker did not remain running after restart")


def replace(path: Path, data: bytes, mode: int) -> None:
    temporary = path.with_name(f".{path.name}.0sky-{os.getpid()}-{time.time_ns()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(apply: bool) -> list[dict]:
    source = {name: (HOST / name).read_bytes() for name in NAMES}
    for name in NAMES:
        if source[name] != (BUNDLED / name).read_bytes():
            raise RuntimeError(f"Canonical and bundled {name} are not synchronized")
    if b"remote_port: str = \"22\"" not in source["pair.py"]:
        raise RuntimeError("Pairing backend does not accept the worker's remote_port argument")
    rows = []
    for udid, (plist_path, plist) in sorted(profiles().items()):
        env = plist.get("EnvironmentVariables", {})
        instance = Path(env.get("CRYPSTORE_INSTANCE_DIR", ""))
        if env.get("CRYPSTORE_DEVICE_UDID") != udid or not instance.is_dir() or instance.is_symlink():
            raise RuntimeError("Worker profile does not match its exact device instance")
        paths = {name: instance / "host-mac" / name for name in NAMES}
        for name, path in paths.items():
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f"Pairing backend path is missing or symbolic: {name}")
        if plist_path.name != plist["Label"] + ".plist":
            raise RuntimeError("Worker launch label does not match its definition")
        target = launch_target(plist["Label"])
        previous = {name: path.read_bytes() for name, path in paths.items()}
        changed = [name for name in NAMES if previous[name] != source[name]]
        row = {"device": udid, "changed_files": changed,
               "target_sha256": {name: digest(source[name]) for name in NAMES}}
        rows.append(row)
        if not apply or not changed:
            continue
        modes = {name: stat.S_IMODE(paths[name].stat().st_mode) for name in changed}
        try:
            for name in changed:
                replace(paths[name], source[name], modes[name])
            restart(target)
        except Exception:
            for name in changed:
                if paths[name].read_bytes() != previous[name]:
                    replace(paths[name], previous[name], modes[name])
            try:
                restart(target)
            except Exception:
                pass
            raise
        if any(paths[name].read_bytes() != source[name] for name in NAMES):
            raise RuntimeError("Worker pairing backend changed after restart")
        row["restart_verified"] = True
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(main(args.apply), indent=2))
