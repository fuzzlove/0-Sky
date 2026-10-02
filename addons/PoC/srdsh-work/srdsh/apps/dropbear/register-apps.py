#!/usr/bin/env python3
"""Keep reviewed research-app registrations healthy on supported SRDs.

The same helper is used on iPhone and iPad across iOS 17-27.  Newer systems
may materialize an app in an MCM bundle container, while older systems may
continue to expose the app directly from its persistent Cryptex mount.  A
valid existing registration always wins so this daemon never replaces an
iOS 27 container registration with a transient mount path.
"""
from __future__ import annotations

import fcntl
import pathlib
import plistlib
import subprocess
import time


REGISTRAR_SCHEMA = 2
MOUNTS = pathlib.Path("/private/var/run/com.apple.security.cryptexd/mnt")
UICACHE = "/var/jb/usr/bin/uicache"
POLL_SECONDS = 30
LOCK_PATH = pathlib.Path("/private/var/run/com.liquidsky.srdssh.app-registration.lock")
ALLOWED = {
    "com.liquidsky.CrypStore": "codes.rambo.research.crypstore.",
    "codes.liquidsky.research.zerosky": "codes.rambo.research.crypstore.",
    "com.tigisoftware.Filza": "codes.rambo.research.filza.permanent.",
}


def candidates() -> dict[str, pathlib.Path]:
    found: dict[str, pathlib.Path] = {}
    for app in MOUNTS.glob("*/Applications/*.app"):
        try:
            info = plistlib.loads((app / "Info.plist").read_bytes())
            bundle = str(info.get("CFBundleIdentifier", ""))
            executable = str(info.get("CFBundleExecutable", ""))
            if bundle not in ALLOWED:
                continue
            if not app.parent.parent.name.startswith(ALLOWED[bundle]):
                continue
            if not executable or not (app / executable).is_file():
                continue
            previous = found.get(bundle)
            if previous is None or app.parent.parent.stat().st_mtime > previous.parent.parent.stat().st_mtime:
                found[bundle] = app
        except (OSError, plistlib.InvalidFileException):
            continue
    return found


def registered() -> dict[str, str]:
    try:
        rows = subprocess.check_output([UICACHE, "-l"], text=True).splitlines()
    except (OSError, subprocess.SubprocessError):
        return {}
    answer: dict[str, str] = {}
    for row in rows:
        if " : " in row:
            bundle, path = row.split(" : ", 1)
            answer[bundle] = path.strip()
    return answer


def valid_registration(bundle: str, raw_path: str) -> bool:
    """Accept either a durable MCM install or the matching Cryptex app."""
    if not raw_path:
        return False
    app = pathlib.Path(raw_path)
    try:
        info = plistlib.loads((app / "Info.plist").read_bytes())
        if str(info.get("CFBundleIdentifier", "")) != bundle:
            return False
        executable = str(info.get("CFBundleExecutable", ""))
        if not executable or not (app / executable).is_file():
            return False
        resolved = str(app)
        if resolved.startswith("/private/var/containers/Bundle/Application/"):
            return True
        prefix = "/private/var/run/com.apple.security.cryptexd/mnt/" + ALLOWED[bundle]
        return resolved.startswith(prefix)
    except (OSError, plistlib.InvalidFileException):
        return False


def repair_once() -> tuple[set[str], list[str]]:
    apps = candidates()
    current = registered()
    healthy: set[str] = set()
    repaired: list[str] = []
    for bundle in sorted(ALLOWED):
        existing = current.get(bundle, "")
        if valid_registration(bundle, existing):
            healthy.add(bundle)
            continue
        app = apps.get(bundle)
        if app is None:
            continue
        completed = subprocess.run(
            [UICACHE, "-p", str(app)], check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if completed.returncode == 0:
            healthy.add(bundle)
            repaired.append(bundle)
    return healthy, repaired


def main() -> int:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock = LOCK_PATH.open("a+")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return 0
    # Cryptexes mount independently, and LaunchServices can later discard a
    # mount-backed record. Stay resident and repair only the bounded allowlist.
    last_state: tuple[str, ...] | None = None
    while True:
        healthy, repaired = repair_once()
        state = tuple(sorted(healthy))
        if repaired:
            print("srdsh: restored app registration: " + ", ".join(repaired), flush=True)
        elif state != last_state:
            missing = sorted(set(ALLOWED) - healthy)
            if missing:
                print("srdsh: waiting for research apps: " + ", ".join(missing), flush=True)
            else:
                print("srdsh: universal app registrations are healthy", flush=True)
        last_state = state
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
