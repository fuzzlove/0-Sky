#!/var/jb/usr/bin/python3
"""One-shot, fail-open post-SpringBoard launch of the 0-Sky Link splash.

This runs only from the authorized rootless 0-Sky launchd environment.  It
never participates in Apple's boot chain or changes service configuration.
"""
from __future__ import annotations

import json
import ctypes
import fcntl
import os
import subprocess
import struct
import time
from pathlib import Path
from typing import Callable

from zero_sky_core.logging import StructuredLogger
from zero_sky_core.paths import RootlessPaths

BUNDLE_ID = "codes.liquidsky.research.zerosky"
MAX_WAIT_SECONDS = 30.0
MAX_OPEN_ATTEMPTS = 3


def boot_identifier() -> int:
    """Return the kernel's boot time, stable across bridge restarts."""
    buffer = ctypes.create_string_buffer(16)
    size = ctypes.c_size_t(len(buffer))
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    if library.sysctlbyname(b"kern.boottime", buffer, ctypes.byref(size), None, 0):
        raise OSError("kern.boottime unavailable")
    if size.value < 8:
        raise OSError("kern.boottime truncated")
    return struct.unpack_from("=q", buffer.raw)[0]


def claim_once(paths: RootlessPaths, identifier: int) -> bool:
    """Claim one foreground launch per actual boot across bridge restarts."""
    directory = paths.state_directory
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = directory / "bootsplash-launch.lock"
    descriptor = os.open(marker, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        if os.read(descriptor, 40).decode("ascii", "replace").strip() == str(identifier):
            return False
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, (str(identifier) + "\n").encode("ascii"))
        os.fsync(descriptor)
        return True
    finally:
        os.close(descriptor)


def enabled(paths: RootlessPaths) -> bool:
    config = paths.jailbreak("/etc/0sky-bootsplash.json")
    try:
        value = json.loads(config.read_text(encoding="utf-8"))
        section = value.get("bootsplash", value)
        return section.get("enabled", True) is not False
    except (OSError, ValueError, AttributeError):
        return True


def springboard_running(paths: RootlessPaths) -> bool:
    ps = paths.jailbreak("/usr/bin/ps")
    if not ps.is_file():
        ps = paths.system("/bin/ps")
    if not ps.is_file():
        return False
    result = subprocess.run([str(ps), "ax", "-o", "command="],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=1.0, check=False)
    if result.returncode:
        return False
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        command = line.strip().split(None, 1)
        if command and Path(command[0]).name == "SpringBoard":
            return True
    return False


def launch(paths: RootlessPaths | None = None,
           springboard: Callable[[], bool] | None = None,
           opener: Callable[[], bool] | None = None,
           now: Callable[[], float] = time.monotonic,
           sleep: Callable[[float], None] = time.sleep,
           log: Callable[..., None] | None = None) -> dict:
    paths = paths or RootlessPaths()
    started = now()
    def emit(event: str, **fields: object) -> None:
        if log:
            try:
                log(event, **fields)
            except Exception:
                pass
    if not enabled(paths):
        emit("disabled")
        return {"status": "DISABLED", "attempts": 0, "duration_ms": 0}
    uiopen = paths.jailbreak("/usr/bin/uiopen")
    if not uiopen.is_file() or not os.access(uiopen, os.X_OK):
        emit("uiopen_missing")
        return {"status": "UNAVAILABLE", "attempts": 0,
                "duration_ms": int((now() - started) * 1000)}
    springboard = springboard or (lambda: springboard_running(paths))
    def default_open() -> bool:
        result = subprocess.run([str(uiopen), "--bundleid", BUNDLE_ID],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=8.0, check=False)
        return result.returncode == 0
    opener = opener or default_open
    deadline = started + MAX_WAIT_SECONDS
    attempts = 0
    while now() < deadline:
        try:
            ready = springboard()
        except Exception:
            ready = False
        if not ready:
            sleep(min(0.5, max(0.0, deadline - now())))
            continue
        attempts += 1
        try:
            opened = opener()
        except Exception:
            opened = False
        if opened:
            duration = int((now() - started) * 1000)
            emit("opened", attempts=attempts, durationMs=duration)
            return {"status": "OPENED", "attempts": attempts,
                    "duration_ms": duration}
        if attempts >= MAX_OPEN_ATTEMPTS:
            break
        sleep(min(0.8, max(0.0, deadline - now())))
    duration = int((now() - started) * 1000)
    status = "UNAVAILABLE" if attempts else "SPRINGBOARD_TIMEOUT"
    emit(status.lower(), attempts=attempts, durationMs=duration)
    return {"status": status, "attempts": attempts,
            "duration_ms": duration}


def main() -> int:
    paths = RootlessPaths()
    logger = StructuredLogger(paths.log_directory / "bootsplash.jsonl")
    def record(event: str, **fields: object) -> None:
        logger.log("INFO" if event in ("opened", "disabled") else "WARN",
                   "CORE", "bootsplash launcher " + event, **fields)
    try:
        if not enabled(paths):
            record("disabled")
            return 0
        if not claim_once(paths, boot_identifier()):
            record("already_launched")
            return 0
        launch(paths, log=record)
    except Exception as error:
        # Unexpected errors must never make a startup job restart or affect UI.
        try:
            record("exception", errorClass=type(error).__name__)
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
