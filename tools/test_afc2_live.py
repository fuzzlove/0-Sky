#!/usr/bin/env python3
"""Run a self-cleaning AFC2 root-mount smoke test against an attached SRD."""

from __future__ import annotations

import argparse
import errno
import os
from pathlib import Path
import queue
import signal
import shutil
import subprocess
import sys
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "bridge/0SkyBridge/Resources/Scripts/afc2_root_mount.py"
MAC_APP = ROOT / ".build/afc2-test-macos/0SkyBridge-AFC2-Test.app"
CONTROL_DEB = (
    ROOT
    / "control/TrollStoreLite/packages/"
    "com.opa334.trollstorelite_3.5.25_iphoneos-arm64.deb"
)
AFC2_DEB = (
    ROOT
    / "addons/PoC/appsync-afc2d-srd-port/dist/"
    "com.cannathea.afc2d-arm64_1.2.0+0sky27.5_iphoneos-arm64.deb"
)
ROOT_MARKERS = ("Applications", "System", "private", "usr", "var")


def run_checked(argv: list[str]) -> str:
    result = subprocess.run(
        argv,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"{Path(argv[0]).name} failed: {result.stdout.strip()}")
    return result.stdout.strip()


def verify_build_artifacts() -> None:
    executable = MAC_APP / "Contents/MacOS/0SkyBridge"
    controller = MAC_APP / "Contents/Resources/Scripts/afc2_root_mount.py"
    for artifact in (executable, controller, CONTROL_DEB, AFC2_DEB):
        if not artifact.is_file():
            raise RuntimeError(f"compiled artifact is missing: {artifact}")
    run_checked(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(MAC_APP)])
    architectures = run_checked(["/usr/bin/lipo", "-archs", str(executable)]).split()
    if "arm64" not in architectures:
        raise RuntimeError("the macOS test app does not contain arm64")
    dpkg_deb = shutil.which("dpkg-deb")
    if not dpkg_deb:
        raise RuntimeError("dpkg-deb is unavailable")
    for package, expected in (
        (CONTROL_DEB, "com.opa334.trollstorelite"),
        (AFC2_DEB, "com.cannathea.afc2d-arm64"),
    ):
        identity = run_checked([dpkg_deb, "-f", str(package), "Package"])
        architecture = run_checked([dpkg_deb, "-f", str(package), "Architecture"])
        if identity != expected or architecture != "iphoneos-arm64":
            raise RuntimeError(f"unexpected iOS package identity: {package.name}")


def reader(stream, output: queue.Queue[str]) -> None:
    for line in iter(stream.readline, ""):
        output.put(line.rstrip("\n"))
    output.put("")


def verify_read_only(mount_path: Path) -> None:
    missing = [name for name in ROOT_MARKERS if not (mount_path / name).exists()]
    if missing:
        raise RuntimeError("mounted volume is missing root markers: " + ", ".join(missing))
    # `/var` is a device-side symlink and WebDAV exposes it as a non-directory
    # entry. Use its canonical location for the harmless write-denial probe.
    probe = mount_path / "private/var/tmp" / f".0sky-afc2-readonly-probe-{os.getpid()}"
    try:
        probe.write_text("read-only verification\n", encoding="utf-8")
    except OSError as error:
        # macOS' WebDAV filesystem can translate the server's forbidden write
        # response to EIO instead of EROFS. Either result proves no file was
        # created through the read-only endpoint.
        if error.errno not in {errno.EACCES, errno.EIO, errno.EROFS, errno.EPERM}:
            raise
    else:
        try:
            probe.unlink()
        finally:
            raise RuntimeError("read-only mount unexpectedly accepted a write")


def live_test(udid: str, timeout: float) -> Path:
    process = subprocess.Popen(
        [
            sys.executable,
            str(HELPER),
            "--udid",
            udid,
            "--label",
            "Automated-SRD-Test",
            "--no-reveal",
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    lines: queue.Queue[str] = queue.Queue()
    threading.Thread(target=reader, args=(process.stdout, lines), daemon=True).start()
    observed: list[str] = []
    mount_path: Path | None = None
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            try:
                line = lines.get(timeout=min(0.5, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                if process.poll() is not None:
                    break
                continue
            if not line:
                if process.poll() is not None:
                    break
                continue
            observed.append(line)
            print(line, flush=True)
            if line.startswith("ROOT_MOUNT_ERROR="):
                raise RuntimeError(line.removeprefix("ROOT_MOUNT_ERROR="))
            if line.startswith("ROOT_MOUNT_READY="):
                mount_path = Path(line.removeprefix("ROOT_MOUNT_READY="))
            if mount_path is not None and line == "ROOT_MOUNT_MODE=read-only":
                verify_read_only(mount_path)
                return mount_path
        detail = " | ".join(observed[-8:]) or "no helper output"
        raise RuntimeError(f"AFC2 mount did not become ready within {timeout:.0f}s: {detail}")
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
        while True:
            try:
                line = lines.get_nowait()
            except queue.Empty:
                break
            if line.startswith("ROOT_MOUNT_"):
                print(line, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument(
        "--skip-artifacts", action="store_true", help="test only the live AFC2 service"
    )
    args = parser.parse_args()
    try:
        if not args.skip_artifacts:
            verify_build_artifacts()
            print("AFC2_ARTIFACTS=PASS", flush=True)
        mount_path = live_test(args.udid, args.timeout)
        if mount_path.exists():
            raise RuntimeError(f"mount was not removed after the test: {mount_path}")
        print("AFC2_LIVE_TEST=PASS", flush=True)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"AFC2_LIVE_TEST=FAIL {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
