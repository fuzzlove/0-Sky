#!/usr/bin/env python3
"""Build, install, and validate AFC2 as an iOS 27 SRD ServiceAgent cryptex."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import inspect
import pathlib
import plistlib
import shutil
import subprocess
import sys
import time


PROJECT = pathlib.Path(__file__).resolve().parents[1]
POC_ROOT = PROJECT.parent
HELPER = PROJECT / "build/afc2d/layout/usr/libexec/afc2d"
SERVICE_AGENT = PROJECT / "patches/afc2d/com.apple.afc2.service-agent.plist"
CRYPTEX_RUN = POC_ROOT / "srdsh-work/components/zero-sky/kit/srdssh/payload-root/usr/bin/cryptex-run"
NATIVE_INSTALLER = POC_ROOT / "native_srd_installer.py"
DEFAULT_IDENTIFIER = "codes.openai.research.afc2.serviceagent"
EXPECTED_HELPER_SHA256 = "c900211619e202e1469f049ad7e721897396f3b0e6b27cfa9c9378ffe0b2284e"
EXPECTED_SERVICE = {
    "AllowUnactivatedService": True,
    "Label": "com.apple.afc2",
    "ProgramArguments": ["/usr/libexec/afc2d"],
    "USBOnlyService": True,
    "UserName": "root",
}


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_inputs() -> None:
    if not HELPER.is_file() or sha256(HELPER) != EXPECTED_HELPER_SHA256:
        raise ValueError("exact-build AFC2 helper is missing or has an unexpected hash")
    subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(HELPER)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    service = plistlib.loads(SERVICE_AGENT.read_bytes())
    if service != EXPECTED_SERVICE:
        raise ValueError("ServiceAgent plist differs from the reviewed definition")
    if not CRYPTEX_RUN.is_file():
        raise ValueError("SRD cryptex-run launcher is missing")


def prepare_root(output: pathlib.Path) -> pathlib.Path:
    root = output / "root"
    if root.exists():
        shutil.rmtree(root)
    helper_target = root / "usr/libexec/afc2d"
    launcher_target = root / "usr/bin/cryptex-run"
    daemon_helper_target = root / "usr/bin/afc2d"
    agent_target = root / "Library/Lockdown/ServiceAgents/com.apple.afc2.plist"
    daemon_target = root / "Library/LaunchDaemons/lockdown.afc2.plist"
    helper_target.parent.mkdir(parents=True)
    launcher_target.parent.mkdir(parents=True, exist_ok=True)
    agent_target.parent.mkdir(parents=True)
    daemon_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(HELPER, helper_target)
    shutil.copy2(HELPER, daemon_helper_target)
    shutil.copy2(CRYPTEX_RUN, launcher_target)
    shutil.copy2(SERVICE_AGENT, agent_target)
    daemon = {
        "EnvironmentVariables": {},
        "Label": "lockdown.afc2",
        "MachServices": {"lockdown.afc2": True},
        "ProgramArguments": ["/usr/bin/cryptex-run", "afc2d"],
        "UserName": "root",
    }
    daemon_target.write_bytes(plistlib.dumps(daemon))
    helper_target.chmod(0o755)
    daemon_helper_target.chmod(0o755)
    launcher_target.chmod(0o755)
    return root


def load_native_installer():
    if not NATIVE_INSTALLER.is_file():
        raise ValueError(f"missing native SRD installer: {NATIVE_INSTALLER}")
    spec = importlib.util.spec_from_file_location("afc2_native_srd_installer", NATIVE_INSTALLER)
    if spec is None or spec.loader is None:
        raise ValueError("could not load the native SRD installer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def maybe_await(value):
    return await value if inspect.isawaitable(value) else value


async def validate_device(udid: str, attempts: int = 20) -> dict[str, object]:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.afc import AfcService

    last_error = "service did not become available"
    for _ in range(attempts):
        client = await create_using_usbmux(serial=udid, autopair=False)
        try:
            try:
                afc = AfcService(lockdown=client, service_name="com.apple.afc2")
                async with afc:
                    root = await asyncio.wait_for(maybe_await(afc.listdir("/")), timeout=10)
                    evidence = {}
                    for path in ("/Applications", "/System", "/private", "/var"):
                        try:
                            evidence[path] = await asyncio.wait_for(
                                maybe_await(afc.listdir(path)), timeout=10
                            )
                        except Exception as error:  # retain diagnostic evidence
                            evidence[path] = f"{type(error).__name__}: {error}"
                return {"root": root, "paths": evidence}
            except Exception as error:
                last_error = f"{type(error).__name__}: {error}"
        finally:
            await maybe_await(client.close())
        await asyncio.sleep(1)
    raise RuntimeError(f"AFC2 validation failed: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", help="explicitly selected authorized SRD")
    parser.add_argument("--identifier", default=DEFAULT_IDENTIFIER)
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--output", type=pathlib.Path, default=PROJECT / "cryptex")
    args = parser.parse_args()

    validate_inputs()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    root = prepare_root(output)
    native = load_native_installer()
    manifest = native.build(root, args.identifier, args.version, output)
    print(f"AFC2_CRYPTEX_MANIFEST={manifest}")
    if args.build_only:
        return 0

    if not args.udid:
        parser.error("--udid is required unless --build-only is used")

    asyncio.run(native.install(manifest, args.identifier, args.udid))
    result = asyncio.run(validate_device(args.udid))
    print("AFC2_SERVICE_AGENT=PASS")
    print("AFC2_START_SERVICE=" + repr(result["attributes"]))
    print("AFC2_ROOT=" + repr(result["root"]))
    print("AFC2_PATHS=" + repr(result["paths"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
