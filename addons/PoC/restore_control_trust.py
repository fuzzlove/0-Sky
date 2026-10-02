#!/usr/bin/env python3
"""Trust the exact signed Control Mach-O bytes already installed on one SRD."""
import argparse
import asyncio
import importlib.util
import pathlib
import plistlib
import shutil
import subprocess

from repair_device_connection import profiles, usb_identity

IDENTIFIER = "com.liquidsky.control.native-trust"
NATIVE = (pathlib.Path(__file__).resolve().parents[2] /
          "bridge/KitScripts/automation/CrypStoreAutomation/native-install/install_cryptex_native.py")
GENERATOR = (pathlib.Path(__file__).resolve().parent /
             "srdsh-work/components/zero-sky/kit/automation/CrypStoreAutomation/"
             "native-install/generate_trust_cache.py")
MAGIC = (bytes.fromhex("cffaedfe"), bytes.fromhex("cafebabe"),
         bytes.fromhex("bebafeca"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=pathlib.Path, required=True)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance-name", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()
    app = args.app.resolve(strict=True)
    info = plistlib.loads((app / "Info.plist").read_bytes())
    bundle_id = info.get("CFBundleIdentifier")
    executable = info.get("CFBundleExecutable")
    if bundle_id != "com.liquidsky.CrypStore" or executable != "CrypStore":
        parser.error("Selected bundle is not Control")
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app],
                   check=True, timeout=30)
    detail = subprocess.run(["/usr/bin/codesign", "-dv", app], capture_output=True,
                            text=True, check=True, timeout=30)
    if "Identifier=com.liquidsky.CrypStore" not in detail.stderr:
        parser.error("Control signature identifier does not match its bundle ID")
    asyncio.run(usb_identity(args.udid))
    configured = profiles(instance_name=args.instance_name)
    if args.udid not in configured:
        parser.error("Selected worker profile does not match the exact USB UDID")
    if configured[args.udid][1]["EnvironmentVariables"].get("CRYPSTORE_DEVICE_HOST") != "127.0.0.1":
        parser.error("Selected worker is not routed through the USB SSH tunnel")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = output / "root/usr/share/0-sky/control-native-trust"
    root.mkdir(parents=True)
    count = 0
    for source in app.rglob("*"):
        if not source.is_file() or source.is_symlink():
            continue
        with source.open("rb") as stream:
            if stream.read(4) not in MAGIC:
                continue
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", source],
                       check=True, timeout=30)
        destination = root / source.relative_to(app)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        count += 1
    if not count or not (root / executable).is_file():
        raise RuntimeError("Control Mach-O payload is incomplete")
    shutil.copy2(GENERATOR, output / "generate_trust_cache.py")
    spec = importlib.util.spec_from_file_location("supported_native_cryptex", NATIVE)
    if spec is None or spec.loader is None:
        raise RuntimeError("Maintained native Cryptex installer is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = module.build(output / "root", IDENTIFIER, "1.0", output)
    if args.install:
        asyncio.run(module.install(manifest, IDENTIFIER, args.udid))
    print(f"Control trust Cryptex includes {count} signed Mach-O files")


if __name__ == "__main__":
    main()
