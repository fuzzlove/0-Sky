#!/usr/bin/env python3
"""Build an Apple research cryptex for the existing offline Control Python."""

import argparse
import asyncio
import hashlib
import importlib.util
import pathlib
import shlex
import shutil
import subprocess
import sys

from repair_device_connection import HOST_TOOLS, profiles, usb_identity


PACKAGES = {
    "libgdbm6_1.23_iphoneos-arm64.deb": "020e4595f059d57c63a6b971a78c2d3546e564f4973e05d55e796509436cf94f",
    "libpython3.9_3.9.9-1_iphoneos-arm64.deb": "06777dac1c01154ab09cba6ea4ed8d5a63e82af37cfb7a5ececa2f1ba274b00b",
    "python3.9_3.9.9-1_iphoneos-arm64.deb": "87ed83ce0bd3c296fe479d323749b31a4c8971c28d03ed6c06e2af1756fe3a91",
    "python3_3.9.9-1_iphoneos-arm64.deb": "f1e5100f072f6ad02fd7dce6c1c18a824d0c4bafc43197a546c43a974efe9238",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit", required=True, type=pathlib.Path)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance-name", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error("output directory already exists")
    tool = shutil.which("dpkg-deb")
    if not tool:
        parser.error("dpkg-deb is required")
    packages = []
    for name, expected in PACKAGES.items():
        package = args.kit / "offline-python" / name
        if package.is_symlink() or hashlib.sha256(package.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"offline package digest mismatch: {name}")
        packages.append(package)
    output.mkdir(parents=True)
    root = output / "root"
    root.mkdir()
    for index, package in enumerate(packages):
        stage = output / f"package-{index}"
        subprocess.run([tool, "-x", str(package), str(stage)], check=True)
        shutil.copytree(stage / "var/jb", root, dirs_exist_ok=True, symlinks=True)
    asyncio.run(usb_identity(args.udid))
    _, worker = profiles(instance_name=args.instance_name)[args.udid]
    env = worker["EnvironmentVariables"]
    if env.get("CRYPSTORE_DEVICE_HOST") != "127.0.0.1":
        raise RuntimeError("Python recovery requires the exact-device USB tunnel")
    sys.path.insert(0, str(HOST_TOOLS))
    import pair
    base = pair.ssh_base("127.0.0.1", env["CRYPSTORE_DEVICE_PORT"],
                         pathlib.Path(env["CRYPSTORE_DEVICE_KEY"]),
                         known_hosts=pathlib.Path(env["CRYPSTORE_DEVICE_KNOWN_HOSTS"]),
                         host_alias=env["CRYPSTORE_DEVICE_HOST_ALIAS"])
    verified = 0
    for local in sorted(root.rglob("*")):
        if local.is_symlink() or not local.is_file():
            continue
        with local.open("rb") as stream:
            magic = stream.read(4)
        if magic not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            continue
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(local)], check=True)
        remote = "/var/jb/" + str(local.relative_to(root))
        result = pair.ssh(base, "cat " + shlex.quote(remote), timeout=60)
        if hashlib.sha256(result.stdout).digest() != hashlib.sha256(local.read_bytes()).digest():
            raise RuntimeError(f"installed Python payload differs: {remote}")
        verified += 1
    if not verified:
        raise RuntimeError("offline packages contained no verified Mach-O payloads")
    print(f"Verified {verified} installed Python code files against pinned offline packages", flush=True)
    native = (pathlib.Path(__file__).resolve().parents[2] /
              "bridge/KitScripts/automation/CrypStoreAutomation/native-install/install_cryptex_native.py")
    spec = importlib.util.spec_from_file_location("supported_native_cryptex", native)
    if spec is None or spec.loader is None:
        raise RuntimeError("Maintained native Cryptex installer is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = module.build(root, "com.liquidsky.control.python", "1.0", output)
    if args.install:
        asyncio.run(module.install(manifest, "com.liquidsky.control.python", args.udid))


if __name__ == "__main__":
    main()
