#!/usr/bin/env python3
"""Restore the exact-build appregistrard Cryptex to one paired USB SRD."""

import argparse
import asyncio
import hashlib
import importlib.util
import json
import pathlib
import plistlib
import shutil
import uuid

from repair_device_connection import profiles, usb_identity, worker_namespace
from restore_srd_bootstrap import DEFAULT_SRDSH_KIT


IDENTIFIER = "codes.rambo.research.appregistrard"
DEFAULT_KIT = DEFAULT_SRDSH_KIT.parent / "appregistrard"
ASSETS = ("BuildManifest.plist", "appregistrard-apfs-sealed-udzo.dmg",
          "appregistrard-apfs-sealed.hash", "appregistrard.gtcd")
NATIVE = (pathlib.Path(__file__).resolve().parents[2] /
          "bridge/KitScripts/automation/CrypStoreAutomation/native-install/install_cryptex_native.py")


def der(tag: int, data: bytes) -> bytes:
    length = len(data)
    header = (bytes([length]) if length < 128 else
              bytes([0x80 + (length.bit_length() + 7) // 8]) +
              length.to_bytes((length.bit_length() + 7) // 8, "big"))
    return bytes([tag]) + header + data


def verified_assets(kit: pathlib.Path, build: str, ios: str) -> tuple[pathlib.Path, dict]:
    if not build or not build.isalnum():
        raise ValueError("Device returned an invalid OS build")
    root = kit.expanduser().resolve() / build
    provenance = json.loads((root / "PROVENANCE.json").read_text())
    if (provenance.get("identifier") != IDENTIFIER
            or provenance.get("product_build") != build
            or provenance.get("ios") != ios):
        raise ValueError("Registrar provenance does not match the device's exact OS build")
    for name in ASSETS:
        path = root / name
        expected = provenance["files"].get(name)
        if not path.is_file() or path.is_symlink() or not path.stat().st_size:
            raise ValueError(f"Missing registrar asset: {path}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"Registrar asset digest mismatch: {name}")
    return root, provenance


def registrar_ready(ssh) -> bool:
    command = (
        "for p in /private/var/run/com.apple.security.cryptexd/mnt/"
        "codes.rambo.research.appregistrard.*/usr/bin/appregistrard; do "
        "m=${p%/usr/bin/appregistrard}; "
        'if [ -x "$p" ] && mount | grep -Fq " on $m ("; then exit 0; fi; '
        "done; exit 1"
    )
    return ssh(command, timeout=30, check=False).returncode == 0


def stage(root: pathlib.Path, provenance: dict, output: pathlib.Path) -> pathlib.Path:
    output.mkdir(parents=True, exist_ok=False)
    assets = output / "Cryptex/research"
    assets.mkdir(parents=True)
    sources = {
        "Cryptex1,GenericDmg": ("appregistrard-apfs-sealed-udzo.dmg", "gdmg"),
        "Cryptex1,GenericTrustCache": ("appregistrard.gtcd", "gtcd"),
        "Cryptex1,GenericVolume": ("appregistrard-apfs-sealed.hash", "gtgv"),
    }
    manifest = plistlib.loads((root / "BuildManifest.plist").read_bytes())
    identities = [i for i in manifest["BuildIdentities"]
                  if i.get("Info", {}).get("Variant") == "research"]
    if len(identities) != 1:
        raise ValueError("Expected one exact-build research identity")
    entries = identities[0]["Manifest"]
    for key, (source, name) in sources.items():
        destination = assets / name
        if key == "Cryptex1,GenericVolume":
            raw = (root / source).read_bytes()
            wrapped = der(0x30, der(0x16, b"IM4P") + der(0x16, b"gtgv") +
                          der(0x16, b"0") + der(0x04, raw))
            destination.write_bytes(wrapped)
        else:
            shutil.copyfile(root / source, destination)
        entries[key]["Info"]["Path"] = f"Cryptex/research/{name}"
        entries[key]["Digest"] = hashlib.sha384(destination.read_bytes()).digest()
    info = assets / "ginf"
    info.write_bytes(plistlib.dumps({
        "CFBundleIdentifier": IDENTIFIER,
        "CFBundleVersion": provenance["version"],
        "DeveloperModeRequired": True,
    }))
    entries["Cryptex1,CryptexInfoPlist"]["Info"]["Path"] = "Cryptex/research/ginf"
    entries["Cryptex1,CryptexInfoPlist"]["Digest"] = hashlib.sha384(info.read_bytes()).digest()
    staged_manifest = output / "BuildManifest.plist"
    staged_manifest.write_bytes(plistlib.dumps(manifest))
    return staged_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance-name", required=True)
    parser.add_argument("--kit", type=pathlib.Path, default=DEFAULT_KIT)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    device = asyncio.run(usb_identity(args.udid))
    configured = profiles(instance_name=args.instance_name)
    if args.udid not in configured:
        parser.error("Selected instance does not belong to the exact USB UDID")
    env = configured[args.udid][1]["EnvironmentVariables"]
    if env.get("CRYPSTORE_DEVICE_HOST") != "127.0.0.1":
        parser.error("Selected instance is not routed through the paired USB tunnel")
    ssh = worker_namespace(configured[args.udid][1])["ssh"]
    if registrar_ready(ssh):
        print("Exact-device appregistrard is already mounted and executable", flush=True)
        return
    root, provenance = verified_assets(args.kit, device["build"], device["version"])
    output = (args.output or pathlib.Path(__file__).resolve().parent /
              "connection-repair" / ("appregistrard-" + uuid.uuid4().hex)).resolve()
    manifest = stage(root, provenance, output)
    spec = importlib.util.spec_from_file_location("supported_native_cryptex", NATIVE)
    if spec is None or spec.loader is None:
        raise RuntimeError("Maintained native Cryptex installer is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.assets_from_manifest(manifest)
    print(f"Installing verified appregistrard {provenance['version']} for {device['build']}", flush=True)
    asyncio.run(module.install(manifest, IDENTIFIER, args.udid))
    if not registrar_ready(ssh):
        raise RuntimeError("appregistrard installation completed without an executable mount")
    print("Exact-device appregistrard is mounted and executable", flush=True)


if __name__ == "__main__":
    main()
