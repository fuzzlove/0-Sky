#!/usr/bin/env python3
"""Identify a byte-matched local rollback image for one mounted SRD runtime."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shlex
import subprocess
import sys
import tempfile

from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.services.cryptexd import CryptexdService

from repair_device_connection import profiles, usb_identity, worker_namespace


HERE = Path(__file__).resolve().parent
GENERATIONS = (HERE / "srdsh-work/components/zero-sky/kit/automation/artifacts/"
               "srd-runtime-poc/runtime-generations")
IDENTIFIER = "codes.openai.research.ellekitloader"
REQUIRED = ("dynamic-tweak-manifest.json", "srdsh-apfs-sealed-udzo.dmg",
            "srdsh.gtcd", "srdsh-apfs-sealed.hash", "BuildManifest.plist",
            "install_cryptex_native.py")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha384_digest(path: Path) -> bytes:
    digest = hashlib.sha384()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    return digest.digest()


def _der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    width = first & 0x7f
    if width == 0 or width > 4 or offset + 1 + width > len(data):
        raise ValueError("invalid DER length")
    value = int.from_bytes(data[offset + 1:offset + 1 + width], "big")
    if value < 0x80:
        raise ValueError("non-canonical DER length")
    return value, offset + 1 + width


def _der_item(data: bytes, offset: int, tag: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != tag:
        raise ValueError("unexpected DER tag")
    length, start = _der_length(data, offset + 1)
    end = start + length
    if end > len(data):
        raise ValueError("truncated DER item")
    return data[start:end], end


def raw_volume_hash(encoded: bytes) -> bytes:
    """Extract the build helper's exact raw hash from a validated gtgv DER."""
    body, end = _der_item(encoded, 0, 0x30)
    if end != len(encoded):
        raise ValueError("trailing DER volume-hash bytes")
    offset = 0
    for expected in (b"IM4P", b"gtgv", b"0"):
        value, offset = _der_item(body, offset, 0x16)
        if value != expected:
            raise ValueError("unexpected DER volume-hash identifier")
    value, offset = _der_item(body, offset, 0x04)
    if offset != len(body) or len(value) < 32 or len(value) > 4096:
        raise ValueError("invalid raw volume hash")
    return value


def _restore_payload(candidate: Path) -> tuple[Path, dict] | None:
    bundles = list(candidate.glob(
        "sdk-cryptex-*/bundles/codes.openai.research.ellekitloader.cxbd/Restore"))
    if not bundles:
        return None
    if len(bundles) != 1 or bundles[0].is_symlink():
        raise RuntimeError("SDK_RESTORE_BUNDLE_AMBIGUOUS")
    restore = bundles[0]
    manifest_path = restore / "BuildManifest.plist"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError("SDK_RESTORE_MANIFEST_MISSING")
    manifest = plistlib.loads(manifest_path.read_bytes())
    try:
        entries = manifest["BuildIdentities"][0]["Manifest"]
    except (KeyError, IndexError, TypeError) as error:
        raise RuntimeError("SDK_RESTORE_MANIFEST_INVALID") from error
    mapping = {
        "Cryptex1,GenericDmg": "gdmg",
        "Cryptex1,GenericTrustCache": "gtcd",
        "Cryptex1,GenericVolume": "gtgv",
        "Cryptex1,CryptexInfoPlist": "ginf",
    }
    files = {}
    for key, name in mapping.items():
        entry = entries.get(key)
        relative = entry.get("Info", {}).get("Path") if isinstance(entry, dict) else None
        digest = entry.get("Digest") if isinstance(entry, dict) else None
        path = restore / relative if isinstance(relative, str) else None
        if (Path(relative).name if isinstance(relative, str) else None) != name or \
                path is None or path.is_symlink() or not path.is_file() or \
                not isinstance(digest, bytes) or sha384_digest(path) != digest:
            raise RuntimeError("SDK_RESTORE_ARTIFACT_DIGEST_MISMATCH")
        files[name] = path
    return restore, files


def materialize_saved_generation(candidate: Path) -> None:
    """Expose an sdk-cryptex output through the transaction's stable filenames."""
    restored = _restore_payload(candidate)
    if restored is None:
        return
    _, files = restored
    aliases = {
        "srdsh-apfs-sealed-udzo.dmg": files["gdmg"],
        "srdsh.gtcd": files["gtcd"],
    }
    for name, source in aliases.items():
        target = candidate / name
        if target.exists():
            if target.is_symlink() or not target.is_file() or sha256(target) != sha256(source):
                raise RuntimeError("SDK_RESTORE_ALIAS_MISMATCH")
            continue
        os.link(source, target)
    raw = raw_volume_hash(files["gtgv"].read_bytes())
    target = candidate / "srdsh-apfs-sealed.hash"
    if target.exists():
        if target.is_symlink() or not target.is_file() or target.read_bytes() != raw:
            raise RuntimeError("SDK_RESTORE_VOLUME_HASH_MISMATCH")
    else:
        temporary = target.with_name("." + target.name + "." + str(os.getpid()))
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)


def select_generation(active_manifest_hash: str, root: Path = GENERATIONS) -> Path:
    """Refuse ambiguous or incomplete saved generations."""
    if len(active_manifest_hash) != 64:
        raise ValueError("INVALID_ACTIVE_MANIFEST_HASH")
    matches = []
    for candidate in root.iterdir():
        if candidate.is_symlink() or not candidate.is_dir():
            continue
        manifest = candidate / REQUIRED[0]
        if manifest.is_symlink() or not manifest.is_file():
            continue
        if sha256(manifest) != active_manifest_hash:
            continue
        materialize_saved_generation(candidate)
        if any((candidate / name).is_symlink() or not (candidate / name).is_file()
               for name in REQUIRED):
            raise RuntimeError("MATCHED_GENERATION_INCOMPLETE")
        matches.append(candidate)
    if len(matches) != 1:
        raise RuntimeError("ROLLBACK_GENERATION_AMBIGUOUS_OR_MISSING")
    return matches[0]


def verify_sealed_records(mount: Path, manifest: dict) -> None:
    """Prove manifest-listed Frida and preference bytes are in the image."""
    records = []
    frida = manifest.get("frida")
    if frida is not None:
        if (not isinstance(frida, dict) or not isinstance(frida.get("files"), list)
                or not frida["files"] or
                not all(isinstance(item, dict) for item in frida["files"])):
            raise RuntimeError("SEALED_FRIDA_MANIFEST_INVALID")
        records.extend((item.get("path"), item.get("sha256"))
                       for item in frida["files"])
    descriptors = manifest.get("preference_descriptors", [])
    if not isinstance(descriptors, list) or \
            not all(isinstance(item, dict) for item in descriptors):
        raise RuntimeError("SEALED_PREFERENCE_MANIFEST_INVALID")
    records.extend((item.get("descriptor"), item.get("sha256"))
                   for item in descriptors)
    unique: dict[str, str] = {}
    for raw, expected in records:
        if raw in unique and unique[raw] != expected:
            raise RuntimeError("SEALED_RECORD_CONFLICT")
        unique[raw] = expected
    root = mount.resolve(strict=True)
    prefix = Path("/var/jb")
    for raw, expected in unique.items():
        if not isinstance(raw, str) or not isinstance(expected, str) or \
                len(expected) != 64 or ".." in Path(raw).parts:
            raise RuntimeError("SEALED_RECORD_INVALID")
        path = Path(raw)
        if not path.is_absolute() or not path.is_relative_to(prefix):
            raise RuntimeError("SEALED_RECORD_OUTSIDE_ROOTLESS_PREFIX")
        target = mount / path.relative_to(prefix)
        if target.is_symlink() or not target.is_file() or \
                not target.resolve().is_relative_to(root) or sha256(target) != expected:
            raise RuntimeError("SEALED_RECORD_HASH_MISMATCH")


def verify_sealed_image(candidate: Path, expected_manifest_hash: str) -> dict:
    image = candidate / "srdsh-apfs-sealed-udzo.dmg"
    check = subprocess.run(["hdiutil", "verify", str(image)], capture_output=True,
                           timeout=60, check=False)
    if check.returncode and _restore_payload(candidate) is None:
        raise RuntimeError("ROLLBACK_IMAGE_CHECKSUM_INVALID")
    with tempfile.TemporaryDirectory(prefix="0sky-rollback-check-") as directory:
        mount = Path(directory) / "mnt"
        mount.mkdir()
        attach = subprocess.run(["hdiutil", "attach", "-readonly", "-nobrowse",
                                 "-mountpoint", str(mount), str(image)],
                                capture_output=True, timeout=60, check=False)
        if attach.returncode:
            raise RuntimeError("ROLLBACK_IMAGE_MOUNT_FAILED")
        primary_error = None
        try:
            sealed = mount / "usr/share/0-sky/dynamic-tweak-manifest.json"
            if not sealed.is_file() or sealed.is_symlink() or \
                    sha256(sealed) != expected_manifest_hash:
                raise RuntimeError("ROLLBACK_SEALED_MANIFEST_MISMATCH")
            verify_sealed_records(mount, json.loads(sealed.read_text()))
        except Exception as error:
            primary_error = error
        detach_error = None
        try:
            detached = subprocess.run(["hdiutil", "detach", str(mount)],
                                      capture_output=True, timeout=60, check=False)
            if detached.returncode:
                raise RuntimeError("ROLLBACK_IMAGE_DETACH_FAILED")
        except Exception as error:
            detach_error = error
        if primary_error and detach_error:
            raise ExceptionGroup("rollback image validation and cleanup failed",
                                 [primary_error, detach_error])
        if primary_error:
            raise primary_error
        if detach_error:
            raise detach_error
    return {"image_sha256": sha256(image),
            "trustcache_sha256": sha256(candidate / "srdsh.gtcd"),
            "volumehash_sha256": sha256(candidate / "srdsh-apfs-sealed.hash"),
            "sealed_manifest_sha256": expected_manifest_hash}


async def installed_version(udid: str) -> str:
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid:
            raise RuntimeError("REMOTEXPC_DEVICE_MISMATCH")
        entries = await asyncio.wait_for(CryptexdService(rsd).copy_installed(), timeout=20)
        matches = [item.version for item in entries if item.identifier == IDENTIFIER]
        if len(matches) != 1:
            raise RuntimeError("ACTIVE_CRYPTEX_NOT_UNIQUE")
        return matches[0]


def mounted_manifest_hash(worker: dict) -> str:
    code = """import hashlib,json,pathlib,subprocess
mount=subprocess.run(['/sbin/mount'],capture_output=True,text=True,timeout=5,check=True)
matches=[]
for line in mount.stdout.splitlines():
 if 'codes.openai.research.ellekitloader' not in line: continue
 path=line.split(' on ',1)[1].split(' (',1)[0]
 p=pathlib.Path(path)/'usr/share/0-sky/dynamic-tweak-manifest.json'
 if p.is_file(): matches.append(hashlib.sha256(p.read_bytes()).hexdigest())
print(json.dumps(matches))
"""
    result = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(code),
                           timeout=20, check=False)
    if result.returncode:
        raise RuntimeError("PINNED_SSH_MOUNT_PROBE_FAILED")
    matches = json.loads(result.stdout)
    if not isinstance(matches, list) or len(matches) != 1 or \
            not isinstance(matches[0], str):
        raise RuntimeError("ACTIVE_MOUNT_NOT_UNIQUE")
    return matches[0]


def run(instance: str, udid: str) -> dict:
    selected = profiles(instance_name=instance)
    if udid not in selected or asyncio.run(usb_identity(udid))["udid"] != udid:
        raise RuntimeError("EXACT_USB_PROFILE_MISMATCH")
    worker = worker_namespace(selected[udid][1])
    active_hash = mounted_manifest_hash(worker)
    version = asyncio.run(installed_version(udid))
    instance_root = (Path(worker["INSTANCE"]) / "automation/artifacts/srd-runtime-poc/"
                     "runtime-generations")
    if instance_root.is_symlink() or not instance_root.is_dir():
        raise RuntimeError("INSTANCE_GENERATION_ROOT_UNAVAILABLE")
    candidate = select_generation(active_hash, instance_root)
    integrity = verify_sealed_image(candidate, active_hash)
    return {"result": "PASS", "device_suffix": udid[-8:],
            "active_version": version, "rollback_generation": candidate.name,
            "rollback_artifact_verified": True, **integrity}


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: frida_cryptex_rollback_preflight.py INSTANCE EXACT_UDID")
    result = run(sys.argv[1], sys.argv[2])
    destination = HERE / "0sky-uat" / result["device_suffix"].lower() / \
        "frida-rollback-preflight.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise RuntimeError("refusing symbolic-link rollback report")
    temporary = destination.with_name("." + destination.name + "-" + str(os.getpid()))
    with temporary.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
