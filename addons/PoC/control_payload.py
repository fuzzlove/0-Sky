"""Build and verify the immutable 0-Sky Control payload manifest.

The release pipeline invokes ``create_manifest`` on the one canonical IPA in
the verified kit. Link embeds that IPA once in SRDKit and seals this manifest
inside its signed application bundle.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import zipfile


BUNDLE_ID = "com.liquidsky.CrypStore"
PAYLOAD_PATH = "SRDKit/packages/Commissary-Universal.ipa"
MAX_MEMBERS = 4096
MAX_EXPANDED = 512 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class PayloadError(ValueError):
    """The packaged Control artifact or its release manifest is invalid."""


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    entries = archive.infolist()
    if not entries or len(entries) > MAX_MEMBERS:
        raise PayloadError("IPA member count is invalid")
    if sum(item.file_size for item in entries) > MAX_EXPANDED:
        raise PayloadError("IPA expanded size exceeds the Control limit")
    found: dict[str, zipfile.ZipInfo] = {}
    for item in entries:
        name = item.filename
        parts = PurePosixPath(name).parts
        if (not name or name.startswith("/") or "\\" in name or
                any(part in ("", ".", "..") for part in name.rstrip("/").split("/")) or
                not parts or parts[0] != "Payload" or name in found):
            raise PayloadError("IPA contains an unsafe or duplicate member")
        mode = (item.external_attr >> 16) & 0xffff
        if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise PayloadError("IPA contains a link or special file")
        found[name] = item
    return found


def _identity(archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo]) -> dict:
    info_name = "Payload/CrypStore.app/Info.plist"
    if info_name not in members:
        raise PayloadError("Control Info.plist is absent")
    try:
        info = plistlib.loads(archive.read(info_name))
    except (ValueError, plistlib.InvalidFileException) as error:
        raise PayloadError("Control Info.plist is invalid") from error
    identity = {field: info.get(field) for field in
                ("CFBundleIdentifier", "CFBundleExecutable", "CFBundleVersion",
                 "CFBundleShortVersionString")}
    if identity["CFBundleIdentifier"] != BUNDLE_ID:
        raise PayloadError("Control bundle identifier is wrong")
    executable = identity["CFBundleExecutable"]
    if not isinstance(executable, str) or not executable or "/" in executable:
        raise PayloadError("Control executable name is invalid")
    executable_name = "Payload/CrypStore.app/" + executable
    if executable_name not in members:
        raise PayloadError("Control executable is absent")
    header = archive.read(executable_name)[:12]
    # Thin arm64 Mach-O. The current Control makefile builds ARCHS=arm64.
    if len(header) < 12 or struct.unpack_from("<II", header) != (0xfeedfacf, 0x0100000c):
        raise PayloadError("Control executable is not arm64 Mach-O")
    if not all(isinstance(identity[field], str) and identity[field]
               for field in ("CFBundleVersion", "CFBundleShortVersionString")):
        raise PayloadError("Control version is absent")
    return identity


def create_manifest(ipa: Path, entitlements: Path) -> dict:
    """Describe exact release bytes; the caller writes this inside signed Link."""
    if ipa.is_symlink() or not ipa.is_file():
        raise PayloadError("Control IPA is missing or is a symbolic link")
    ipa = ipa.resolve(strict=True)
    with zipfile.ZipFile(ipa) as archive:
        members = _members(archive)
        identity = _identity(archive, members)
        hashes = {name: hashlib.sha256(archive.read(name)).hexdigest()
                  for name, member in members.items() if not member.is_dir()}
    declared = plistlib.loads(entitlements.read_bytes())
    if not isinstance(declared, dict):
        raise PayloadError("Control entitlement declaration is invalid")
    return {
        "schema": 1,
        "application": "0-Sky Control",
        "payload_path": PAYLOAD_PATH,
        "ipa_sha256": digest(ipa),
        "identity": identity,
        "supported_os": {"minimum_major": 17, "maximum_major": 27},
        "architectures": ["arm64"],
        "backend": "paired-srd-worker-v1",
        "registration": "appregistrard-or-native-install",
        "bootstrap_requirements": ["rootless-python", "device-bridge", "paired-mac-worker"],
        "services": [],
        "permissions": {"required_entitlements": declared, "optional": [],
                        "user_approval_required": []},
        "files": hashes,
    }


def verify_manifest(ipa: Path, manifest: dict) -> dict:
    """Validate every IPA member and the complete archive before staging."""
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise PayloadError("Control manifest schema is unsupported")
    if manifest.get("payload_path") != PAYLOAD_PATH or manifest.get("backend") != "paired-srd-worker-v1":
        raise PayloadError("Control payload backend or path differs from the release contract")
    expected = manifest.get("ipa_sha256")
    if not isinstance(expected, str) or not SHA256.fullmatch(expected) or digest(ipa) != expected:
        raise PayloadError("Control IPA SHA-256 mismatch")
    with zipfile.ZipFile(ipa) as archive:
        members = _members(archive)
        identity = _identity(archive, members)
        hashes = {name: hashlib.sha256(archive.read(name)).hexdigest()
                  for name, member in members.items() if not member.is_dir()}
    if identity != manifest.get("identity") or hashes != manifest.get("files"):
        raise PayloadError("Control IPA contents differ from the release manifest")
    return identity


def load_manifest(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 262144:
        raise PayloadError("Control manifest is absent or too large")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        raise PayloadError("Control manifest is invalid JSON") from error
