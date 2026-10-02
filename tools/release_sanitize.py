#!/usr/bin/env python3
"""Audit installer inputs for embedded personal data without printing it."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile
from typing import BinaryIO


PATTERNS = {
    "fixed-home-path": re.compile(rb"/(?:Users|home)/[A-Za-z0-9._-]+"),
    "mounted-volume-path": re.compile(rb"/Volumes/[A-Za-z0-9._ -]+(?:/|\x00)"),
    "derived-data-path": re.compile(rb"(?i)\bDerivedData(?:/|\\|\x00)"),
    # A bare file URL is a normal Foundation/CoreFoundation string and does not
    # identify the build host.  Flag only file URLs rooted in locations that
    # can disclose a developer account or transient build workspace.
    "absolute-file-uri": re.compile(
        rb"(?i)file:///(?:Users|home|Volumes|private/(?:tmp|var/folders)|tmp|var/folders)/"),
    "physical-device-id": re.compile(rb"\b0000(?!0000)[0-9A-Fa-f]{4}-[0-9A-Fa-f]{16}\b"),
    "private-key": re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----"),
    "embedded-password": re.compile(
        rb"(?im)^\s*(?:CERT_PASS|PASSWORD|API_TOKEN|PRIVATE_KEY)\s*=\s*['\"][^'\"$]{4,}['\"]\s*$"),
    "personal-payment": re.compile(rb"https?://(?:www\.)?account\.venmo\.com/u/", re.I),
    "ssh-public-key-comment": re.compile(
        rb"(?m)^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) "
        rb"[A-Za-z0-9+/=]+ [^\r\n]*@"),
    "developer-coredevice-host": re.compile(rb"(?i)\b[a-z0-9._-]+-iphone\.coredevice\.local\b"),
    "local-ip-address": re.compile(
        rb"\b(?:192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})\b"),
    "temporary-build-path": re.compile(
        rb"(?<!/var/jb/var)/(?:private/)?tmp/0sky-[A-Za-z0-9_-]{8,}/"),
}
CHUNK_SIZE = 1024 * 1024
OVERLAP = 8192
MAX_ARCHIVE_MEMBER = 1024 * 1024 * 1024


def load_deny_patterns(path: Path) -> dict[str, re.Pattern[bytes]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    patterns = value.get("patterns")
    if not isinstance(patterns, dict):
        raise ValueError("deny file must contain a patterns object")
    return {"project-" + category: re.compile(expression.encode("utf-8"))
            for category, expression in patterns.items()
            if isinstance(category, str) and isinstance(expression, str)}


def audit(paths: list[Path], deny_patterns: dict[str, re.Pattern[bytes]] | None = None) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    patterns = {**PATTERNS, **(deny_patterns or {})}

    def safe_label(value: str) -> str:
        components = []
        for component in Path(value).parts:
            if ("@" in component or any(pattern.search(component.encode("utf-8", "replace"))
                   for pattern in patterns.values())):
                digest = hashlib.sha256(component.encode("utf-8")).hexdigest()[:12]
                components.append(f"<redacted-name:{digest}>")
            else:
                components.append(component)
        return "/".join(components)

    def scan_stream(stream: BinaryIO, label: str) -> None:
        found: set[str] = set()
        tail = b""
        while chunk := stream.read(CHUNK_SIZE):
            data = tail + chunk
            for category, pattern in patterns.items():
                if category not in found and pattern.search(data):
                    findings.append({"file": label, "category": category})
                    found.add(category)
            tail = data[-OVERLAP:]

    def scan_name(value: str, label: str) -> None:
        data = value.encode("utf-8", "replace")
        for category, pattern in patterns.items():
            if pattern.search(data):
                findings.append({"file": label, "category": category})

    def scan_zip_file(path: Path, label: str) -> None:
        try:
            with zipfile.ZipFile(path) as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    member_label = label + "!/" + safe_label(member.filename)
                    if (Path(member.filename).is_absolute() or
                            ".." in Path(member.filename).parts):
                        findings.append({"file": member_label,
                                         "category": "unsafe-archive-path"})
                    scan_name(member.filename, member_label)
                    if member.file_size > MAX_ARCHIVE_MEMBER:
                        findings.append({"file": member_label,
                                         "category": "oversized-archive-member"})
                        continue
                    with archive.open(member) as stream:
                        scan_stream(stream, member_label)
        except (OSError, zipfile.BadZipFile, RuntimeError):
            findings.append({"file": label, "category": "invalid-archive"})

    def scan_deb(path: Path, label: str) -> None:
        try:
            outer = subprocess.run(["/usr/bin/bsdtar", "-tf", str(path)],
                                   capture_output=True, timeout=30, check=False)
            if outer.returncode:
                raise ValueError("invalid ar archive")
            members = [line.strip() for line in outer.stdout.decode("utf-8", "replace").splitlines()]
            nested = [name for name in members if name.startswith(("data.tar.", "control.tar."))]
            if not any(name.startswith("data.tar.") for name in nested):
                raise ValueError("missing Debian payload")
            with tempfile.TemporaryDirectory(prefix="0sky-deb-scan-") as folder:
                for index, name in enumerate(nested):
                    archive = Path(folder) / f"nested-{index}.tar"
                    with archive.open("wb") as output:
                        extracted = subprocess.run(["/usr/bin/bsdtar", "-xOf", str(path), name],
                                                   stdout=output, stderr=subprocess.DEVNULL,
                                                   timeout=120, check=False)
                    if extracted.returncode:
                        raise ValueError("invalid Debian member")
                    listing = subprocess.run(["/usr/bin/bsdtar", "-tf", str(archive)],
                                             capture_output=True, timeout=60, check=False)
                    if listing.returncode:
                        raise ValueError("invalid nested archive")
                    for member_index, member in enumerate(
                            listing.stdout.decode("utf-8", "replace").splitlines()):
                        clean = member.removeprefix("./")
                        member_label = label + "!/" + safe_label(clean)
                        if Path(clean).is_absolute() or ".." in Path(clean).parts:
                            findings.append({"file": member_label, "category": "unsafe-archive-path"})
                        scan_name(member, member_label)
                        if Path(clean).suffix.lower() in {".ipa", ".zip", ".whl"}:
                            nested_zip = Path(folder) / f"zip-{index}-{member_index}"
                            with nested_zip.open("wb") as output:
                                extracted_zip = subprocess.run(
                                    ["/usr/bin/bsdtar", "-xOf", str(archive), member],
                                    stdout=output, stderr=subprocess.DEVNULL,
                                    timeout=120, check=False)
                            if extracted_zip.returncode:
                                raise ValueError("nested ZIP extraction failed")
                            scan_zip_file(nested_zip, member_label)
                    with tempfile.TemporaryFile() as output:
                        contents = subprocess.run(["/usr/bin/bsdtar", "-xOf", str(archive)],
                                                  stdout=output, stderr=subprocess.DEVNULL,
                                                  timeout=300, check=False)
                        if contents.returncode:
                            raise ValueError("nested archive extraction failed")
                        output.seek(0)
                        scan_stream(output, label + "!/" + name)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            findings.append({"file": label, "category": "invalid-archive"})

    for root in paths:
        files = [root] if root.is_file() else root.rglob("*")
        for path in files:
            if path.is_symlink():
                label = safe_label(str(path.relative_to(root)) if root.is_dir() else path.name)
                try:
                    target = os.readlink(path)
                    if Path(target).is_absolute() or ".." in Path(target).parts:
                        findings.append({"file": label, "category": "unsafe-symlink"})
                    scan_name(target, label)
                except OSError:
                    findings.append({"file": label, "category": "unreadable"})
                continue
            if not path.is_file():
                continue
            label = safe_label(str(path.relative_to(root)) if root.is_dir() else path.name)
            scan_name(str(path.relative_to(root)) if root.is_dir() else path.name, label)
            if path.suffix.lower() in {".ipa", ".zip", ".whl"}:
                scan_zip_file(path, label)
                continue
            if path.suffix.lower() == ".deb":
                scan_deb(path, label)
                continue
            try:
                with path.open("rb") as stream:
                    scan_stream(stream, label)
            except OSError:
                findings.append({"file": label, "category": "unreadable"})
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--deny-file", type=Path,
                        help="JSON patterns for project-specific release exclusions")
    args = parser.parse_args()
    deny = load_deny_patterns(args.deny_file) if args.deny_file else {}
    findings = audit(args.paths, deny)
    print(json.dumps({"passed": not findings, "findings": findings}, indent=2, sort_keys=True))
    return 0 if not findings else 2


if __name__ == "__main__":
    raise SystemExit(main())
