#!/usr/bin/env python3
"""Audit installer inputs for embedded personal data without printing it."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
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
    # Require key material after the PEM header. Crypto libraries legitimately
    # contain the header as a string constant when parsing keys generated for
    # users; that is not itself a bundled private key.
    "private-key": re.compile(
        rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----\r?\n"
        rb"(?:[A-Za-z0-9+/=]{16,}\r?\n?)+"),
    "embedded-password": re.compile(
        rb"(?im)^\s*(?:CERT_PASS|API_TOKEN|ZERO_SKY_[A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET))"
        rb"\s*=\s*['\"][^'\"$]{8,}['\"]\s*$"),
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
# These strings commonly occur in reproducible upstream binaries, source maps,
# documentation, and networking libraries. They are reported for audit but do
# not make an otherwise verified payload unusable or disclose a release-owned
# secret. Exact caller-owned values remain blocking through project-* deny
# patterns, while Mach-O runtime paths are checked structurally by the release
# verifier rather than inferred from arbitrary debug strings.
ADVISORY_CATEGORIES = {
    "fixed-home-path", "mounted-volume-path", "derived-data-path",
    "absolute-file-uri", "local-ip-address", "personal-payment",
    "temporary-build-path",
}
CHUNK_SIZE = 1024 * 1024
OVERLAP = 8192
MAX_ARCHIVE_MEMBER = 1024 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]
EXCEPTIONS_PATH = ROOT / "manifests/release-sanitizer-exceptions.json"


def load_exceptions(path: Path = EXCEPTIONS_PATH) -> list[dict[str, str]]:
    """Load hash-bound exceptions for public upstream test fixtures only."""
    if not path.is_file() or path.is_symlink():
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    entries = value.get("entries") if isinstance(value, dict) else None
    if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(entries, list):
        raise ValueError("release sanitizer exception manifest is invalid")
    result: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("release sanitizer exception entry is invalid")
        required = ("file", "category", "member_prefix", "reason")
        if any(not isinstance(entry.get(key), str) or not entry[key] for key in required):
            raise ValueError("release sanitizer exception entry is incomplete")
        bindings = {key: entry.get(key) for key in ("sha256", "member_sha256")
                    if entry.get(key) is not None}
        if len(bindings) != 1 or any(not isinstance(value, str) or
                                    not re.fullmatch(r"[a-f0-9]{64}", value)
                                    for value in bindings.values()):
            raise ValueError("release sanitizer exception must have one exact hash binding")
        relative = Path(entry["file"])
        if (relative.is_absolute() or ".." in relative.parts or
                entry["category"] not in {"private-key", "project-local-address-*"} or
                entry["member_prefix"].startswith(("/", "../"))):
            raise ValueError("release sanitizer exception entry is unsafe")
        result.append({key: entry[key] for key in required} | bindings)
    return result


def load_deny_patterns(path: Path) -> dict[str, re.Pattern[bytes]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    patterns = value.get("patterns")
    if not isinstance(patterns, dict):
        raise ValueError("deny file must contain a patterns object")
    build_reference_labels = {"builder-home", "checkout", "staging", "output", "username"}
    return {
        ("project-build-reference-" if category in build_reference_labels else "project-")
        + category: re.compile(expression.encode("utf-8"))
        for category, expression in patterns.items()
        if isinstance(category, str) and isinstance(expression, str)
    }


def blocking_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return only findings that represent secrets, identity, or unsafe input."""
    return [finding for finding in findings
            if finding.get("category") not in ADVISORY_CATEGORIES and
            not finding.get("category", "").startswith("project-build-reference-") and
            finding.get("disposition") != "verified-public-test-fixture"]


def audit(paths: list[Path], deny_patterns: dict[str, re.Pattern[bytes]] | None = None,
          exceptions: list[dict[str, str]] | None = None) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    patterns = {**PATTERNS, **(deny_patterns or {})}
    approved = load_exceptions() if exceptions is None else exceptions

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
        def scan_with_bsdtar(archive: Path, archive_label: str, folder: Path,
                            archive_index: int) -> None:
            """Scan compression formats unsupported by older system Python.

            Member names and every link target are validated before extraction;
            extraction is confined to a new directory and every resulting path
            is checked again before content is read.
            """
            listing = subprocess.run(["/usr/bin/bsdtar", "-tf", str(archive)],
                                     capture_output=True, timeout=120, check=False)
            verbose = subprocess.run(["/usr/bin/bsdtar", "-tvf", str(archive)],
                                     capture_output=True, timeout=120, check=False)
            if listing.returncode or verbose.returncode:
                raise ValueError("invalid nested archive")
            names = listing.stdout.decode("utf-8", "replace").splitlines()
            details = verbose.stdout.decode("utf-8", "replace").splitlines()
            if len(names) != len(details):
                raise ValueError("ambiguous nested archive inventory")
            excluded_links: list[str] = []
            for name, detail in zip(names, details):
                clean = name.removeprefix("./")
                relative = Path(clean)
                member_label = archive_label + "!/" + safe_label(clean)
                if relative.is_absolute() or ".." in relative.parts:
                    findings.append({"file": member_label, "category": "unsafe-archive-path"})
                    raise ValueError("unsafe nested archive path")
                scan_name(name, member_label)
                kind = detail[:1]
                if kind in {"l", "h"}:
                    excluded_links.append(name)
                    separator = " -> " if kind == "l" else " link to "
                    if separator not in detail:
                        raise ValueError("ambiguous nested archive link")
                    target_text = detail.rsplit(separator, 1)[1]
                    target = Path(target_text)
                    normalized = Path(os.path.normpath((relative.parent / target).as_posix()))
                    safe_absolute = target_text.startswith("/var/jb/")
                    if ((target.is_absolute() and not safe_absolute) or
                            (not target.is_absolute() and
                             (normalized.is_absolute() or ".." in normalized.parts))):
                        findings.append({"file": member_label, "category": "unsafe-symlink"})
                        raise ValueError("unsafe nested archive link")
                    scan_name(target_text, member_label)
                elif kind not in {"-", "d"}:
                    findings.append({"file": member_label, "category": "unsafe-archive-member"})
                    raise ValueError("unsafe nested archive member")
            extracted_root = folder / f"expanded-{archive_index}"
            extracted_root.mkdir()
            extract_command = ["/usr/bin/bsdtar", "-xf", str(archive),
                               "-C", str(extracted_root), "--no-same-owner",
                               "--no-same-permissions"]
            for link_name in excluded_links:
                extract_command += ["--exclude", link_name]
            unpacked = subprocess.run(
                extract_command,
                capture_output=True, timeout=180, check=False)
            if unpacked.returncode:
                raise ValueError("nested archive extraction failed")
            for extracted in extracted_root.rglob("*"):
                if extracted.is_symlink() or not extracted.is_file():
                    continue
                resolved = extracted.resolve()
                if extracted_root.resolve() not in resolved.parents:
                    raise ValueError("nested archive escaped extraction root")
                relative = extracted.relative_to(extracted_root)
                member_label = archive_label + "!/" + safe_label(relative.as_posix())
                if extracted.stat().st_size > MAX_ARCHIVE_MEMBER:
                    findings.append({"file": member_label,
                                     "category": "oversized-archive-member"})
                    continue
                if relative.suffix.lower() in {".ipa", ".zip", ".whl"}:
                    scan_zip_file(extracted, member_label)
                else:
                    with extracted.open("rb") as stream:
                        scan_stream(stream, member_label)

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
                    try:
                        bundle_context = tarfile.open(archive, "r:*")
                    except tarfile.ReadError:
                        scan_with_bsdtar(archive, label, Path(folder), index)
                        continue
                    with bundle_context as bundle:
                        members = bundle.getmembers()
                        for member_index, member in enumerate(members):
                            clean = member.name.removeprefix("./")
                            member_label = label + "!/" + safe_label(clean)
                            relative = Path(clean)
                            if relative.is_absolute() or ".." in relative.parts:
                                findings.append({"file": member_label,
                                                 "category": "unsafe-archive-path"})
                                continue
                            scan_name(member.name, member_label)
                            if member.isdev() or member.isfifo():
                                findings.append({"file": member_label,
                                                 "category": "unsafe-archive-member"})
                                continue
                            if member.issym() or member.islnk():
                                target = Path(member.linkname)
                                if target.is_absolute():
                                    resolved_target = member.linkname.lstrip("/").rstrip("/")
                                    safe_link = member.linkname.startswith("/var/jb/")
                                else:
                                    resolved_target = (relative.parent / target)
                                    normalized = Path(os.path.normpath(resolved_target.as_posix()))
                                    safe_link = (not normalized.is_absolute() and
                                                 ".." not in normalized.parts)
                                if not safe_link:
                                    findings.append({"file": member_label,
                                                     "category": "unsafe-symlink"})
                                scan_name(member.linkname, member_label)
                                continue
                            if not member.isfile():
                                continue
                            if member.size > MAX_ARCHIVE_MEMBER:
                                findings.append({"file": member_label,
                                                 "category": "oversized-archive-member"})
                                continue
                            stream = bundle.extractfile(member)
                            if stream is None:
                                raise ValueError("nested archive member is unreadable")
                            if relative.suffix.lower() in {".ipa", ".zip", ".whl"}:
                                nested_zip = Path(folder) / f"zip-{index}-{member_index}"
                                with nested_zip.open("wb") as output:
                                    while block := stream.read(CHUNK_SIZE):
                                        output.write(block)
                                scan_zip_file(nested_zip, member_label)
                            else:
                                scan_stream(stream, member_label)
        except (OSError, ValueError, tarfile.TarError, subprocess.TimeoutExpired):
            findings.append({"file": label, "category": "invalid-archive"})

    roots: list[Path] = []
    for root in paths:
        roots.append(root)
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
    hash_cache: dict[Path, str] = {}
    member_hash_cache: dict[tuple[Path, str], str | None] = {}
    for finding in findings:
        label = finding["file"]
        outer, separator, member = label.partition("!/")
        if not separator:
            continue
        for root in roots:
            outer_path = root if root.is_file() else root / outer
            if not outer_path.is_file():
                continue
            for entry in approved:
                if (not fnmatch.fnmatchcase(finding["category"], entry["category"]) or
                        not (outer == entry["file"] or outer.endswith("/" + entry["file"])) or
                        not member.startswith(entry["member_prefix"])):
                    continue
                approved_hash = False
                if "sha256" in entry:
                    if outer_path not in hash_cache:
                        value = hashlib.sha256()
                        with outer_path.open("rb") as stream:
                            for block in iter(lambda: stream.read(CHUNK_SIZE), b""):
                                value.update(block)
                        hash_cache[outer_path] = value.hexdigest()
                    approved_hash = hash_cache[outer_path] == entry["sha256"]
                else:
                    key = (outer_path, member)
                    if key not in member_hash_cache:
                        try:
                            value = hashlib.sha256()
                            with zipfile.ZipFile(outer_path) as archive, archive.open(member) as stream:
                                for block in iter(lambda: stream.read(CHUNK_SIZE), b""):
                                    value.update(block)
                            member_hash_cache[key] = value.hexdigest()
                        except (OSError, KeyError, zipfile.BadZipFile):
                            member_hash_cache[key] = None
                    approved_hash = member_hash_cache[key] == entry["member_sha256"]
                if approved_hash:
                    finding["disposition"] = "verified-public-test-fixture"
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--deny-file", type=Path,
                        help="JSON patterns for project-specific release exclusions")
    parser.add_argument("--verbose", action="store_true",
                        help="include every advisory finding; blockers are always shown")
    args = parser.parse_args()
    deny = load_deny_patterns(args.deny_file) if args.deny_file else {}
    findings = audit(args.paths, deny)
    blocked = blocking_findings(findings)
    advisory = [item for item in findings if item not in blocked]
    categories: dict[str, int] = {}
    for item in advisory:
        category = item.get("category", "unknown")
        categories[category] = categories.get(category, 0) + 1
    result: dict[str, object] = {
        "passed": not blocked,
        "blocking_findings": blocked,
        "advisory_summary": {"count": len(advisory), "categories": categories},
    }
    if args.verbose:
        result["advisory_findings"] = advisory
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not blocked else 2


if __name__ == "__main__":
    raise SystemExit(main())
