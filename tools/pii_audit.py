#!/usr/bin/env python3
"""Fail when a source release contains local PII, secrets, or binary payloads."""
from __future__ import annotations

import argparse
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys

SKIP_DIRS = {".git", ".build", ".venv", "artifacts", "build", "dist", ".theos", "DerivedData",
             "__pycache__", "packages", "work", "state", "logs", "evidence",
             "research_sessions"}
BINARY_SOURCE_SUFFIXES = {".ipa", ".deb", ".dmg", ".pkg", ".p12",
                          ".mobileprovision", ".provisionprofile", ".pem",
                          ".key", ".cer", ".crt", ".zip", ".zst"}
TEXT_SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".icns"}
ALLOWLIST_PATH = Path("tools/pii_audit_allowlist.json")

CHECKS = (
    ("fixed-home-path", re.compile(rb"/(?:Users|home)/(?!example/|username/|USER/)[A-Za-z0-9._-]+/")),
    ("physical-udid", re.compile(rb"\b0000(?!0000)[0-9A-Fa-f]{4}-[0-9A-Fa-f]{16}\b")),
    ("derived-device-id", re.compile(rb"\b(?:iphone|ipad)-srd-(?!0{7}[0-9]\b)[0-9a-f]{8}\b", re.I)),
    ("personal-payment", re.compile(rb"https?://(?:www\.)?account\.venmo\.com/u/", re.I)),
    ("private-key", re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----")),
    ("embedded-credential", re.compile(
        rb"(?im)^\s*(?:CERT_PASS|PASSWORD|API_TOKEN|PRIVATE_KEY)\s*=\s*['\"][^'\"$]{4,}['\"]\s*$")),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_allowlist(root: Path) -> tuple[dict[tuple[str, str], str], list[dict[str, str]]]:
    """Load exact-hash exceptions for immutable upstream or public-key fixtures."""
    path = root / ALLOWLIST_PATH
    if not path.is_file() or path.is_symlink():
        return {}, [{"category": "allowlist-missing", "file": ALLOWLIST_PATH.as_posix()}]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return {}, [{"category": "allowlist-invalid", "file": ALLOWLIST_PATH.as_posix()}]
    entries = payload.get("entries") if isinstance(payload, dict) else None
    if (not isinstance(payload, dict) or payload.get("schema") != 1 or
            not isinstance(entries, list)):
        return {}, [{"category": "allowlist-invalid", "file": ALLOWLIST_PATH.as_posix()}]
    allowed: dict[tuple[str, str], str] = {}
    errors: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            errors.append({"category": "allowlist-invalid", "file": ALLOWLIST_PATH.as_posix()})
            continue
        relative = entry.get("file")
        category = entry.get("category")
        digest = entry.get("sha256")
        if (not isinstance(relative, str) or not isinstance(category, str) or
                not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) or
                Path(relative).is_absolute() or ".." in Path(relative).parts or
                (relative, category) in allowed):
            errors.append({"category": "allowlist-invalid", "file": ALLOWLIST_PATH.as_posix()})
            continue
        allowed[(relative, category)] = digest
    return allowed, errors


def apply_allowlist(root: Path, findings: list[dict[str, object]]) -> tuple[list[dict[str, object]], int]:
    """Suppress only findings whose category, path, and current bytes are pinned."""
    allowlist, allowlist_errors = load_allowlist(root)
    approved: set[tuple[str, str]] = set()
    filtered: list[dict[str, object]] = list(allowlist_errors)
    hashes: dict[str, str | None] = {}
    for finding in findings:
        key = (str(finding["file"]), str(finding["category"]))
        expected = allowlist.get(key)
        if expected is None:
            filtered.append(finding)
            continue
        relative = key[0]
        if relative not in hashes:
            candidate = root / relative
            hashes[relative] = sha256(candidate) if candidate.is_file() else None
        if hashes[relative] == expected:
            approved.add(key)
        else:
            filtered.append({"category": "allowlist-hash-mismatch", "file": relative})
    for key, expected in allowlist.items():
        relative, _ = key
        if relative not in hashes:
            candidate = root / relative
            hashes[relative] = sha256(candidate) if candidate.is_file() else None
        if hashes[relative] != expected:
            mismatch = {"category": "allowlist-hash-mismatch", "file": relative}
            if mismatch not in filtered:
                filtered.append(mismatch)
        elif key not in approved:
            filtered.append({"category": "allowlist-stale", "file": relative})
    return filtered, len(approved)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.root.resolve()
    findings: list[dict[str, object]] = []
    tracked = subprocess.run(["git", "ls-files", "-z", "--cached", "--others",
                              "--exclude-standard"], cwd=root,
                             capture_output=True, timeout=15, check=False)
    paths = ([root / value.decode("utf-8", "surrogateescape")
              for value in tracked.stdout.split(b"\0") if value]
             if tracked.returncode == 0 else root.rglob("*"))
    for path in sorted(paths):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        relative = path.relative_to(root).as_posix()
        if relative == "tools/pii_audit.py":
            continue
        suffix = path.suffix.lower()
        if suffix in BINARY_SOURCE_SUFFIXES:
            findings.append({"category": "forbidden-binary-or-credential", "file": relative})
            continue
        data = path.read_bytes()
        if data.startswith((b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")):
            findings.append({"category": "mach-o-binary", "file": relative})
            continue
        if suffix in TEXT_SKIP_SUFFIXES:
            continue
        if any(part.endswith(".storyboardc") for part in path.relative_to(root).parts):
            # Compiled Interface Builder resources are required by the upstream
            # Control project. They contain no host or device state.
            continue
        if b"\x00" in data[:4096]:
            findings.append({"category": "unexpected-binary", "file": relative})
            continue
        for category, regex in CHECKS:
            if regex.search(data):
                findings.append({"category": category, "file": relative})
    filtered, approved_count = apply_allowlist(root, findings)
    report = {"schema": 1, "passed": not filtered,
              "files_scanned_root": root.name,
              "allowlisted_findings": approved_count, "findings": filtered}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not filtered else 2


if __name__ == "__main__":
    raise SystemExit(main())
