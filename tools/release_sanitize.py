#!/usr/bin/env python3
"""Audit installer inputs for embedded personal data without printing it."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import zipfile


PATTERNS = {
    "fixed-home-path": re.compile(rb"/(?:Users|home)/(?!example/|username/|USER/)[A-Za-z0-9._-]+/"),
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
SKIP_PARTS = {".git", ".build", ".venv", "__pycache__", "artifacts"}
TEXT_SUFFIXES = {".py", ".sh", ".command", ".json", ".plist", ".txt",
                 ".md", ".xml", ".yaml", ".yml", ".swift", ".m", ".h"}


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

    def scan(data: bytes, label: str) -> None:
        for category, pattern in patterns.items():
            if pattern.search(data):
                findings.append({"file": label, "category": category})

    for root in paths:
        files = [root] if root.is_file() else root.rglob("*")
        for path in files:
            if not path.is_file() or any(part in SKIP_PARTS
                                         for part in path.relative_to(root).parts):
                continue
            label = path.name
            if path.suffix.lower() in {".ipa", ".zip"}:
                try:
                    with zipfile.ZipFile(path) as archive:
                        for member in archive.infolist():
                            if (member.is_dir() or member.file_size > 4 * 1024 * 1024
                                    or Path(member.filename).suffix.lower() not in TEXT_SUFFIXES):
                                continue
                            data = archive.read(member)
                            scan(data, label + "!/" + Path(member.filename).name)
                except (OSError, zipfile.BadZipFile, RuntimeError):
                    findings.append({"file": label, "category": "invalid-archive"})
                continue
            try:
                with path.open("rb") as stream:
                    sample = stream.read(4096)
                    stream.seek(0)
                    data = stream.read() if path.stat().st_size <= 64 * 1024 * 1024 else sample
            except OSError:
                findings.append({"file": label, "category": "unreadable"})
                continue
            scan(data, label)
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
