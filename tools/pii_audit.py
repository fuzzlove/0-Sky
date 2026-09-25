#!/usr/bin/env python3
"""Fail when a source release contains local PII, secrets, or binary payloads."""
from __future__ import annotations

import argparse
from pathlib import Path
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

CHECKS = (
    ("fixed-home-path", re.compile(rb"/(?:Users|home)/(?!example/|username/|USER/)[A-Za-z0-9._-]+/")),
    ("physical-udid", re.compile(rb"\b0000(?!0000)[0-9A-Fa-f]{4}-[0-9A-Fa-f]{16}\b")),
    ("derived-device-id", re.compile(rb"\b(?:iphone|ipad)-srd-(?!0{7}[0-9]\b)[0-9a-f]{8}\b", re.I)),
    ("personal-payment", re.compile(rb"https?://(?:www\.)?account\.venmo\.com/u/", re.I)),
    ("private-key", re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----")),
    ("embedded-credential", re.compile(
        rb"(?im)^\s*(?:CERT_PASS|PASSWORD|API_TOKEN|PRIVATE_KEY)\s*=\s*['\"][^'\"$]{4,}['\"]\s*$")),
)


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
    report = {"schema": 1, "passed": not findings,
              "files_scanned_root": root.name, "findings": findings}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not findings else 2


if __name__ == "__main__":
    raise SystemExit(main())
