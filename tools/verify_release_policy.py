#!/usr/bin/env python3
"""Fail closed when supported-release policy or retained evidence diverges."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")
CURRENT_STATE = "CURRENT_VERIFIED_SUPPORTED"
DEPRECATED_STATE = "DEPRECATED_UNSUPPORTED_HISTORICAL_ONLY"
REQUIRED_EVIDENCE = {
    "SHA256SUMS",
    "build-manifest.json",
    "github-release.json",
    "notarization-info.txt",
    "public-release-audit.json",
    "RELEASE_AUDIT.txt",
    "sbom/cyclonedx.json",
    "signing-info.txt",
    "test-results/automated-tests.txt",
    "uat-results/intel-ios27.txt",
}


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def sha256sums(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        pieces = line.split(None, 1)
        if len(pieces) != 2 or not HEX64.fullmatch(pieces[0]):
            raise ValueError("SHA256SUMS contains an invalid row")
        name = pieces[1].lstrip("*")
        if not name or "/" in name or name in values:
            raise ValueError("SHA256SUMS contains an unsafe or duplicate name")
        values[name] = pieces[0]
    return values


def verify(root: Path) -> list[str]:
    errors: list[str] = []
    status_path = root / "manifests/release-status.json"
    try:
        status = load_json(status_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return ["RELEASE_STATUS_INVALID"]
    if status.get("schema") != 1:
        errors.append("RELEASE_STATUS_SCHEMA_INVALID")
    current = status.get("current")
    if not isinstance(current, dict) or current.get("state") != CURRENT_STATE:
        return errors + ["CURRENT_RELEASE_INVALID"]
    tag = current.get("tag")
    commit = current.get("commit")
    if not isinstance(tag, str) or not tag or not HEX40.fullmatch(str(commit)):
        errors.append("CURRENT_IDENTITY_INVALID")
    installer = current.get("installer")
    if (not isinstance(installer, dict)
            or not HEX64.fullmatch(str(installer.get("sha256", "")))
            or not isinstance(installer.get("bytes"), int)
            or installer["bytes"] <= 0
            or not str(installer.get("name", "")).endswith(".pkg")):
        errors.append("CURRENT_INSTALLER_INVALID")
        installer = {}
    deprecated = status.get("deprecated")
    if not isinstance(deprecated, list) or not deprecated:
        errors.append("DEPRECATED_RELEASES_MISSING")
        deprecated = []
    deprecated_tags: set[str] = set()
    for item in deprecated:
        if (not isinstance(item, dict)
                or item.get("state") != DEPRECATED_STATE
                or not isinstance(item.get("tag"), str)
                or not HEX40.fullmatch(str(item.get("commit", "")))):
            errors.append("DEPRECATED_RELEASE_INVALID")
            continue
        if item["tag"] == tag or item["tag"] in deprecated_tags:
            errors.append("RELEASE_STATE_NOT_UNIQUE")
        deprecated_tags.add(item["tag"])
    removed = status.get("removed_from_distribution")
    if not isinstance(removed, list):
        errors.append("REMOVED_ASSET_AUDIT_INVALID")
        removed = []
    for item in removed:
        if (not isinstance(item, dict)
                or item.get("tag") not in deprecated_tags
                or not HEX64.fullmatch(str(item.get("sha256", "")))
                or not isinstance(item.get("bytes"), int)
                or item["bytes"] <= 0
                or not item.get("name") or not item.get("reason")):
            errors.append("REMOVED_ASSET_RECORD_INVALID")
    evidence = root / "release-evidence" / str(tag)
    for relative in sorted(REQUIRED_EVIDENCE):
        path = evidence / relative
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            errors.append("EVIDENCE_MISSING:" + relative)
    try:
        sums = sha256sums(evidence / "SHA256SUMS")
        if sums.get(str(installer.get("name"))) != installer.get("sha256"):
            errors.append("CURRENT_CHECKSUM_MISMATCH")
        manifest = load_json(evidence / "build-manifest.json")
        packages = [row for row in manifest.get("files", [])
                    if isinstance(row, dict) and row.get("role") == "installer"]
        if (manifest.get("schema") != 1 or manifest.get("mode") != "distribution"
                or len(packages) != 1
                or packages[0].get("path") != installer.get("name")
                or packages[0].get("sha256") != installer.get("sha256")
                or packages[0].get("size") != installer.get("bytes")):
            errors.append("CURRENT_BUILD_MANIFEST_MISMATCH")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        errors.append("CURRENT_MANIFEST_EVIDENCE_INVALID")
    try:
        audit = (evidence / "RELEASE_AUDIT.txt").read_text(encoding="utf-8")
        if "FINAL_RESULT=PASS" not in audit or "FAILURES: NONE" not in audit:
            errors.append("CURRENT_RELEASE_AUDIT_NOT_PASSING")
        sbom = load_json(evidence / "sbom/cyclonedx.json")
        if (sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5"
                or not isinstance(sbom.get("components"), list)
                or not sbom["components"]):
            errors.append("CURRENT_SBOM_INVALID")
        public = load_json(evidence / "public-release-audit.json")
        releases = public.get("releases")
        states = {row.get("tag") for row in releases if isinstance(row, dict)} \
            if isinstance(releases, list) else set()
        if public.get("authoritative_release") != tag or tag not in states \
                or not deprecated_tags.issubset(states):
            errors.append("PUBLIC_RELEASE_AUDIT_INCOMPLETE")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        errors.append("CURRENT_EVIDENCE_INVALID")
    for relative in ("README.md", "INSTALL.md", "docs/RELEASE_POLICY.md",
                     "docs/RELEASE_CLEANUP_REPORT.md"):
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append("RELEASE_DOCUMENT_MISSING:" + relative)
            continue
        if tag not in text and relative in {"README.md", "INSTALL.md",
                                            "docs/RELEASE_CLEANUP_REPORT.md"}:
            errors.append("CURRENT_RELEASE_NOT_DOCUMENTED:" + relative)
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = verify(args.root.resolve())
    if errors:
        for error in errors:
            print("RELEASE_POLICY=FAIL code=" + error)
        return 2
    status = load_json(args.root.resolve() / "manifests/release-status.json")
    print("RELEASE_POLICY=PASS current=" + status["current"]["tag"]
          + " deprecated=" + str(len(status["deprecated"]))
          + " removed_assets=" + str(len(status["removed_from_distribution"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
