#!/usr/bin/env python3
"""Verify GitHub release presentation and downloadable-asset hygiene."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
CURRENT_PREFIX = "[CURRENT / VERIFIED / SUPPORTED]"
DEPRECATED_PREFIX = "[DEPRECATED / UNSUPPORTED]"
DEPRECATED_WARNING = "⚠️ DEPRECATED RELEASE"
BLOCKED_SUFFIXES = (".pkg", ".dmg", ".zip", ".ipa", ".deb", ".tar",
                    ".tar.gz", ".tgz", ".7z", ".rar")
CURRENT_ASSETS = {
    "0-Sky-Bridge-1.0.0-distribution-universal.pkg",
    "RELEASE_AUDIT.txt", "RELEASE_MANIFEST.json", "SHA256SUMS",
}


def read_releases(path: Path | None, repository: str) -> list[dict]:
    if path:
        value = json.loads(path.read_text(encoding="utf-8"))
    else:
        result = subprocess.run(
            ["gh", "api", "--paginate", f"repos/{repository}/releases"],
            capture_output=True, check=False, timeout=60)
        if result.returncode:
            raise RuntimeError("GitHub release metadata is unavailable")
        value = json.loads(result.stdout)
    if not isinstance(value, list):
        raise ValueError("GitHub release metadata must be one array")
    return value


def verify(releases: list[dict], status: dict) -> list[str]:
    errors: list[str] = []
    current = status["current"]
    deprecated = {row["tag"] for row in status["deprecated"]}
    by_tag = {row.get("tag_name"): row for row in releases
              if isinstance(row, dict) and isinstance(row.get("tag_name"), str)}
    expected = deprecated | {current["tag"]}
    if set(by_tag) != expected:
        errors.append("RELEASE_SET_MISMATCH")
    row = by_tag.get(current["tag"])
    if row is None:
        errors.append("CURRENT_RELEASE_MISSING")
    else:
        if not str(row.get("name", "")).startswith(CURRENT_PREFIX):
            errors.append("CURRENT_TITLE_INVALID")
        if not str(row.get("body", "")).lstrip().startswith(CURRENT_PREFIX):
            errors.append("CURRENT_BODY_INVALID")
        if row.get("draft") is not False or row.get("prerelease") is not True:
            errors.append("CURRENT_RELEASE_FLAGS_INVALID")
        names = {a.get("name") for a in row.get("assets", []) if isinstance(a, dict)}
        if names != CURRENT_ASSETS:
            errors.append("CURRENT_ASSET_SET_INVALID")
        assets = {a.get("name"): a for a in row.get("assets", []) if isinstance(a, dict)}
        installer = assets.get(current["installer"]["name"])
        if not installer or installer.get("size") != current["installer"]["bytes"]:
            errors.append("CURRENT_INSTALLER_SIZE_MISMATCH")
    for tag in sorted(deprecated):
        row = by_tag.get(tag)
        if row is None:
            errors.append("DEPRECATED_RELEASE_MISSING:" + tag)
            continue
        if not str(row.get("name", "")).startswith(DEPRECATED_PREFIX):
            errors.append("DEPRECATED_TITLE_INVALID:" + tag)
        if not str(row.get("body", "")).lstrip().startswith(DEPRECATED_WARNING):
            errors.append("DEPRECATED_BODY_INVALID:" + tag)
        if row.get("draft") is not False or row.get("prerelease") is not True:
            errors.append("DEPRECATED_RELEASE_FLAGS_INVALID:" + tag)
        for asset in row.get("assets", []):
            name = str(asset.get("name", "")).lower() if isinstance(asset, dict) else ""
            if name.endswith(BLOCKED_SUFFIXES):
                errors.append("DEPRECATED_BINARY_ASSET:" + tag + ":" + name)
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default="fuzzlove/0-Sky")
    parser.add_argument("--releases-json", type=Path)
    parser.add_argument("--status", type=Path,
                        default=ROOT / "manifests/release-status.json")
    args = parser.parse_args()
    try:
        status = json.loads(args.status.read_text(encoding="utf-8"))
        releases = read_releases(args.releases_json, args.repository)
        errors = verify(releases, status)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError,
            subprocess.TimeoutExpired):
        errors = ["RELEASE_METADATA_UNAVAILABLE_OR_INVALID"]
    if errors:
        for error in errors:
            print("GITHUB_RELEASE_HYGIENE=FAIL code=" + error)
        return 2
    print(f"GITHUB_RELEASE_HYGIENE=PASS current={status['current']['tag']} "
          f"deprecated={len(status['deprecated'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
