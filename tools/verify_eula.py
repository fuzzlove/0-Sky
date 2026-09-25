#!/usr/bin/env python3
"""Verify canonical and bundled EULA bytes, version, date, and SHA-256."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
LEGAL = ROOT / "bridge/0SkyBridge/Resources/Legal"


class EULAError(ValueError):
    pass


def verify(directory: Path) -> dict[str, str]:
    text_path = directory / "EULA.md"
    metadata_path = directory / "EULA.json"
    if text_path.is_symlink() or metadata_path.is_symlink():
        raise EULAError("legal resources must be regular files")
    try:
        contents = text_path.read_bytes()
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EULAError("legal resources are missing or unreadable") from error
    if not isinstance(metadata, dict) or metadata.get("schema") != 1:
        raise EULAError("unsupported EULA metadata schema")
    version = metadata.get("eula_version")
    date = metadata.get("effective_date")
    digest = metadata.get("sha256")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", version):
        raise EULAError("invalid EULA version")
    if not isinstance(date, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", date):
        raise EULAError("invalid EULA effective date")
    try:
        effective = dt.date.fromisoformat(date)
        text = contents.decode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise EULAError("EULA text or date is invalid") from error
    if not isinstance(digest, str) or hashlib.sha256(contents).hexdigest() != digest:
        raise EULAError("EULA digest does not match the legal text")
    legacy = metadata.get("legacy_acceptance")
    if legacy is not None and (not isinstance(legacy, dict)
            or not isinstance(legacy.get("eula_version"), str)
            or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", legacy["eula_version"])
            or not isinstance(legacy.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", legacy["sha256"])):
        raise EULAError("invalid legacy acceptance binding")
    if f"**Version:** {version}" not in text or (
            f"**Effective Date:** {effective.strftime('%B')} {effective.day}, {effective.year}") not in text:
        raise EULAError("EULA metadata does not match the document header")
    if not text.startswith("# 0-Sky End User License Agreement"):
        raise EULAError("EULA title is missing")
    return {"eula_version": version, "effective_date": date, "sha256": digest}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=LEGAL)
    parser.add_argument("--bundle", type=Path, help="Mac app bundle to compare with canonical bytes")
    args = parser.parse_args()
    try:
        source = verify(args.source)
        if args.bundle:
            bundled = args.bundle / "Contents/Resources/Legal"
            if source != verify(bundled) or any(
                (args.source / name).read_bytes() != (bundled / name).read_bytes()
                for name in ("EULA.md", "EULA.json")
            ):
                raise EULAError("bundled EULA differs from canonical source")
    except EULAError as error:
        print(f"EULA_VERIFY=FAIL: {error}")
        return 2
    print("EULA_VERIFY=PASS " + json.dumps(source, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
