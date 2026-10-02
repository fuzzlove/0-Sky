#!/usr/bin/env python3
"""Write a private, machine-readable inventory of kit privacy failures."""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import tempfile
import zipfile

try:
    from .release_sanitize import PATTERNS, audit
except ImportError:
    from release_sanitize import PATTERNS, audit


SECRET_CATEGORIES = {"private-key", "embedded-password", "ssh-public-key-comment"}
REBUILD_CATEGORIES = {"fixed-home-path", "mounted-volume-path", "derived-data-path",
                      "temporary-build-path", "absolute-file-uri"}


def extract_value(root: Path, label: str, category: str) -> tuple[str, str]:
    if category in SECRET_CATEGORIES or category.startswith("project-"):
        return "redacted", "<redacted-sensitive-value>"
    pattern = PATTERNS.get(category)
    if pattern is None:
        return "not-applicable", "<not-disclosed>"
    pieces = label.split("!/")
    path = root / pieces[0]
    try:
        if len(pieces) == 1:
            with path.open("rb") as stream:
                tail = b""
                offset = 0
                while block := stream.read(1024 * 1024):
                    data = tail + block
                    match = pattern.search(data)
                    if match:
                        return f"byte:{offset-len(tail)+match.start()}", match.group().decode(
                            "utf-8", "replace")
                    offset += len(block)
                    tail = data[-8192:]
        else:
            data: bytes | None = None
            for member in pieces[1:]:
                with zipfile.ZipFile(path if data is None else io.BytesIO(data)) as archive:
                    info = archive.getinfo(member)
                    if info.file_size > 128 * 1024 * 1024:
                        return "archive-member", "<redacted-large-member>"
                    data = archive.read(info)
            if data is not None and (match := pattern.search(data)):
                return f"byte:{match.start()}", match.group().decode("utf-8", "replace")
    except (OSError, KeyError, RuntimeError, ValueError, zipfile.BadZipFile):
        pass
    return "binary-or-archive", "<redacted-unresolved-member>"


def create_report(root: Path, output: Path) -> int:
    root = root.resolve(strict=True)
    findings = audit([root])
    rows = []
    for finding in findings:
        category = finding["category"]
        location, value = extract_value(root, finding["file"], category)
        action = ("REBUILD_FROM_CANONICAL_SOURCE" if category in REBUILD_CATEGORIES
                  else "REMOVE_SECRET_OR_TEST_FIXTURE" if category in SECRET_CATEGORIES
                  else "REVIEW_AND_REBUILD_OR_REPLACE_VERIFIED_INPUT")
        rows.append({"FILE": finding["file"], "LINE_OR_KEY": location,
                     "CATEGORY": category, "ORIGINAL_VALUE": value,
                     "REQUIRED_ACTION": action})
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".pii-report-", dir=output.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"schema_version": 1, "findings": rows}, stream, indent=2,
                      sort_keys=True)
            stream.write("\n")
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kit", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    count = create_report(args.kit, args.report)
    print(f"KIT_PII_REPORT=CREATED findings={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
