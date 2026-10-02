#!/usr/bin/env python3
"""Deterministic inventory and fail-closed validation for an offline 0-Sky kit."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

try:
    from .wheel_inventory import verify as verify_wheel_inventory
except ImportError:
    from wheel_inventory import verify as verify_wheel_inventory


MANIFEST_NAME = "RELEASE_KIT_MANIFEST.json"
HASH_NAME = "SHA256SUMS"
APPROVAL_NAME = "RELEASE_KIT_APPROVAL.json"
APPROVAL_STATES = ("KIT_BUILT", "KIT_STRUCTURALLY_VALID", "KIT_PII_CLEAN",
                   "KIT_PORTABLE", "KIT_DEPENDENCIES_VERIFIED", "KIT_HASH_VERIFIED",
                   "KIT_EMBED_APPROVED")
REQUIRED = {
    "python": [
        "host-mac/requirements.txt",
        "host-mac/requirements-lock.txt",
        "host-mac/frida-requirements-lock.txt",
        "host-mac/frida-wheelhouse.sha256",
    ],
    "scripts": [
        "host-mac/install.py", "host-mac/pair.py", "host-mac/uninstall.py",
        "host-mac/apple_device_transport.py",
        "automation/CrypStoreAutomation/crypstore_worker.py",
        "automation/CrypStoreAutomation/device_bridge_supervisor",
    ],
    "zero_sky_link": ["payloads/0-Sky-Link-1.9.0-universal.ipa"],
    "metadata": ["PORTABILITY.json", "WHEEL_INVENTORY.json", APPROVAL_NAME, HASH_NAME],
}
IGNORED = {MANIFEST_NAME, HASH_NAME}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def inventory(root: Path) -> list[dict[str, object]]:
    root = root.resolve(strict=True)
    entries: list[dict[str, object]] = []
    for item in sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix()):
        relative = item.relative_to(root).as_posix()
        if relative in IGNORED or item.is_dir() and not item.is_symlink():
            continue
        if not item.is_file():
            raise ValueError("unsupported kit entry")
        resolved = item.resolve(strict=True)
        if root not in resolved.parents:
            raise ValueError("kit symlink escapes its root")
        link = os.readlink(item) if item.is_symlink() else None
        if link is not None and (Path(link).is_absolute() or ".." in Path(link).parts):
            raise ValueError("kit contains an unsafe symlink")
        observed = item.lstat()
        if link is None and observed.st_mode & (stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID):
            raise ValueError("kit file has unsafe mode")
        entry: dict[str, object] = {
            "relative_path": relative,
            "size": item.stat().st_size,
            "sha256": digest(item),
            "mode": f"{stat.S_IMODE(observed.st_mode):04o}",
            "file_type": "symlink" if link is not None else "file",
        }
        if link is not None:
            entry["link_target"] = link
        entries.append(entry)
    return entries


def required_issues(root: Path) -> list[str]:
    issues: list[str] = []
    for group, paths in REQUIRED.items():
        for relative in paths:
            item = root / relative
            if not item.is_file() or item.stat().st_size == 0:
                issues.append(f"MISSING_OR_EMPTY:{group}:{relative}")
    wheelhouse = root / "host-mac/wheelhouse"
    if not wheelhouse.is_dir() or not list(wheelhouse.glob("*.whl")):
        issues.append("OFFLINE_WHEELHOUSE_MISSING")
    for relative in ("host-mac/zero-sky-bluetooth-tunnel",
                     "automation/CrypStoreAutomation/device_bridge_supervisor"):
        item = root / relative
        if not item.is_file() or not item.stat().st_mode & 0o111:
            issues.append(f"EXECUTABLE_MODE_MISSING:{relative}")
    return issues


def script_issues(root: Path) -> list[str]:
    issues: list[str] = []
    for relative in REQUIRED["scripts"]:
        if not relative.endswith(".py"):
            continue
        try:
            ast.parse((root / relative).read_text(encoding="utf-8"), filename=relative)
        except (OSError, UnicodeError, SyntaxError):
            issues.append(f"MALFORMED_SCRIPT:{relative}")
    for relative in ("automation/CrypStoreAutomation/device_bridge_supervisor.sh",
                     "runtime-generation/build_and_install.sh"):
        path = root / relative
        if not path.is_file():
            issues.append(f"MISSING_SCRIPT:{relative}")
            continue
        try:
            result = subprocess.run(["/bin/bash", "-n", str(path)],
                                    capture_output=True, timeout=15, check=False)
            valid = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            valid = False
        if not valid:
            issues.append(f"MALFORMED_SCRIPT:{relative}")
    return issues


def generate(root: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    entries = inventory(root)
    if issues := [issue for issue in required_issues(root) if not issue.endswith(HASH_NAME)]:
        raise ValueError("required kit components are missing: " + ",".join(issues))
    if script_issues(root):
        raise ValueError("required kit script is malformed")
    content_id = hashlib.sha256(json.dumps(entries, sort_keys=True,
                                           separators=(",", ":")).encode("utf-8")).hexdigest()[:16]
    data: dict[str, object] = {
        "schema_version": 1,
        "kit_version": content_id,
        "required": REQUIRED,
        "files": entries,
    }
    manifest = root / MANIFEST_NAME
    manifest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows = [f"{item['sha256']}  ./{item['relative_path']}" for item in entries]
    rows.append(f"{digest(manifest)}  ./{MANIFEST_NAME}")
    (root / HASH_NAME).write_text("\n".join(rows) + "\n", encoding="utf-8")
    return data


def verify(root: Path) -> list[str]:
    root = root.resolve(strict=True)
    issues = required_issues(root)
    issues.extend(script_issues(root))
    manifest = root / MANIFEST_NAME
    hashes = root / HASH_NAME
    if not manifest.is_file() or manifest.is_symlink() or not hashes.is_file() or hashes.is_symlink():
        return issues + ["KIT_MANIFEST_MISSING"]
    if not verify_wheel_inventory(root):
        issues.append("WHEEL_INVENTORY_MISMATCH")
    try:
        approval = json.loads((root / APPROVAL_NAME).read_text(encoding="utf-8"))
        if approval != {"schema_version": 1, "states": list(APPROVAL_STATES)}:
            issues.append("KIT_APPROVAL_INVALID")
        data = json.loads(manifest.read_text(encoding="utf-8"))
        entries = inventory(root)
        expected_id = hashlib.sha256(json.dumps(entries, sort_keys=True,
                                                separators=(",", ":")).encode("utf-8")).hexdigest()[:16]
        if (data.get("schema_version") != 1 or data.get("required") != REQUIRED
                or not isinstance(data.get("files"), list)):
            return issues + ["KIT_MANIFEST_SCHEMA_INVALID"]
        if data["files"] != entries:
            issues.append("KIT_FILE_INVENTORY_MISMATCH")
        if data.get("kit_version") != expected_id:
            issues.append("KIT_CONTENT_ID_MISMATCH")
        rows = [f"{item['sha256']}  ./{item['relative_path']}" for item in entries]
        rows.append(f"{digest(manifest)}  ./{MANIFEST_NAME}")
        if hashes.read_text(encoding="utf-8") != "\n".join(rows) + "\n":
            issues.append("KIT_HASH_MANIFEST_MISMATCH")
        if any(not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
               for item in data["files"] if isinstance(item, dict)):
            issues.append("KIT_MANIFEST_SCHEMA_INVALID")
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        issues.append("KIT_MANIFEST_INVALID")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("generate", "verify"))
    parser.add_argument("kit", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "generate":
            generate(args.kit)
        issues = verify(args.kit)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"KIT_MANIFEST=FAIL reason={type(error).__name__}", file=sys.stderr)
        return 2
    if issues:
        print("KIT_MANIFEST=FAIL reasons=" + ",".join(issues), file=sys.stderr)
        return 2
    print("KIT_MANIFEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
