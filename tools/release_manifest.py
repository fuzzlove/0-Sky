#!/usr/bin/env python3
"""Create and verify the minimal, checksummed 0-Sky release file set."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile


SCHEMA = 1
AUDIT_NAME = "RELEASE_AUDIT.txt"
MANIFEST_NAME = "RELEASE_MANIFEST.json"
CHECKSUM_NAME = "SHA256SUMS"
PACKAGE_RE = re.compile(
    r"0-Sky-Bridge-[0-9]+(?:\.[0-9]+){1,3}-(?:development|release-candidate|distribution)-universal\.pkg"
)
MODES = {"development", "release-candidate", "distribution"}


class ManifestError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_file(root: Path, name: str) -> Path:
    if Path(name).name != name or name in {".", ".."}:
        raise ManifestError("release manifest contains an unsafe path")
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ManifestError(f"release file is missing or unsafe: {name}")
    return path


def _atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise ManifestError(f"refusing to replace symbolic link: {path.name}")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _verify_audit_report(path: Path, *, product: str, version: str,
                         build: str, mode: str) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ManifestError("release audit report is unreadable") from error
    expected_result = "PASS" if mode == "distribution" else "BLOCKED"
    required = {
        f"Product: {product}", f"Version: {version}", f"Build: {build}",
        f"Build mode: {mode}", f"FINAL_RESULT={expected_result}",
    }
    lines = set(text.splitlines())
    if not required.issubset(lines):
        raise ManifestError("release audit report does not match the artifact identity")


def generate(directory: Path, package_name: str, *, product: str,
             version: str, build: str, mode: str) -> dict[str, object]:
    root = directory.resolve(strict=True)
    if directory.is_symlink() or not PACKAGE_RE.fullmatch(package_name):
        raise ManifestError("release directory or package name is unsafe")
    if mode not in MODES or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
        raise ManifestError("release version or mode is invalid")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", build):
        raise ManifestError("release build identifier is invalid")
    expected_before = {package_name, AUDIT_NAME}
    actual_before = {item.name for item in root.iterdir()}
    if actual_before != expected_before:
        raise ManifestError("release staging directory contains unexpected files")
    _verify_audit_report(_regular_file(root, AUDIT_NAME), product=product,
                         version=version, build=build, mode=mode)
    files = []
    for name, role in ((package_name, "installer"), (AUDIT_NAME, "audit-report")):
        path = _regular_file(root, name)
        files.append({"path": name, "role": role, "sha256": sha256(path),
                      "size": path.stat().st_size})
    manifest = {"schema": SCHEMA, "product": product, "version": version,
                "build": build, "mode": mode, "files": files}
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    _atomic_write(root / MANIFEST_NAME, encoded)
    checksum_names = [package_name, AUDIT_NAME, MANIFEST_NAME]
    checksums = "".join(f"{sha256(_regular_file(root, name))}  {name}\n"
                        for name in checksum_names).encode()
    _atomic_write(root / CHECKSUM_NAME, checksums)
    verify(root)
    return manifest


def verify(directory: Path) -> dict[str, object]:
    root = directory.resolve(strict=True)
    if directory.is_symlink():
        raise ManifestError("release directory is a symbolic link")
    manifest_path = _regular_file(root, MANIFEST_NAME)
    checksum_path = _regular_file(root, CHECKSUM_NAME)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ManifestError("release manifest is invalid JSON") from error
    version, build, mode = (manifest.get("version"), manifest.get("build"),
                            manifest.get("mode")) if isinstance(manifest, dict) else (None, None, None)
    if (not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA
            or mode not in MODES
            or not isinstance(version, str)
            or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version)
            or not isinstance(build, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", build)
            or not isinstance(manifest.get("product"), str)
            or not manifest["product"].strip()
            or not isinstance(manifest.get("files"), list)):
        raise ManifestError("release manifest schema is invalid")
    rows = manifest["files"]
    if len(rows) != 2 or {row.get("role") for row in rows if isinstance(row, dict)} != {
            "installer", "audit-report"}:
        raise ManifestError("release manifest file roles are incomplete")
    recorded: dict[str, str] = {}
    package_names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ManifestError("release manifest file entry is invalid")
        name, digest, size = row.get("path"), row.get("sha256"), row.get("size")
        if (not isinstance(name, str) or not isinstance(digest, str)
                or not re.fullmatch(r"[a-f0-9]{64}", digest)
                or not isinstance(size, int) or size < 0 or name in recorded):
            raise ManifestError("release manifest file entry is invalid")
        path = _regular_file(root, name)
        if path.stat().st_size != size or sha256(path) != digest:
            raise ManifestError(f"release file checksum mismatch: {name}")
        recorded[name] = digest
        if row["role"] == "installer":
            package_names.append(name)
    expected_package = f"0-Sky-Bridge-{version}-{mode}-universal.pkg"
    if package_names != [expected_package]:
        raise ManifestError("release package name is invalid")
    if AUDIT_NAME not in recorded:
        raise ManifestError("release audit report is missing")
    _verify_audit_report(_regular_file(root, AUDIT_NAME),
                         product=manifest["product"], version=version,
                         build=build, mode=mode)
    checksum_rows: dict[str, str] = {}
    for raw in checksum_path.read_text(encoding="utf-8").splitlines():
        parts = raw.split("  ", 1)
        if (len(parts) != 2 or not re.fullmatch(r"[a-f0-9]{64}", parts[0])
                or Path(parts[1]).name != parts[1] or parts[1] in checksum_rows):
            raise ManifestError("SHA256SUMS contains an invalid entry")
        checksum_rows[parts[1]] = parts[0]
    expected_checksums = {**recorded, MANIFEST_NAME: sha256(manifest_path)}
    if checksum_rows != expected_checksums:
        raise ManifestError("SHA256SUMS does not match the release allowlist")
    expected_names = set(expected_checksums) | {CHECKSUM_NAME}
    if {item.name for item in root.iterdir()} != expected_names:
        raise ManifestError("release directory contains files outside the allowlist")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("generate")
    create.add_argument("directory", type=Path)
    create.add_argument("--package", required=True)
    create.add_argument("--product", default="0-Sky Bridge")
    create.add_argument("--version", required=True)
    create.add_argument("--build", required=True)
    create.add_argument("--mode", choices=sorted(MODES), required=True)
    check = subparsers.add_parser("verify")
    check.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "generate":
            generate(args.directory, args.package, product=args.product,
                     version=args.version, build=args.build, mode=args.mode)
        else:
            verify(args.directory)
        print("RELEASE_MANIFEST=PASS")
        return 0
    except (ManifestError, OSError, ValueError) as error:
        print(f"RELEASE_MANIFEST=FAIL reason={error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
