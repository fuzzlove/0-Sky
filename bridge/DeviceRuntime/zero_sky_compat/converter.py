"""Plan and apply only reviewed deterministic compatibility conversions."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import stat
import zipfile

from .archive_adapter import normalize_zip_compression
from .deb_adapter import canonicalize_locked_plist
from .intake import safe_name


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_locks(directory: Path) -> list[dict]:
    locks = []
    if directory.is_dir():
        for path in sorted(directory.glob("*.json")):
            value = json.loads(path.read_text())
            value["lock_file"] = path.name
            locks.append(value)
    return locks


def plan(source: Path, locks: list[dict]) -> dict:
    source = Path(source)
    digest = sha256(source)
    issues = []
    transformations = []
    if zipfile.is_zipfile(source):
        try:
            with zipfile.ZipFile(source) as archive:
                entries = archive.infolist()
                if len(entries) > 100_000 or sum(item.file_size for item in entries) > 4 * 1024 ** 3:
                    raise ValueError("archive expansion limit exceeded")
                names = set()
                for item in entries:
                    relative = safe_name(item.filename)
                    if relative.as_posix() in names:
                        raise ValueError("duplicate archive entry")
                    names.add(relative.as_posix())
                    if stat.S_ISLNK(item.external_attr >> 16):
                        raw = archive.read(item)
                        if len(raw) > 4096 or b"\0" in raw:
                            raise ValueError("invalid ZIP symlink target")
                        link = raw.decode("utf-8", "strict")
                        if PurePosixPath(link).is_absolute():
                            raise ValueError("external ZIP symlink requires adapter")
                        safe_name(os.path.normpath(str(relative.parent / link)))
                methods = sorted(set(item.compress_type for item in entries))
                members = len(entries)
        except (OSError, UnicodeError, ValueError, zipfile.BadZipFile) as error:
            return {"source": source.name, "sha256": digest, "format": "zip",
                    "issues": [{"code": "UNSAFE_OR_CORRUPT_ARCHIVE",
                                "detail": type(error).__name__}], "transformations": [],
                    "compatibility": "UNSAFE_PACKAGE", "confidence": "HIGH",
                    "device_changes": "NONE"}
        unsupported = [method for method in methods if method not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)]
        if unsupported:
            issues.append({"code": "INSTALLER_ZIP_COMPRESSION_UNSUPPORTED", "methods": unsupported})
            transformations.append({"rule": "zip-compression-normalization-v1",
                                    "action": "repackage members with Deflate"})
        return {"source": source.name, "sha256": digest, "format": "zip",
                "members": members, "issues": issues, "transformations": transformations,
                "compatibility": "LIKELY_CONVERTIBLE" if transformations else "UNKNOWN",
                "confidence": "HIGH" if transformations else "MANUAL",
                "device_changes": "NONE"}
    if source.suffix.lower() == ".deb":
        matches = [lock for lock in locks if lock.get("expected_original_sha256") == digest]
        if len(matches) == 1:
            lock = matches[0]
            issues.append({"code": "LEGACY_PLIST_SERIALIZATION", "path": lock["plist_path"]})
            transformations.append({"rule": lock["rule"], "lock": lock["lock_file"],
                                    "action": "canonicalize locked plist and update derivative version"})
        return {"source": source.name, "sha256": digest, "format": "deb",
                "issues": issues, "transformations": transformations,
                "compatibility": "LIKELY_CONVERTIBLE" if transformations else "UNKNOWN",
                "confidence": "HIGH" if transformations else "MANUAL",
                "device_changes": "NONE"}
    return {"source": source.name, "sha256": digest, "format": source.suffix.lower().lstrip("."),
            "issues": [{"code": "NO_DETERMINISTIC_RULE_MATCH"}], "transformations": [],
            "compatibility": "UNKNOWN", "confidence": "MANUAL", "device_changes": "NONE"}


def convert(source: Path, destination: Path, locks: list[dict]) -> dict:
    value = plan(source, locks)
    if len(value["transformations"]) != 1:
        raise ValueError("artifact does not match exactly one deterministic conversion rule")
    transformation = value["transformations"][0]
    if transformation["rule"] == "zip-compression-normalization-v1":
        result = normalize_zip_compression(source, destination)
    elif transformation["rule"] == "legacy-plist-canonicalization-v1":
        lock = next(item for item in locks if item["lock_file"] == transformation["lock"])
        result = canonicalize_locked_plist(
            source, destination, package=lock["package"],
            from_version=lock["from_version"], to_version=lock["to_version"],
            plist_path=lock["plist_path"], source_date_epoch=lock["source_date_epoch"])
        if result["converted_sha256"] != lock["expected_converted_sha256"]:
            destination.unlink(missing_ok=True)
            raise RuntimeError("converted artifact does not match conversion lock")
    else:
        raise ValueError("unimplemented deterministic rule")
    return {"schema_version": 1, "plan": value, "result": result,
            "runtime_validation": "NOT_RUN", "compatibility_status": "UNTESTED"}
