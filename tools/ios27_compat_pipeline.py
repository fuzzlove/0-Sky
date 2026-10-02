#!/usr/bin/env python3
"""Deterministic, read-only intake and fail-closed admission for iOS 27 artifacts.

Device installation stays with zero_sky_compat.Engine and its transactional
backend. This scanner never executes package scripts or downloaded build logic.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))
from zero_sky_compat import macho  # noqa: E402
from zero_sky_core.research_toolkit import load_catalog  # noqa: E402
from compat.ios27.admission import load_reviewed_receipts  # noqa: E402
from compat.ios27.candidates import load_candidate_pins  # noqa: E402

# Staged release artifacts are inputs to admission and must be inventoried too.
# Generated JSON reports are not classified as components, so repeated scans
# remain stable when the output directory lives under artifacts/.
SKIP_DIRS = {".git", ".venv", ".theos", ".build", "__pycache__", "node_modules"}
SOURCE_SUFFIXES = {".m", ".mm", ".h", ".c", ".cc", ".cpp", ".swift", ".xm", ".x", ".py", ".sh"}
APP_ARCHIVE_SUFFIXES = (".ipa", ".tipa")
PACKAGE_SUFFIXES = (".deb", ".ipa", ".tipa")
BUNDLE_TYPES = {".app": "APP", ".appex": "APP", ".framework": "FRAMEWORK", ".bundle": "UNKNOWN"}
MACHO_MAGIC = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"}
PATH_PATTERN = re.compile(rb"(?<![A-Za-z0-9_])/(?:Library|Applications|usr|bin|sbin|etc|var|private/var|Users|Volumes)(?:/[A-Za-z0-9._+@%-]+)+")
SECRET_PATTERN = re.compile(rb"(?:-----BEGIN (?:RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY-----|AKIA[0-9A-Z]{16})")
API_PATTERNS = {
    "class": re.compile(rb'(?:NSClassFromString\s*\(\s*@"|objc_getClass\s*\(\s*")([A-Za-z_$][A-Za-z0-9_$]{1,127})"'),
    "selector": re.compile(rb'(?:NSSelectorFromString\s*\(\s*@"|sel_registerName\s*\(\s*")([A-Za-z_$][A-Za-z0-9_$:]{1,127})"'),
}
VALID_RESULTS = {"PASS", "DEGRADED", "BLOCKED", "QUARANTINED"}
COMPATIBILITY_STATES = {
    "UNKNOWN", "ANALYZING", "NATIVE_COMPATIBLE", "ADAPTATION_REQUIRED",
    "ADAPTING", "BUILD_REQUIRED", "TESTING", "COMPATIBLE",
    "COMPATIBLE_WITH_ADAPTER", "PARTIALLY_COMPATIBLE",
    "BLOCKED_BY_DEPENDENCY", "BLOCKED_BY_PLATFORM",
    "BLOCKED_BY_ENTITLEMENT", "BLOCKED_BY_ARCHITECTURE",
    "BROKEN_UPSTREAM", "UNSAFE_TO_ADAPT",
    # Read existing v1 manifests without granting them current evidence.
    "NATIVE_IOS27", "PORT_REQUIRED", "PORT_IN_PROGRESS", "OSKY_PORTED",
    "SHIMMED", "DEGRADED", "BLOCKED_SOURCE_REQUIRED", "BLOCKED_ENTITLEMENT",
    "BLOCKED_DEPENDENCY", "BLOCKED_DUPLICATE", "BLOCKED_BINARY_ONLY",
    "QUARANTINED", "PASS",
}
STATIC_UNSAFE_ISSUES = {"IPA_UNSAFE_PATH", "IPA_EXPANSION_LIMIT", "IPA_UNSUPPORTED_ENTRY",
                        "IPA_ENTRY_LIMIT", "PACKAGE_UNSAFE_PATH", "PACKAGE_SPECIAL_ENTRY",
                        "PACKAGE_CONTROL_UNSAFE_PATH", "PACKAGE_CONTROL_SPECIAL_ENTRY"}
STATIC_BROKEN_ISSUES = {"IPA_INVALID", "IPA_INFO_INVALID",
                        "IPA_INFO_MISSING_OR_OVERSIZE", "IPA_APP_IDENTITY_INVALID",
                        "IPA_APP_IDENTITY_AMBIGUOUS", "IPA_EXECUTABLE_MISSING",
                        "IPA_EXECUTABLE_OVERSIZE", "IPA_EXECUTABLE_TRUNCATED",
                        "IPA_MACHO_INVALID", "PACKAGE_CONTENTS_INVALID",
                        "PACKAGE_METADATA_INVALID", "PACKAGE_CONTROL_ARCHIVE_INVALID",
                        "PACKAGE_CONTROL_MEMBER_OVERSIZE", "DUPLICATE_PACKAGE_FIELD",
                        "INVALID_DEPENDENCY_EXPRESSION"}
REQUIRED_GATE = ("inventory", "dependency", "architecture", "pii_secrets", "build",
                 "package", "installation", "registration", "runtime", "smoke", "uat", "license_provenance")
HOST_PATH_PATTERN = re.compile(r"/(?:Users|Volumes)/[^/\s\"']+")
DERIVED_DATA_PATTERN = re.compile(r"(?i)(?:/[^\s\"']+)?\bDerivedData[/\\][^\s\"']+")


def sanitize(value):
    """Keep local evidence useful without exporting host account or volume names."""
    if isinstance(value, str):
        return HOST_PATH_PATTERN.sub("/<redacted-host-path>",
                                     DERIVED_DATA_PATTERN.sub("<redacted-build-path>", value))
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, dict):
        return {sanitize(key): sanitize(item) for key, item in value.items()}
    return value


def digest(path: Path, limit: int = 512 * 1024 * 1024) -> str | None:
    if path.stat().st_size > limit:
        return None
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def stable_id(relative: str) -> str:
    stem = re.sub(r"[^a-z0-9]+", "-", Path(relative).name.lower()).strip("-")[:48] or "component"
    return stem + "-" + hashlib.sha256(relative.encode()).hexdigest()[:12]


def classify(path: Path, magic: bytes) -> str | None:
    if path.is_dir():
        if path.suffix == ".bundle" and "PreferenceBundles" in path.parts:
            return "PREFERENCE_BUNDLE"
        return BUNDLE_TYPES.get(path.suffix)
    if magic in MACHO_MAGIC:
        return "MACHO"
    if path.suffix == ".deb":
        return "UNKNOWN"
    if path.suffix in APP_ARCHIVE_SUFFIXES:
        return "APP"
    if path.suffix == ".dylib":
        return "LIBRARY"
    if path.suffix == ".plist":
        if "LaunchDaemons" in path.parts or "LaunchAgents" in path.parts:
            return "DAEMON"
        return "PLIST"
    if path.name in {"Makefile", "control", "preinst", "postinst", "prerm", "postrm"}:
        return "BUILD_OR_PACKAGE_METADATA"
    if path.suffix in SOURCE_SUFFIXES:
        return "SOURCE"
    if path.stat().st_mode & 0o111:
        return "CLI_TOOL"
    return None


def deb_fields(path: Path) -> dict:
    tool = "/opt/homebrew/bin/dpkg-deb" if Path("/opt/homebrew/bin/dpkg-deb").is_file() else "dpkg-deb"
    try:
        result = subprocess.run([tool, "--field", str(path)], capture_output=True,
                                text=True, timeout=20, check=False)
    except UnicodeError:
        return {"error": "PACKAGE_METADATA_INVALID"}
    except (OSError, subprocess.TimeoutExpired):
        return {"error": "PACKAGE_METADATA_UNAVAILABLE"}
    if result.returncode or len(result.stdout) > 65536:
        return {"error": "PACKAGE_METADATA_INVALID"}
    fields: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if line.startswith(" ") and fields:
            fields[next(reversed(fields))] += " " + line.strip()
        elif ":" in line:
            key, value = line.split(":", 1)
            if key in fields:
                return {"error": "DUPLICATE_PACKAGE_FIELD"}
            fields[key] = value.strip()
    return {key: fields.get(key) for key in ("Package", "Version", "Architecture", "Depends", "Pre-Depends", "Conflicts")}


def deb_contents_type(path: Path) -> tuple[str, list[str]]:
    tool = "/opt/homebrew/bin/dpkg-deb" if Path("/opt/homebrew/bin/dpkg-deb").is_file() else "dpkg-deb"
    try:
        result = subprocess.run([tool, "--contents", str(path)], capture_output=True,
                                text=True, timeout=30, check=False)
    except UnicodeError:
        return "UNKNOWN", ["PACKAGE_CONTENTS_INVALID"]
    except (OSError, subprocess.TimeoutExpired):
        return "UNKNOWN", ["PACKAGE_CONTENTS_UNAVAILABLE"]
    if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
        return "UNKNOWN", ["PACKAGE_CONTENTS_INVALID"]
    paths = []
    issues = set()
    seen = set()
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not fields[0] or fields[0][0] not in ("-", "d", "l"):
            issues.add("PACKAGE_CONTENTS_INVALID")
            continue
        if " -> " in fields[5] and fields[0][0] != "l":
            issues.add("PACKAGE_CONTENTS_INVALID")
            continue
        if fields[0][0] == "l":
            issues.add("PACKAGE_SYMLINK_REQUIRES_REVIEW")
        raw = fields[5].split(" -> ", 1)[0]
        name = raw[2:] if raw.startswith("./") else raw
        normalized = name.rstrip("/")
        if normalized in ("", "."):
            continue
        parts = PurePosixPath(normalized)
        if (parts.is_absolute() or any(part in ("", ".", "..") for part in normalized.split("/")) or
                "\\" in normalized or
                "\x00" in normalized or normalized.casefold() in seen):
            issues.add("PACKAGE_UNSAFE_PATH")
            continue
        seen.add(normalized.casefold())
        if fields[0][0] == "l":
            continue
        paths.append(normalized)
    if issues:
        return "UNKNOWN", sorted(issues)
    kinds = set()
    for item in paths:
        if ".app/" in item:
            kinds.add("APP")
        if "/Library/MobileSubstrate/DynamicLibraries/" in item and item.endswith(".dylib"):
            kinds.add("TWEAK")
        if "/Library/PreferenceBundles/" in item:
            kinds.add("PREFERENCE_BUNDLE")
        if "/Library/LaunchDaemons/" in item:
            kinds.add("DAEMON")
        if "/usr/lib/" in item and item.endswith(".dylib"):
            kinds.add("LIBRARY")
        if "/usr/bin/" in item or "/usr/sbin/" in item:
            kinds.add("CLI_TOOL")
    if len(kinds) == 1:
        return next(iter(kinds)), []
    return "UNKNOWN", ["PACKAGE_CONTENTS_AMBIGUOUS" if kinds else "PACKAGE_CONTENTS_UNCLASSIFIED"]


def deb_control_members(path: Path, run=subprocess.run) -> tuple[list[dict], list[str]]:
    """Inspect control archive metadata without extracting or executing scripts."""
    tool = "/opt/homebrew/bin/dpkg-deb" if Path("/opt/homebrew/bin/dpkg-deb").is_file() else "dpkg-deb"
    scripts = {"preinst", "postinst", "prerm", "postrm", "config"}
    entries, issues, seen = [], set(), set()
    try:
        with tempfile.TemporaryFile() as output:
            result = run([tool, "--ctrl-tarfile", str(path)], stdout=output,
                         stderr=subprocess.DEVNULL, timeout=30, check=False)
            if result.returncode or output.tell() > 8 * 1024 * 1024:
                return [], ["PACKAGE_CONTROL_ARCHIVE_INVALID"]
            output.seek(0)
            with tarfile.open(fileobj=output, mode="r:*") as archive:
                members = archive.getmembers()
                if len(members) > 512:
                    return [], ["PACKAGE_CONTROL_ARCHIVE_INVALID"]
                for member in members:
                    raw = member.name.removeprefix("./")
                    name = raw.rstrip("/")
                    if name in ("", "."):
                        continue
                    parts = PurePosixPath(name)
                    if (parts.is_absolute() or any(part in ("", ".", "..") for part in name.split("/"))
                            or "\\" in name or "\x00" in name or name.casefold() in seen):
                        issues.add("PACKAGE_CONTROL_UNSAFE_PATH")
                        continue
                    seen.add(name.casefold())
                    if not (member.isfile() or member.isdir()):
                        issues.add("PACKAGE_CONTROL_SPECIAL_ENTRY")
                        continue
                    if member.isdir():
                        continue
                    if member.size > 1024 * 1024:
                        issues.add("PACKAGE_CONTROL_MEMBER_OVERSIZE")
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        issues.add("PACKAGE_CONTROL_ARCHIVE_INVALID")
                        continue
                    data = stream.read(1024 * 1024 + 1)
                    if len(data) != member.size:
                        issues.add("PACKAGE_CONTROL_ARCHIVE_INVALID")
                        continue
                    entry = {"name": name, "sha256": hashlib.sha256(data).hexdigest(),
                             "size": len(data), "maintainer_script": name in scripts}
                    if name in scripts:
                        entry["absolute_paths"] = sorted({match.group().decode("utf-8", "replace")
                            for match in PATH_PATTERN.finditer(data)})[:64]
                        entry["command_references"] = sorted({match.group().decode("ascii").lower()
                            for match in re.finditer(rb"\b(?:uicache|launchctl|dpkg|apt-get|curl|wget)\b",
                                                     data, re.IGNORECASE)})
                        issues.add("MAINTAINER_SCRIPT_REQUIRES_REVIEW")
                    entries.append(entry)
    except (OSError, ValueError, EOFError, OverflowError, tarfile.TarError,
            subprocess.TimeoutExpired):
        return [], ["PACKAGE_CONTROL_ARCHIVE_INVALID"]
    return entries, sorted(issues)


def ipa_metadata(path: Path) -> tuple[dict, list[str]]:
    """Inspect an IPA's central directory and small Info.plist without extraction."""
    metadata: dict = {}
    issues: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > 100000:
                return metadata, ["IPA_ENTRY_LIMIT"]
            names: set[str] = set()
            app_roots: set[str] = set()
            total_size = 0
            for entry in entries:
                name = entry.filename
                parts = name.split("/")
                if (not name or name.startswith("/") or "\\" in name or
                        any(part in ("", ".", "..") for part in parts[:-1]) or
                        (parts[-1] in ("", ".", "..") and not entry.is_dir()) or
                        (entry.is_dir() and parts[-1] != "") or
                        name.casefold() in names):
                    issues.append("IPA_UNSAFE_PATH")
                    break
                names.add(name.casefold())
                if stat.S_IFMT(entry.external_attr >> 16) == stat.S_IFLNK:
                    issues.append("IPA_SYMLINK_REQUIRES_REVIEW")
                    break
                if entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    issues.append("IPA_UNSUPPORTED_ENTRY")
                    break
                total_size += entry.file_size
                if total_size > 4 * 1024 ** 3 or (entry.file_size > 1024 * 1024 and
                        entry.file_size > max(entry.compress_size, 1) * 1000):
                    issues.append("IPA_EXPANSION_LIMIT")
                    break
                if len(parts) >= 3 and parts[0] == "Payload" and parts[1].endswith(".app"):
                    app_roots.add("/".join(parts[:2]))
            if issues:
                return metadata, issues
            if len(app_roots) != 1:
                return metadata, ["IPA_APP_IDENTITY_AMBIGUOUS"]
            app_root = next(iter(app_roots))
            info_name = app_root + "/Info.plist"
            info = archive.getinfo(info_name) if info_name.casefold() in names else None
            if info is None or info.file_size > 1024 * 1024:
                return metadata, ["IPA_INFO_MISSING_OR_OVERSIZE"]
            value = plistlib.loads(archive.read(info))
            if not isinstance(value, dict):
                return metadata, ["IPA_INFO_INVALID"]
            bundle_id = value.get("CFBundleIdentifier")
            executable = value.get("CFBundleExecutable")
            version = value.get("CFBundleVersion")
            if (not isinstance(bundle_id, str) or
                    not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,199}", bundle_id) or
                    not isinstance(version, str) or not 0 < len(version) <= 128 or
                    not isinstance(executable, str) or not re.fullmatch(r"[A-Za-z0-9._+-]{1,255}", executable)):
                return metadata, ["IPA_APP_IDENTITY_INVALID"]
            if (app_root + "/" + executable).casefold() not in names:
                return metadata, ["IPA_EXECUTABLE_MISSING"]
            executable_info = archive.getinfo(app_root + "/" + executable)
            if executable_info.file_size > 128 * 1024 * 1024:
                return metadata, ["IPA_EXECUTABLE_OVERSIZE"]
            with tempfile.TemporaryDirectory(prefix="0sky-ipa-inspect-") as temporary:
                executable_path = Path(temporary) / "executable"
                with archive.open(executable_info) as source, executable_path.open("wb") as target:
                    remaining = executable_info.file_size
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk:
                            return metadata, ["IPA_EXECUTABLE_TRUNCATED"]
                        target.write(chunk)
                        remaining -= len(chunk)
                try:
                    slices = macho.parse(executable_path)
                except (OSError, ValueError):
                    return metadata, ["IPA_MACHO_INVALID"]
            metadata = {"bundle_id": bundle_id, "version": version,
                        "archive_app_path": app_root, "archive_entries": len(entries),
                        "architectures": sorted({item["architecture"] for item in slices}),
                        "minimum_ios": sorted({item["minimum_os"] for item in slices if item["minimum_os"]}),
                        "linked_libraries": sorted({entry["name"] for item in slices
                                                    for entry in item["dependencies"]}),
                        "signature_present": all(item["signed"] for item in slices)}
            if not set(metadata["architectures"]) & {"arm64", "arm64e"}:
                issues.append("BLOCKED_BINARY_ONLY")
            if any(name.startswith(("/Users/", "/Volumes/")) for name in metadata["linked_libraries"]):
                issues.append("DEVELOPER_PATH_REVIEW")
    except (OSError, ValueError, KeyError, RuntimeError, zipfile.BadZipFile,
            plistlib.InvalidFileException):
        return metadata, ["IPA_INVALID"]
    return metadata, issues


def inspect_item(root: Path, path: Path) -> dict:
    relative = path.relative_to(root).as_posix()
    result = {"id": stable_id(relative), "path": relative, "type": "UNKNOWN",
              "sha256": None, "status": "BLOCKED", "issues": [], "dependencies": []}
    if path.is_symlink():
        result["type"] = BUNDLE_TYPES.get(path.suffix, "UNKNOWN")
        result["issues"].append("SYMLINK_REQUIRES_REVIEW")
        return result
    try:
        with path.open("rb") as stream:
            magic = stream.read(4)
    except IsADirectoryError:
        magic = b""
    kind = classify(path, magic)
    if kind is None:
        return {}
    result["type"] = kind
    if path.is_file():
        result["size"] = path.stat().st_size
        result["sha256"] = digest(path)
        if result["sha256"] is None:
            result["issues"].append("HASH_SIZE_LIMIT")
        if kind == "MACHO":
            try:
                slices = macho.parse(path)
                result["architectures"] = sorted({item["architecture"] for item in slices})
                result["minimum_ios"] = sorted({item["minimum_os"] for item in slices if item["minimum_os"]})
                result["linked_libraries"] = sorted({entry["name"] for item in slices for entry in item["dependencies"]})
                result["rpaths"] = sorted({entry for item in slices for entry in item["rpaths"]})
                result["signature_present"] = all(item["signed"] for item in slices)
                if any(value.startswith(("/Users/", "/Volumes/")) for value in
                       result["rpaths"] + result["linked_libraries"]):
                    result["issues"].append("DEVELOPER_PATH_REVIEW")
                if not set(result["architectures"]) & {"arm64", "arm64e"}:
                    result["issues"].append("BLOCKED_BINARY_ONLY")
            except (OSError, ValueError) as error:
                result["issues"].append("MACHO_INVALID:" + type(error).__name__)
        elif path.suffix == ".deb":
            result["package"] = deb_fields(path)
            if result["package"].get("error"):
                result["issues"].append(result["package"]["error"])
            try:
                result["dependency_groups"] = [
                    {"kind": field, "alternatives": alternatives}
                    for field in ("Pre-Depends", "Depends")
                    for alternatives in parse_dependency_groups(result["package"].get(field) or "")]
                result["dependencies"] = sorted({alternative["name"]
                    for group in result["dependency_groups"]
                    for alternative in group["alternatives"]})
            except ValueError:
                result["issues"].append("INVALID_DEPENDENCY_EXPRESSION")
            result["type"], issues = deb_contents_type(path)
            result["issues"].extend(issues)
            result["control_members"], issues = deb_control_members(path)
            result["issues"].extend(issues)
        elif path.suffix in APP_ARCHIVE_SUFFIXES:
            metadata, issues = ipa_metadata(path)
            result.update(metadata)
            result["issues"].extend(issues)
        elif kind in {"PLIST", "DAEMON"}:
            try:
                value = plistlib.loads(path.read_bytes())
                if not isinstance(value, dict):
                    raise ValueError("plist root is not a dictionary")
                if kind == "DAEMON":
                    result["service_label"] = value.get("Label")
                    program = value.get("Program") or (value.get("ProgramArguments") or [None])[0]
                    if not isinstance(program, str) or not program.startswith("/"):
                        result["issues"].append("DAEMON_PROGRAM_INVALID")
                    else:
                        result["program"] = program
                    if not isinstance(value.get("Label"), str):
                        result["issues"].append("DAEMON_LABEL_INVALID")
            except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
                result["issues"].append("PLIST_INVALID")
        if kind in {"SOURCE", "CLI_TOOL", "BUILD_OR_PACKAGE_METADATA", "MACHO"} and path.stat().st_size <= 8 * 1024 * 1024:
            data = path.read_bytes()
            if kind == "SOURCE":
                result["api_references"] = sorted({
                    (api_kind, match.group(1).decode("ascii"))
                    for api_kind, pattern in API_PATTERNS.items()
                    for match in pattern.finditer(data)})[:128]
            paths = sorted({m.group().decode("utf-8", "replace") for m in PATH_PATTERN.finditer(data)})[:100]
            if any(value.startswith(("/Users/", "/Volumes/")) for value in paths):
                result["issues"].append("DEVELOPER_PATH_REVIEW")
            result["absolute_paths"] = [re.sub(r"^/(Users|Volumes)/[^/]+", r"/\1/<redacted>", value)
                                        for value in paths]
            if SECRET_PATTERN.search(data):
                result["issues"].append("POTENTIAL_SECRET_REVIEW")
    elif kind in {"APP", "FRAMEWORK", "PREFERENCE_BUNDLE"}:
        info = path / "Info.plist"
        if info.is_file():
            try:
                value = plistlib.loads(info.read_bytes())
                result["bundle_id"] = value.get("CFBundleIdentifier")
                result["version"] = value.get("CFBundleVersion")
                result["principal_class"] = value.get("NSPrincipalClass")
                if kind == "APP" and not (path / str(value.get("CFBundleExecutable", ""))).is_file():
                    result["issues"].append("APP_EXECUTABLE_MISSING")
            except (OSError, ValueError, plistlib.InvalidFileException):
                result["issues"].append("BUNDLE_INFO_INVALID")
        else:
            result["issues"].append("BUNDLE_INFO_MISSING")
    result["status"] = "BLOCKED" if result["issues"] else "UNVERIFIED"
    return result


DEPENDENCY_TERM = re.compile(
    r"\s*([a-z0-9][a-z0-9+.-]*)(?::([a-z0-9-]+))?\s*"
    r"(?:\((<<|<=|=|>=|>>)\s*([0-9A-Za-z.+:~_-]+)\))?\s*\Z")


def parse_dependency_groups(value: str) -> list[list[dict]]:
    """Preserve Debian alternatives and version constraints; reject unknown syntax."""
    if not value.strip():
        return []
    groups = []
    for clause in value.split(","):
        alternatives = []
        for term in clause.split("|"):
            match = DEPENDENCY_TERM.fullmatch(term)
            if not match:
                raise ValueError("unsupported dependency expression")
            name, qualifier, operator, version = match.groups()
            alternatives.append({"name": name, "qualifier": qualifier,
                                 "operator": operator, "version": version})
        groups.append(alternatives)
    return groups


def dependency_names(value: str) -> list[str]:
    return sorted({item["name"] for group in parse_dependency_groups(value) for item in group})


def compare_package_versions(actual: str, operator: str | None, required: str | None) -> bool | None:
    if not operator:
        return True
    tool = shutil.which("dpkg")
    if not tool or not actual or not required:
        return None
    try:
        result = subprocess.run([tool, "--compare-versions", actual, operator, required],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return True if result.returncode == 0 else False if result.returncode == 1 else None


def source_catalog_details(root: Path = ROOT) -> tuple[dict[str, dict], str | None]:
    path = root / "bridge/DeviceRuntime/zero_sky_core/research_toolkit_manifest.json"
    try:
        contained = path.resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError):
        contained = False
    if path.is_symlink() or not contained:
        return {}, "SOURCE_CATALOG_SYMLINK"
    try:
        components = load_catalog(path)["components"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        return {}, "SOURCE_CATALOG_" + type(error).__name__.upper()
    result = {}
    for item in components:
        if not isinstance(item, dict):
            continue
        identifiers = [value for key in ("package_ids", "bundle_ids")
                       for value in (item.get(key) if isinstance(item.get(key), list) else [])]
        for identifier in identifiers:
            if isinstance(identifier, str):
                result[identifier.lower()] = item
    return result, None


def source_catalog(root: Path = ROOT) -> dict[str, dict]:
    return source_catalog_details(root)[0]


def resolve_graph(rows: list[dict], candidate_pins: dict[str, dict] | None = None) -> dict:
    candidate_pins = candidate_pins or {}
    package_rows: dict[str, list[str]] = {}
    by_id = {row["id"]: row for row in rows}
    for row in rows:
        if row.get("path") is not None and not row["path"].endswith(PACKAGE_SUFFIXES):
            continue
        metadata = row.get("package")
        package_name = metadata.get("Package") if isinstance(metadata, dict) else row.get("bundle_id")
        if package_name:
            package_rows.setdefault(package_name.lower(), []).append(row["id"])
    duplicates = {}
    identical_copies = {}
    selected_candidates = {}
    candidate_pin_errors = []
    packages = {}
    for name, ids in package_rows.items():
        hashes = {by_id[identifier].get("sha256") for identifier in ids}
        pin = candidate_pins.get(name)
        if pin is not None:
            matched = [identifier for identifier in ids if
                       identifier == pin.get("component_id") and
                       by_id[identifier].get("sha256") == pin.get("artifact_sha256")]
            if len(matched) != 1:
                duplicates[name] = sorted(ids)
                candidate_pin_errors.append("CANDIDATE_PIN_MISMATCH:" + name)
            else:
                packages[name] = matched[0]
                selected_candidates[name] = {"canonical": matched[0],
                    "rejected": sorted(identifier for identifier in ids if identifier != matched[0]),
                    "artifact_sha256": pin["artifact_sha256"]}
        elif len(ids) == 1:
            packages[name] = ids[0]
        elif len(hashes) == 1 and None not in hashes:
            ordered = sorted(ids, key=lambda identifier: by_id[identifier].get("path", identifier))
            packages[name] = ordered[0]
            identical_copies[name] = {"canonical": ordered[0], "copies": ordered[1:]}
        else:
            duplicates[name] = sorted(ids)
    for name in sorted(set(candidate_pins) - set(package_rows)):
        candidate_pin_errors.append("CANDIDATE_PIN_TARGET_MISSING:" + name)
    edges, missing = [], []
    for row in rows:
        groups = row.get("dependency_groups")
        if groups is None:
            groups = [{"kind": "Depends", "alternatives": [
                {"name": name, "qualifier": None, "operator": None, "version": None}]}
                for name in row.get("dependencies", [])]
        for group_number, group in enumerate(groups):
            choices = []
            selected = None
            for position, alternative in enumerate(group["alternatives"]):
                name = alternative["name"].lower()
                qualifier = alternative.get("qualifier")
                ids = package_rows.get(name, [])
                state = "SOURCE_UNRESOLVED"
                if qualifier not in (None, "any", "native", "arm64", "arm64e", "iphoneos-arm64"):
                    state = "ARCHITECTURE_CONFLICT"
                elif name in duplicates:
                    state = "DUPLICATE_SOURCE"
                elif name in packages:
                    identifier = packages[name]
                    candidate = by_id[identifier]
                    meta = candidate.get("package", {})
                    arch = meta.get("Architecture")
                    if arch and arch not in ("iphoneos-arm64", "all"):
                        state = "ARCHITECTURE_CONFLICT"
                    else:
                        actual_version = meta.get("Version") or candidate.get("version")
                        matched = compare_package_versions(actual_version,
                            alternative.get("operator"), alternative.get("version"))
                        state = "PRESENT" if matched is True else (
                            "VERSION_CONFLICT" if matched is False else "VERSION_UNVERIFIED")
                        if matched is True and selected is None:
                            selected = (position, alternative, identifier)
                choices.append({**alternative, "state": state})
            if selected is not None:
                position, alternative, identifier = selected
                edges.append({"from": row["id"], "to": identifier,
                              "package": alternative["name"], "kind": group["kind"],
                              "group": group_number, "chosen_alternative": position,
                              "operator": alternative.get("operator"),
                              "version": alternative.get("version")})
            else:
                missing.append({"from": row["id"], "package": choices[0]["name"],
                                "kind": group["kind"], "group": group_number,
                                "reason": "NO_SATISFIED_ALTERNATIVE",
                                "alternatives": choices})
    pending = {row["id"]: set() for row in rows}
    for edge in edges:
        pending[edge["from"]].add(edge["to"])
    order = []
    while pending:
        ready = sorted(name for name, deps in pending.items() if not deps)
        if not ready:
            break
        for name in ready:
            order.append(name)
            del pending[name]
        for deps in pending.values():
            deps.difference_update(ready)
    return {"edges": sorted(edges, key=lambda item: (item["from"], item["group"], item["to"])),
            "missing": sorted(missing, key=lambda item: (item["from"], item["group"], item["package"])),
            "build_order": order, "cycles": sorted(pending),
            "duplicate_packages": duplicates, "identical_copies": identical_copies,
            "selected_candidates": selected_candidates,
            "candidate_pin_errors": candidate_pin_errors}


def admission(evidence: dict, kind: str, *, artifact_sha256: str | None = None,
              environment_hash: str | None = None, quarantined: bool = False,
              maintainer_scripts: list[str] | None = None) -> dict:
    """Require stage evidence bound to one artifact and measured environment."""
    required = set(REQUIRED_GATE)
    if kind not in {"APP", "PACKAGE_MANAGER"}:
        required.discard("registration")
    if maintainer_scripts:
        required.add("maintainer_scripts")
    def passed(name: str) -> bool:
        value = evidence.get(name)
        return (isinstance(value, dict) and value.get("result") == "PASS" and
                artifact_sha256 is not None and value.get("artifact_sha256") == artifact_sha256 and
                environment_hash is not None and value.get("environment_hash") == environment_hash and
                (name != "maintainer_scripts" or
                 value.get("reviewed_scripts") == sorted(maintainer_scripts or [])))
    missing = sorted(name for name in required if not passed(name))
    if quarantined:
        status = "QUARANTINED"
    elif any(isinstance(evidence.get(name), dict) and
             evidence[name].get("result") == "FAIL" for name in required):
        status = "BLOCKED"
    else:
        status = "PASS" if not missing else "BLOCKED"
    return {"repo_admission": status, "missing_or_failed": missing}


def validate_compat_manifest(manifest: object) -> dict:
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or manifest.get("target") != "ios27":
        raise ValueError("compatibility manifest schema or target is invalid")
    package, status = manifest.get("package"), manifest.get("status")
    if (not isinstance(package, str) or
            not re.fullmatch(r"[a-z0-9][a-z0-9+._-]{1,199}", package) or
            status not in COMPATIBILITY_STATES):
        raise ValueError("compatibility identity or state is invalid")
    tests = manifest.get("tests")
    scripts = manifest.get("maintainer_scripts", [])
    if (not isinstance(scripts, list) or
            any(not isinstance(item, dict) or
                not isinstance(item.get("name"), str) or
                not re.fullmatch(r"(?:preinst|postinst|prerm|postrm|config)", item["name"]) or
                not isinstance(item.get("sha256"), str) or
                not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
                for item in scripts) or
            len({item["name"] for item in scripts}) != len(scripts)):
        raise ValueError("maintainer script manifest is invalid")
    if not isinstance(tests, dict) or not set(REQUIRED_GATE).issubset(tests):
        raise ValueError("compatibility tests are incomplete")
    if any(tests[name] not in ("PASS", "FAIL", "UNVERIFIED", "SKIP", "BLOCKED")
           for name in REQUIRED_GATE):
        raise ValueError("compatibility test result is invalid")
    if ("maintainer_scripts" in tests and
            tests["maintainer_scripts"] not in ("PASS", "FAIL", "UNVERIFIED", "SKIP", "BLOCKED")):
        raise ValueError("maintainer script review result is invalid")
    if status == "PASS" or manifest.get("repo_admission") == "PASS":
        required = ("original_sha256", "resulting_artifact_sha256", "source_commit", "license",
                    "environment_hash", "reviewed_receipt_sha256")
        required_tests = set(REQUIRED_GATE)
        if manifest.get("type") not in {"APP", "PACKAGE_MANAGER"}:
            required_tests.discard("registration")
        if manifest.get("maintainer_scripts"):
            required_tests.add("maintainer_scripts")
        if (any(not manifest.get(name) for name in required) or
                not required_tests.issubset(tests) or
                any(tests[name] != "PASS" for name in required_tests) or
                manifest.get("repo_admission") != "PASS"):
            raise ValueError("PASS lacks exact artifact, provenance or test evidence")
        for name in ("original_sha256", "resulting_artifact_sha256", "environment_hash",
                     "reviewed_receipt_sha256"):
            if not re.fullmatch(r"[a-f0-9]{64}", manifest[name]):
                raise ValueError("PASS has an invalid artifact hash")
    return manifest


def conversion_plan(rows: list[dict], graph: dict, catalog: dict[str, dict]) -> list[dict]:
    duplicate_ids = {identity for ids in graph["duplicate_packages"].values() for identity in ids}
    copy_ids = {identity for item in graph.get("identical_copies", {}).values()
                for identity in item["copies"]}
    superseded_ids = {identity for item in graph.get("selected_candidates", {}).values()
                      for identity in item["rejected"]}
    cycles = set(graph["cycles"])
    missing = {item["from"] for item in graph["missing"]}
    order = {identifier: position for position, identifier in enumerate(graph["build_order"])}
    result = []
    for row in rows:
        if not row["path"].endswith(PACKAGE_SUFFIXES):
            continue
        metadata = row.get("package", {})
        package = (metadata.get("Package") or row.get("bundle_id") or "").lower()
        source = catalog.get(package, {})
        blockers = list(row.get("issues", []))
        if row["id"] in duplicate_ids:
            blockers.append("DUPLICATE_PACKAGE_IDENTIFIER")
        if row["id"] in copy_ids:
            blockers.append("DUPLICATE_ARTIFACT_COPY")
        if row["id"] in superseded_ids:
            blockers.append("SUPERSEDED_CANDIDATE")
        if row["id"] in cycles:
            blockers.append("DEPENDENCY_CYCLE")
        if row["id"] in missing:
            blockers.append("DEPENDENCY_SOURCE_UNRESOLVED")
        if not source.get("upstream_project"):
            blockers.append("SOURCE_PROVENANCE_UNRESOLVED")
        checkout = source.get("source_mirror") or source.get("upstream_project")
        checkout_trust = (source.get("source_mirror_trust", "UNVERIFIED") if source.get("source_mirror")
                          else source.get("trust_state", "UNVERIFIED"))
        if checkout_trust not in {"OFFICIAL", "VERIFIED_COMMUNITY", "LOCAL_0SKY"}:
            blockers.append("SOURCE_CHECKOUT_UNVERIFIED")
        if not source.get("source_mirror_revision") and not source.get("source_revision"):
            blockers.append("SOURCE_REVISION_UNRESOLVED")
        if source.get("license") in (None, "", "UNKNOWN", "UNVERIFIED", "NOASSERTION"):
            blockers.append("SOURCE_LICENSE_UNRESOLVED")
        if (row["path"].endswith(".deb") and metadata.get("Architecture") not in ("iphoneos-arm64", "all")) or (
                row["path"].endswith(APP_ARCHIVE_SUFFIXES) and
                not set(row.get("architectures", [])) & {"arm64", "arm64e"}):
            blockers.append("ARCHITECTURE_REBUILD_REQUIRED")
        state = "UNSAFE_TO_ADAPT" if any(value in blockers for value in
            STATIC_UNSAFE_ISSUES) else (
            "BROKEN_UPSTREAM" if any(value in blockers for value in
            STATIC_BROKEN_ISSUES) else (
            "UNKNOWN" if any(value in blockers for value in
            ("DUPLICATE_PACKAGE_IDENTIFIER", "DUPLICATE_ARTIFACT_COPY",
             "SUPERSEDED_CANDIDATE")) else (
            "BLOCKED_BY_DEPENDENCY" if any(value.startswith("DEPENDENCY") for value in blockers) else (
            "BUILD_REQUIRED" if any(value in blockers for value in
                ("SOURCE_PROVENANCE_UNRESOLVED", "SOURCE_CHECKOUT_UNVERIFIED",
                 "SOURCE_REVISION_UNRESOLVED", "SOURCE_LICENSE_UNRESOLVED")) else (
            "BLOCKED_BY_ARCHITECTURE" if "BLOCKED_BINARY_ONLY" in blockers else (
            "BUILD_REQUIRED" if "ARCHITECTURE_REBUILD_REQUIRED" in blockers else
            "ADAPTATION_REQUIRED")))))
        )
        result.append({"id": row["id"], "package": package or None,
                       "source_path": row["path"], "original_sha256": row.get("sha256"),
                       "category": row["type"], "architecture": metadata.get("Architecture") or row.get("architectures"),
                       "upstream_project": source.get("upstream_project"),
                       "source_url": checkout,
                       "source_revision": source.get("source_mirror_revision") or source.get("source_revision"),
                       "license": source.get("license"),
                       "source_trust": checkout_trust,
                       "dependencies": row.get("dependencies", []),
                       "recommended_order": order.get(row["id"]),
                       "conversion": "REBUILD_FROM_SOURCE" if source.get("upstream_project") else "SOURCE_REVIEW_REQUIRED",
                       "status": state, "blockers": sorted(set(blockers)),
                       "repo_admission": "BLOCKED"})
    return sorted(result, key=lambda item: (item["recommended_order"] is None,
                                          item["recommended_order"] or 0, item["source_path"]))


def entitlement_evidence(root: Path, row: dict) -> dict:
    entry = {"id": row["id"], "path": row["path"], "state": "UNVERIFIED",
             "entitlements": None}
    if row.get("signature_present") is False:
        entry["state"] = "SIGNATURE_ABSENT"
        return entry
    if row.get("signature_present") is not True:
        return entry
    path = root / row["path"]
    try:
        output = subprocess.run(["/usr/bin/codesign", "--display", "--entitlements", ":-",
                                 str(path)], capture_output=True, timeout=8, check=False)
        if output.returncode:
            entry["reason"] = "CODESIGN_ENTITLEMENT_EXTRACTION_FAILED"
        elif not output.stdout.strip():
            entry["state"] = "NO_ENTITLEMENTS"
            entry["entitlements"] = {}
        elif len(output.stdout) > 1024 * 1024:
            entry["reason"] = "ENTITLEMENT_DATA_TOO_LARGE"
        else:
            value = plistlib.loads(output.stdout)
            if not isinstance(value, dict):
                raise ValueError("entitlement root is not dictionary")
            entry["state"] = "EXTRACTED_UNVERIFIED"
            entry["entitlements"] = sanitize(value)
    except (OSError, ValueError, subprocess.TimeoutExpired, plistlib.InvalidFileException):
        entry["reason"] = "ENTITLEMENT_PARSE_OR_TOOL_FAILURE"
    return entry


def scan(root: Path, candidate_pins: dict[str, dict] | None = None) -> tuple[list[dict], dict]:
    root = root.resolve()
    rows = []
    for base, dirs, files in os.walk(root, followlinks=False):
        candidates = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".git"))
        dirs[:] = [name for name in candidates if not (Path(base) / name).is_symlink()]
        for name in candidates + sorted(files):
            path = Path(base) / name
            row = inspect_item(root, path)
            if row:
                rows.append(row)
    rows.sort(key=lambda item: item["path"])
    return rows, resolve_graph(rows, candidate_pins)


def write_reports(root: Path, output: Path) -> dict:
    root = root.resolve()
    candidate_pins, registry_errors = load_candidate_pins(root)
    rows, graph = scan(root, candidate_pins)
    graph["candidate_pin_errors"] = registry_errors + graph["candidate_pin_errors"]
    rows, graph = sanitize(rows), sanitize(graph)
    output.mkdir(parents=True, exist_ok=True)
    private_libraries = sorted({name for row in rows for name in row.get("linked_libraries", [])
        if "PrivateFrameworks" in name or any(marker in name for marker in
            ("SpringBoardServices", "FrontBoardServices", "BackBoardServices"))})
    source_apis = sorted({(kind, name) for row in rows for kind, name in row.get("api_references", [])})
    with ThreadPoolExecutor(max_workers=8) as pool:
        entitlements = list(pool.map(lambda row: entitlement_evidence(root, row),
            (row for row in rows if row["type"] == "MACHO")))
    catalog, catalog_error = source_catalog_details(root)
    plan = conversion_plan(rows, graph, catalog)
    planned_by_id = {item["id"]: item for item in plan}
    reviewed_receipts, receipt_errors = load_reviewed_receipts(root)
    admission_by_id = {}
    packages = []
    for row in rows:
        if not row["path"].endswith(PACKAGE_SUFFIXES):
            continue
        planned = planned_by_id[row["id"]]
        receipt = reviewed_receipts.get((row["id"], row["sha256"]))
        evidence = receipt.get("stages", {}) if receipt else {}
        environment_hash = receipt.get("environment_hash") if receipt else None
        gate = admission(evidence, row["type"], artifact_sha256=row["sha256"],
                         environment_hash=environment_hash,
                         quarantined=receipt.get("quarantined", False) if receipt else False,
                         maintainer_scripts=sorted(member["name"] + ":" + member["sha256"]
                             for member in row.get("control_members", []) if member["maintainer_script"]))
        blockers = list(planned["blockers"])
        if "maintainer_scripts" not in gate["missing_or_failed"]:
            blockers = [item for item in blockers if item != "MAINTAINER_SCRIPT_REQUIRES_REVIEW"]
            planned["blockers"] = blockers
        if receipt and (receipt.get("resulting_artifact_sha256") != row["sha256"] or
                        not re.fullmatch(r"[a-f0-9]{64}", receipt.get("original_sha256", ""))):
            blockers.append("REVIEWED_ARTIFACT_PROVENANCE_INCOMPLETE")
        if (not planned.get("source_revision") or
                planned.get("license") in (None, "", "UNKNOWN", "UNVERIFIED", "NOASSERTION")):
            blockers.append("SOURCE_METADATA_INCOMPLETE")
        if blockers and gate["repo_admission"] == "PASS":
            gate["repo_admission"] = "BLOCKED"
        gate["blocking_reasons"] = sorted(set(blockers))
        gate["reviewed_receipt_sha256"] = receipt.get("reviewed_receipt_sha256") if receipt else None
        gate["environment_hash"] = environment_hash
        admission_by_id[row["id"]] = gate
        packages.append({"id": row["id"], "package": row.get("package", {}).get("Package") or row.get("bundle_id"),
                         **gate})
    admitted_count = sum(item["repo_admission"] == "PASS" for item in packages)
    payloads = {"inventory.json": {"schema": 1, "target": "ios27", "components": rows},
                "source-catalog-status.json": {"schema": 1, "status":
                    "BLOCKED" if catalog_error else "PASS", "error": catalog_error,
                    "indexed_identities": len(catalog)},
                "dependency-graph.json": {"schema": 1, **graph},
                "entitlements-report.json": {"schema": 1, "components": entitlements,
                    "status": "UNVERIFIED", "reason": "Extraction alone does not establish effective device entitlements"},
                "private-api-map.json": {"schema": 1, "target": "ios27", "entries": [
                    {"kind": kind, "old_api": name, "observed_ios27_api": None, "replacement": None,
                     "shim_available": False, "source_modification_required": "UNKNOWN",
                     "runtime_discovery_possible": True, "status": "UNRESOLVED"}
                    for kind, name in [("linked_framework", value) for value in private_libraries] + source_apis]},
                "repository-admission.json": {"schema": 1, "packages": packages,
                    "receipt_errors": receipt_errors, "repo_admitted": admitted_count},
                "conversion-plan.json": {"schema": 1, "target": "ios27", "packages": plan}}
    for name, value in payloads.items():
        temporary = output / (name + ".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
        temporary.replace(output / name)
    manifest_root = output / "manifests"
    manifest_root.mkdir(exist_ok=True)
    live_manifest_ids = {item["id"] for item in plan}
    for planned in plan:
        row = next(item for item in rows if item["id"] == planned["id"])
        metadata = row.get("package", {})
        receipt = reviewed_receipts.get((row["id"], row["sha256"]))
        gate = admission_by_id[row["id"]]
        identity = metadata.get("Package") or row.get("bundle_id")
        manifest = {"schema": 1, "package": identity.lower() if isinstance(identity, str) else None,
                    "type": row["type"],
                    "version": metadata.get("Version") or row.get("version"), "component_id": row["id"],
                    "target": "ios27", "original_sha256":
                    receipt.get("original_sha256") if receipt else row["sha256"],
                    "upstream_project": planned["upstream_project"],
                    "source_url": planned["source_url"],
                    "source_commit": planned["source_revision"],
                    "license": planned["license"], "patches": [], "resulting_artifact_sha256":
                    row["sha256"] if receipt else None,
                    "maintainer_scripts": [
                        {"name": member["name"], "sha256": member["sha256"]}
                        for member in row.get("control_members", []) if member["maintainer_script"]],
                    "toolchain_version": None,
                    "architecture": ([metadata["Architecture"]] if metadata.get("Architecture") else
                                     row.get("architectures", [])),
                    "rootless": "UNVERIFIED", "conversion_method": None,
                    "dependencies": row.get("dependencies", []), "status":
                    "PASS" if gate["repo_admission"] == "PASS" else planned["status"],
                    "tests": {name: (receipt.get("stages", {}).get(name, {}).get("result", "UNVERIFIED")
                                     if receipt else "UNVERIFIED") if name != "registration" or
                              row["type"] in {"APP", "PACKAGE_MANAGER"} else "SKIP"
                              for name in REQUIRED_GATE},
                    "repo_admission": gate["repo_admission"],
                    "environment_hash": gate["environment_hash"],
                    "reviewed_receipt_sha256": gate["reviewed_receipt_sha256"],
                    "blocking_reason": gate["blocking_reasons"] + gate["missing_or_failed"]}
        manifest["tests"]["maintainer_scripts"] = (
            receipt.get("stages", {}).get("maintainer_scripts", {}).get("result", "UNVERIFIED")
            if manifest["maintainer_scripts"] and receipt else
            "UNVERIFIED" if manifest["maintainer_scripts"] else "SKIP")
        if manifest["package"] is not None:
            validate_compat_manifest(manifest)
        target = manifest_root / row["id"]
        target.mkdir(exist_ok=True)
        temporary = target / "0sky-compat.json.tmp"
        temporary.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        temporary.replace(target / "0sky-compat.json")
    for stale in manifest_root.iterdir():
        if stale.name in live_manifest_ids or stale.is_symlink() or not stale.is_dir():
            continue
        children = list(stale.iterdir())
        if (len(children) != 1 or children[0].name != "0sky-compat.json" or
                children[0].is_symlink() or not children[0].is_file() or
                children[0].stat().st_size > 256 * 1024):
            continue
        try:
            old = json.loads(children[0].read_text())
        except (OSError, UnicodeError, ValueError):
            continue
        if (isinstance(old, dict) and old.get("schema") == 1 and old.get("target") == "ios27" and
                old.get("component_id") == stale.name):
            children[0].unlink()
            stale.rmdir()
    index = {"schema": 1, "target": "ios27", "component_ids": sorted(live_manifest_ids)}
    temporary_index = output / "manifest-index.json.tmp"
    temporary_index.write_text(json.dumps(index, sort_keys=True, indent=2) + "\n")
    temporary_index.replace(output / "manifest-index.json")
    with (output / "inventory.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["id", "path", "type", "sha256", "status", "issues"])
        writer.writeheader()
        for row in rows:
            writer.writerow({key: ",".join(row[key]) if key == "issues" else row.get(key)
                             for key in writer.fieldnames})
    conversion_counts = dict(sorted(Counter(item["status"] for item in plan).items()))
    summary = {"total_components": len(rows), "package_artifacts": len(plan),
               "status_counts": {state: sum(row["status"] == state for row in rows)
                for state in ("UNVERIFIED", "BLOCKED")}, "conversion_counts": conversion_counts,
               "missing_dependencies": len(graph["missing"]),
               "dependency_cycles": len(graph["cycles"]),
               "duplicate_packages": len(graph["duplicate_packages"]),
               "identical_package_copies": sum(len(item["copies"]) for item in
                   graph["identical_copies"].values()),
               "selected_candidates": len(graph["selected_candidates"]),
               "candidate_pin_errors": len(graph["candidate_pin_errors"]),
               "source_catalog_status": "BLOCKED" if catalog_error else "PASS",
               "repo_admitted": admitted_count}
    (output / "summary.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    lines = ["# iOS 27 compatibility intake", "", "This is static intake evidence. No device runtime, smoke, or UAT result is inferred from a package file.", "",
             f"- Components inventoried: {len(rows)}", f"- Package artifacts: {len(plan)}",
             f"- Unverified inventory entries: {summary['status_counts']['UNVERIFIED']}",
             f"- Blocked inventory entries: {summary['status_counts']['BLOCKED']}",
             f"- Missing dependency edges: {len(graph['missing'])}",
             f"- Duplicate package identifiers: {len(graph['duplicate_packages'])}",
             f"- Identical package copies: {summary['identical_package_copies']}",
             f"- Hash-pinned candidates: {summary['selected_candidates']}",
             f"- Candidate pin errors: {summary['candidate_pin_errors']}",
             f"- Source catalog: {summary['source_catalog_status']}",
             f"- Dependency cycles: {len(graph['cycles'])}", f"- Repository admitted: {admitted_count}", "",
             "| Package | Version | Type | Original architecture | Dependencies | Conversion | Build | Install | Runtime | Smoke | UAT | Repository | Blocking reason |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    by_id = {row["id"]: row for row in rows}
    def cell(value: object) -> str:
        return str(value if value is not None else "UNKNOWN").replace("|", "\\|").replace("\n", " ")
    for item in sorted(plan, key=lambda value: (value["package"] or "", value["source_path"])):
        row = by_id[item["id"]]
        metadata = row.get("package", {})
        columns = [item["package"], metadata.get("Version") or row.get("version"), item["category"], item["architecture"],
                   ", ".join(item["dependencies"]) or "none declared", item["status"],
                   "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED",
                   admission_by_id[item["id"]]["repo_admission"],
                   ", ".join(admission_by_id[item["id"]]["blocking_reasons"] +
                             admission_by_id[item["id"]]["missing_or_failed"]) or "none"]
        lines.append("| " + " | ".join(cell(value) for value in columns) + " |")
    (output / "report.md").write_text("\n".join(lines) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/compatibility")
    args = parser.parse_args()
    print(json.dumps(write_reports(args.root, args.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
