"""Forensic comparison of immutable package artifacts.

The comparator extracts through the hardened intake path, never executes package
scripts, and emits only logical labels for source locations.  Its output is
evidence for rule review; it does not promote or apply compatibility rules.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tempfile
import zipfile
import re

from .discovery import MAGICS, entries, file_hash
from .intake import stage
from .macho import parse as parse_macho


SCRIPT_NAMES = {"preinst", "postinst", "prerm", "postrm", "config", "triggers", "extrainst_"}


def _redact_string(value: str) -> str:
    value = re.sub(r"/Users/[^/\x00]+", "<DEVELOPER_HOME>", value)
    value = re.sub(r"/Volumes/[^/\x00]+", "<MOUNTED_VOLUME>", value)
    return value


def _jsonable(value):
    if isinstance(value, bytes):
        return {"bytes_sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in sorted(value.items(), key=lambda row: str(row[0]))}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


def _read_plist(path: Path) -> dict:
    try:
        value = plistlib.loads(path.read_bytes())
        return {"valid": True, "value": _jsonable(value)}
    except (OSError, plistlib.InvalidFileException, ValueError, TypeError) as error:
        return {"valid": False, "error": type(error).__name__}


def _entitlements(path: Path) -> dict:
    codesign = shutil.which("codesign")
    if not codesign:
        return {"state": "TOOL_UNAVAILABLE"}
    try:
        result = subprocess.run(
            [codesign, "-d", "--entitlements", ":-", str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"state": "INSPECTION_FAILED", "error": type(error).__name__}
    candidates = [result.stdout, result.stderr]
    for data in candidates:
        start = data.find(b"<?xml")
        if start < 0:
            start = data.find(b"bplist")
        if start >= 0:
            try:
                return {"state": "PRESENT", "value": _jsonable(plistlib.loads(data[start:]))}
            except (plistlib.InvalidFileException, ValueError, TypeError):
                pass
    return {"state": "ABSENT_OR_UNREADABLE", "exit_status": result.returncode}


def _control_metadata(root: Path) -> dict:
    path = root / "DEBIAN/control"
    if not path.is_file():
        return {}
    output: dict[str, str] = {}
    current = ""
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith((" ", "\t")) and current:
            output[current] += "\n" + line
        elif ":" in line:
            current, value = line.split(":", 1)
            output[current] = value.strip()
    return output


def _archive_metadata(source: Path) -> dict:
    """Record archive modes/owners without applying them to the host."""
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            return {
                "format": "zip",
                "comment_sha256": hashlib.sha256(archive.comment).hexdigest(),
                "members": {
                    item.filename: {
                        "size": item.file_size,
                        "mode": item.external_attr >> 16,
                        "compression": item.compress_type,
                        "crc32": f"{item.CRC:08x}",
                    }
                    for item in archive.infolist()
                },
            }
    if source.suffix.lower() != ".deb":
        return {"format": source.suffix.lower().lstrip(".") or "bundle", "members": {}}
    tool = shutil.which("dpkg-deb")
    if not tool:
        return {"format": "deb", "members": {}, "inspection": "TOOL_UNAVAILABLE"}
    import tarfile
    members = {}
    for option, prefix in (("--fsys-tarfile", ""), ("--ctrl-tarfile", "DEBIAN/")):
        with tempfile.TemporaryFile() as output:
            result = subprocess.run([tool, option, str(source)], stdout=output,
                                    stderr=subprocess.PIPE, timeout=120, check=False)
            if result.returncode:
                return {"format": "deb", "members": {}, "inspection": "FAILED"}
            output.seek(0)
            with tarfile.open(fileobj=output, mode="r:*") as archive:
                for item in archive:
                    name = prefix + item.name.lstrip("./")
                    members[name] = {"size": item.size, "mode": item.mode,
                                     "uid": item.uid, "gid": item.gid,
                                     "type": item.type.decode("ascii", "replace"),
                                     "link": item.linkname or None}
    return {"format": "deb", "members": members}


def inspect_staged(root: Path) -> dict:
    files = {}
    plists = {}
    machos = {}
    scripts = {}
    preference_bundles = []
    launch_services = []
    for path in entries(root):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            files[relative] = {"type": "symlink", "mode": mode, "target": os.readlink(path)}
            continue
        if path.is_dir():
            files[relative] = {"type": "directory", "mode": mode}
            if path.suffix == ".bundle" and "PreferenceBundles" in path.parts:
                preference_bundles.append(relative)
            continue
        digest = file_hash(path)
        files[relative] = {"type": "file", "mode": mode, "size": path.stat().st_size,
                           "sha256": digest}
        if path.suffix == ".plist":
            plists[relative] = _read_plist(path)
            if any(part in ("LaunchDaemons", "LaunchAgents") for part in path.parts):
                launch_services.append(relative)
        if path.parent.name == "DEBIAN" and path.name in SCRIPT_NAMES:
            text = path.read_text(errors="replace")[:131072]
            scripts[relative] = {"sha256": digest, "mode": mode,
                                 "operations": sorted(set(re.findall(
                                     r"\b(?:launchctl|uicache|dpkg|apt(?:-get)?|killall|chmod|chown|"
                                     r"mkdir|rm|mv|cp|ln|defaults)\b", text))),
                                 "absolute_paths": sorted(set(re.findall(
                                     r"/(?:Library|Applications|usr|bin|sbin|etc|var)(?:/[A-Za-z0-9._+@%${}-]+)*",
                                     text)))[:256]}
        try:
            with path.open("rb") as handle:
                magic = handle.read(4)
            if magic in MAGICS:
                raw_slices = parse_macho(path)
                redacted = _jsonable(raw_slices)
                sensitive = []
                for index, item in enumerate(raw_slices):
                    values = list(item.get("rpaths", [])) + [item.get("install_name")] + [
                        dependency.get("name") for dependency in item.get("dependencies", [])]
                    for value in values:
                        if isinstance(value, str) and value != _redact_string(value):
                            sensitive.append({"slice": index,
                                              "sha256": hashlib.sha256(value.encode()).hexdigest(),
                                              "kind": "developer_path"})
                machos[relative] = {"slices": redacted, "sensitive_path_evidence": sensitive,
                                    "entitlements": _entitlements(path)}
        except (OSError, ValueError) as error:
            machos[relative] = {"error": type(error).__name__ + ": " + str(error)}
    return {
        "files": files,
        "package_metadata": _control_metadata(root),
        "plists": plists,
        "launch_daemons": sorted(launch_services),
        "preference_bundles": sorted(preference_bundles),
        "maintainer_scripts": scripts,
        "mach_o": machos,
    }


def _mapping_diff(before: dict, after: dict) -> dict:
    common = before.keys() & after.keys()
    return {
        "added": sorted(after.keys() - before.keys()),
        "removed": sorted(before.keys() - after.keys()),
        "changed": sorted(key for key in common if before[key] != after[key]),
        "unchanged_count": sum(before[key] == after[key] for key in common),
    }


@dataclass(frozen=True)
class ArtifactRef:
    label: str
    path: Path


def compare_pair(pair_id: str, relationship: str, original: ArtifactRef,
                 working: ArtifactRef, evidence: list[str] | None = None) -> dict:
    """Compare one pair in isolated temporary workspaces."""
    if original.path.resolve() == working.path.resolve():
        raise ValueError("original and working artifacts must be different files")
    with tempfile.TemporaryDirectory(prefix="0sky-manual-comparison-") as folder:
        base = Path(folder)
        original_root, original_hash = stage(original.path, base / "original")
        working_root, working_hash = stage(working.path, base / "working")
        original_value = inspect_staged(original_root)
        working_value = inspect_staged(working_root)
    file_diff = _mapping_diff(original_value["files"], working_value["files"])
    content_changed = [
        name for name in file_diff["changed"]
        if original_value["files"][name].get("sha256") != working_value["files"][name].get("sha256")
    ]
    mode_changed = [
        name for name in file_diff["changed"]
        if original_value["files"][name].get("mode") != working_value["files"][name].get("mode")
    ]
    archive_before = _archive_metadata(original.path)
    archive_after = _archive_metadata(working.path)
    member_diff = _mapping_diff(archive_before.get("members", {}), archive_after.get("members", {}))
    return {
        "pair_id": pair_id,
        "relationship": relationship,
        "original": {"label": original.label, "sha256": original_hash,
                     "size": original.path.stat().st_size, "archive": archive_before,
                     "inspection": original_value},
        "working": {"label": working.label, "sha256": working_hash,
                    "size": working.path.stat().st_size, "archive": archive_after,
                    "inspection": working_value},
        "diff": {
            "recursive_files": file_diff,
            "content_changed": content_changed,
            "mode_changed": mode_changed,
            "package_metadata": _mapping_diff(original_value["package_metadata"], working_value["package_metadata"]),
            "plists": _mapping_diff(original_value["plists"], working_value["plists"]),
            "launch_daemons": {
                "original": original_value["launch_daemons"], "working": working_value["launch_daemons"]},
            "entitlements_and_macho": _mapping_diff(original_value["mach_o"], working_value["mach_o"]),
            "maintainer_scripts": _mapping_diff(original_value["maintainer_scripts"], working_value["maintainer_scripts"]),
            "preference_bundles": {
                "original": original_value["preference_bundles"], "working": working_value["preference_bundles"]},
            "archive_members": member_diff,
        },
        "runtime_evidence": evidence or [],
    }
