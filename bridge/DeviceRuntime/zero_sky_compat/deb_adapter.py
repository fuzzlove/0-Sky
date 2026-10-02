"""Locked, deterministic transformations for Debian package metadata/plists."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import shutil
import subprocess
import tempfile

from .intake import safe_name, stage


def _run(arguments: list[str], *, timeout: int = 120,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False, env=env)
    if result.returncode:
        raise RuntimeError(Path(arguments[0]).name + " failed with exit status " + str(result.returncode))
    return result


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _control(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text().splitlines():
        if line.startswith((" ", "\t")):
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            result[key] = value.strip()
    return result


def _plist_json(plutil: str, path: Path) -> object:
    data = _run([plutil, "-convert", "json", "-o", "-", str(path)], timeout=30).stdout
    return json.loads(data)


def canonicalize_locked_plist(source: Path, destination: Path, *, package: str,
                              from_version: str, to_version: str,
                              plist_path: str, source_date_epoch: int) -> dict:
    """Canonicalize one named plist and bump one locked package version.

    The function refuses unconstrained matching.  A reviewed conversion lock
    supplies exact identity, versions and relative path, and all other staged
    content remains byte and mode identical.
    """
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("destination must not overwrite the original artifact")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    relative = safe_name(plist_path)
    if not relative.as_posix().endswith(".plist"):
        raise ValueError("locked path is not a plist")
    dpkg = shutil.which("dpkg-deb")
    plutil = shutil.which("plutil")
    if not dpkg or not plutil:
        raise RuntimeError("dpkg-deb and plutil are required")
    with tempfile.TemporaryDirectory(prefix="0sky-deb-adapter-") as temporary:
        work = Path(temporary)
        root, original_hash = stage(source, work / "intake", dpkg)
        control = root / "DEBIAN/control"
        metadata = _control(control)
        if metadata.get("Package") != package or metadata.get("Version") != from_version:
            raise ValueError("artifact identity does not match conversion lock")
        target = root / relative.as_posix()
        if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root.resolve()):
            raise ValueError("locked plist is absent or unsafe")
        before = _plist_json(plutil, target)
        converted = work / "canonical.plist"
        _run([plutil, "-convert", "xml1", "-o", str(converted), str(target)], timeout=30)
        after = plistlib.loads(converted.read_bytes())
        if before != after:
            raise RuntimeError("plist canonicalization changed semantic content")
        converted.replace(target)
        text = control.read_text()
        needle = "Version: " + from_version + "\n"
        if text.count(needle) != 1:
            raise ValueError("locked source version is not unique")
        control.write_text(text.replace(needle, "Version: " + to_version + "\n"))
        for path in root.rglob("*"):
            if path.is_symlink():
                raise ValueError("DEB staging contains an unsupported symbolic link")
            os.utime(path, (source_date_epoch, source_date_epoch))
        pending = work / "converted.deb"
        environment = {key: os.environ[key] for key in ("PATH", "LANG") if key in os.environ}
        environment["SOURCE_DATE_EPOCH"] = str(source_date_epoch)
        _run([dpkg, "--build", "--root-owner-group", "--uniform-compression",
              "--compression=xz", str(root), str(pending)], env=environment)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(pending, destination)
    return {"rule": "legacy-plist-canonicalization-v1",
            "package": package, "from_version": from_version, "to_version": to_version,
            "plist": relative.as_posix(), "semantic_plist_preserved": True,
            "original_sha256": original_hash, "converted_sha256": _sha(destination),
            "output": destination.name}
