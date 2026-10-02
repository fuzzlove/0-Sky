"""Deterministic, byte-preserving ZIP compression adapter for IPA/TIPA input."""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
from pathlib import PurePosixPath
import shutil
import stat
import tempfile
import zipfile

from .intake import safe_name

MAX_ENTRIES = 100_000
MAX_EXPANDED_BYTES = 4 * 1024 ** 3


def _inventory(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        return {
            item.filename: {
                "sha256": hashlib.sha256(archive.read(item)).hexdigest(),
                "size": item.file_size, "mode": item.external_attr >> 16,
            }
            for item in archive.infolist()
        }


def normalize_zip_compression(source: Path, destination: Path) -> dict:
    """Create a derivative Deflate archive without changing member payloads."""
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or not source.is_file():
        raise ValueError("source must be one real artifact file")
    if source.resolve() == destination.resolve():
        raise ValueError("destination must not overwrite the original artifact")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise ValueError("destination directory must not be symbolic")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        if len(members) > MAX_ENTRIES or sum(item.file_size for item in members) > MAX_EXPANDED_BYTES:
            raise ValueError("archive expansion limit exceeded")
        expanded = sum(item.file_size for item in members)
        if shutil.disk_usage(destination.parent).free < expanded + 256 * 1024 * 1024:
            raise ValueError("insufficient workspace for archive conversion")
        seen = set()
        for item in members:
            relative = safe_name(item.filename)
            key = relative.as_posix()
            if key in seen:
                raise ValueError("duplicate archive entry")
            seen.add(key)
            if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
                                           zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
                raise ValueError("unsupported ZIP compression method")
            if stat.S_ISLNK(item.external_attr >> 16):
                raw = archive.read(item)
                if len(raw) > 4096 or b"\0" in raw:
                    raise ValueError("invalid ZIP symlink target")
                link = raw.decode("utf-8", "strict")
                if PurePosixPath(link).is_absolute():
                    raise ValueError("external ZIP symlink requires adapter")
                safe_name(os.path.normpath(str(relative.parent / link)))
        before = _inventory(source)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".0sky-zip-",
                                             suffix=".tmp", delete=False) as handle:
                temporary = Path(handle.name)
            with zipfile.ZipFile(temporary, "w", allowZip64=True) as output:
                output.comment = archive.comment
                for item in members:
                    clone = copy.copy(item)
                    clone.compress_type = zipfile.ZIP_STORED if item.is_dir() else zipfile.ZIP_DEFLATED
                    with archive.open(item) as incoming, output.open(clone, "w") as outgoing:
                        shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            with zipfile.ZipFile(temporary) as check:
                bad = check.testzip()
                if bad:
                    raise ValueError("converted archive CRC failure: " + bad)
            after = _inventory(temporary)
            if before != after:
                raise RuntimeError("archive normalization changed member bytes or modes")
            temporary.replace(destination)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return {
        "rule": "zip-compression-normalization-v1",
        "original_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "converted_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "members_verified": len(before), "payload_bytes_preserved": True,
        "output": destination.name,
    }
