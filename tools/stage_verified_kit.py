#!/usr/bin/env python3
"""Stage only manifest-listed 0-Sky kit assets for a distributable app."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import tempfile


class StageError(RuntimeError):
    pass


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def stage(source: Path, destination: Path, *, release: bool = False,
          link_embed: bool = False) -> int:
    source = source.resolve(strict=True)
    manifest = source / "SHA256SUMS"
    if manifest.is_symlink() or not manifest.is_file():
        raise StageError("kit manifest is missing")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".0sky-kit-", dir=destination.parent))
    count = 0
    staged_lines: list[str] = []
    try:
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            parts = line.split(None, 1)
            if len(parts) != 2 or not re.fullmatch(r"[a-f0-9]{64}", parts[0]):
                raise StageError("kit manifest has an invalid line")
            relative = parts[1].strip().lstrip("*").removeprefix("./")
            if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise StageError("kit manifest path escapes its root")
            if ((release or link_embed) and
                    (Path(relative).name.startswith("test_")
                     or "tests" in Path(relative).parts)):
                continue
            if link_embed and relative == "payloads/0-Sky-Link-1.9.0-universal.ipa":
                continue
            item = source / relative
            if not item.is_file() or source not in item.resolve().parents:
                raise StageError(f"unsafe kit file: {relative}")
            link = os.readlink(item) if item.is_symlink() else None
            if link is not None and (Path(link).is_absolute() or ".." in Path(link).parts):
                raise StageError(f"unsafe kit link: {relative}")
            if digest(item) != parts[0]:
                raise StageError(f"kit digest mismatch: {relative}")
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if link is None:
                shutil.copy2(item, target, follow_symlinks=False)
            else:
                target.symlink_to(link)
            count += 1
            staged_lines.append(parts[0] + "  ./" + relative)
        if count < 10:
            raise StageError("kit manifest is incomplete")
        for link in temporary.rglob("*"):
            if link.is_symlink() and (not link.resolve().exists()
                                      or temporary not in link.resolve().parents):
                raise StageError(f"staged kit link is invalid: {link.relative_to(temporary)}")
        (temporary / "SHA256SUMS").write_text(
            "\n".join(staged_lines) + "\n", encoding="utf-8")
        previous = destination.with_name(destination.name + f".previous.{os.getpid()}")
        if previous.exists():
            raise StageError("previous kit staging directory is already present")
        if destination.exists():
            destination.replace(previous)
        try:
            temporary.replace(destination)
        except Exception:
            if previous.exists():
                previous.replace(destination)
            raise
        if previous.exists():
            shutil.rmtree(previous)
        return count
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--link-embed", action="store_true",
                        help="omit the Link IPA itself and test files from its embedded kit")
    parser.add_argument("--release", action="store_true",
                        help="omit test files and generate a matching release manifest")
    args = parser.parse_args()
    try:
        count = stage(args.source, args.destination, release=args.release,
                      link_embed=args.link_embed)
    except (StageError, OSError) as error:
        print(f"KIT_STAGE=FAIL: {error}")
        return 2
    print(f"KIT_STAGE=PASS FILES={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
