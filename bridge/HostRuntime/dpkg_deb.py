#!/usr/bin/env python3
"""Bounded dpkg-deb compatibility for extracting or reading verified packages."""
from __future__ import annotations
import os, pathlib, subprocess, sys, tempfile

MAX_PACKAGE_SIZE = 1024 * 1024 * 1024


def members(path: pathlib.Path) -> dict[str, bytes]:
    if path.stat().st_size > MAX_PACKAGE_SIZE:
        raise ValueError("Debian package exceeds the 1 GiB safety limit")
    data=path.read_bytes()
    if not data.startswith(b"!<arch>\n"): raise ValueError("not a Debian ar archive")
    result={}; offset=8
    while offset < len(data):
        if offset+60>len(data): raise ValueError("truncated ar header")
        header=data[offset:offset+60]; offset+=60
        if header[58:60] != b"`\n": raise ValueError("invalid ar header")
        name=header[:16].decode("ascii").strip().rstrip("/")
        size=int(header[48:58].decode("ascii").strip())
        if size<0 or offset+size>len(data): raise ValueError("invalid ar member")
        if name in result or size > 2 * 1024 * 1024 * 1024:
            raise ValueError("duplicate or oversized ar member")
        result[name]=data[offset:offset+size]; offset += size + size%2
    return result


def extract_archive(blob: bytes, destination: pathlib.Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="0sky-deb-", suffix=".tar", delete=True) as stream:
        stream.write(blob); stream.flush()
        listing=subprocess.run(["/usr/bin/bsdtar","-tf",stream.name],capture_output=True,
                               text=True,timeout=60,check=False)
        if listing.returncode: raise RuntimeError("bsdtar could not list Debian payload")
        for raw in listing.stdout.splitlines():
            path=pathlib.PurePosixPath(raw.removeprefix("./"))
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("Debian payload contains an unsafe path")
        result=subprocess.run(["/usr/bin/bsdtar","--no-same-owner","--no-same-permissions",
                               "-xf",stream.name,"-C",str(destination)],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, timeout=120, check=False)
    if result.returncode: raise RuntimeError("bsdtar could not extract Debian payload")
    root=destination.resolve()
    for path in destination.rglob("*"):
        if path.is_symlink():
            target=(path.parent/pathlib.Path(os.readlink(path))).resolve()
            if target != root and root not in target.parents:
                raise RuntimeError("Debian payload contains an escaping symbolic link")


def control_fields(blob: bytes) -> dict[str,str]:
    with tempfile.TemporaryDirectory(prefix="0sky-control-") as folder:
        root=pathlib.Path(folder); extract_archive(blob,root)
        text=(root/"control").read_text(encoding="utf-8")
    answer={}
    for line in text.splitlines():
        if line and not line[0].isspace() and ":" in line:
            key,value=line.split(":",1); answer[key]=value.strip()
    return answer


def main(argv: list[str]) -> int:
    if argv == ["--version"]:
        print("0-Sky dpkg-deb compatibility 1.0")
        return 0
    if len(argv) not in {2,3} or argv[0] not in {"-x","--extract","-f","--field"}:
        print("usage: dpkg-deb {-x|--extract|-f|--field} PACKAGE [DESTINATION|FIELD]",
              file=sys.stderr); return 64
    operation, package = argv[0], pathlib.Path(argv[1])
    argument = argv[2] if len(argv) == 3 else None
    archive=members(package)
    if operation in ("-x","--extract"):
        if not argument: raise ValueError("extraction destination is required")
        key=next((k for k in archive if k.startswith("data.tar")),None)
        if not key: raise ValueError("Debian data archive is missing")
        extract_archive(archive[key],pathlib.Path(argument)); return 0
    key=next((k for k in archive if k.startswith("control.tar")),None)
    if not key: raise ValueError("Debian control archive is missing")
    fields=control_fields(archive[key])
    if argument:
        if argument not in fields: return 1
        print(fields[argument])
    else:
        for key in sorted(fields): print(f"{key}: {fields[key]}")
    return 0

if __name__ == "__main__":
    try: raise SystemExit(main(sys.argv[1:]))
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        print(f"dpkg-deb: {error}",file=sys.stderr); raise SystemExit(2)
