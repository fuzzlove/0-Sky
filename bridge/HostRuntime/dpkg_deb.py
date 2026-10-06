#!/usr/bin/env python3
"""Bounded dpkg-deb compatibility for verified package read, extract, and build."""
from __future__ import annotations
import bz2, gzip, importlib, io, lzma, os, pathlib, stat, subprocess, sys, tarfile, tempfile

MAX_PACKAGE_SIZE = 1024 * 1024 * 1024
MAX_BUILD_FILE_SIZE = 256 * 1024 * 1024
MAX_EXPANDED_ARCHIVE_SIZE = 4 * 1024 * 1024 * 1024
COPY_CHUNK_SIZE = 1024 * 1024


def _copy_bounded(source, destination) -> None:
    """Copy a decompressed tar stream with a hard expanded-size ceiling."""
    total = 0
    while True:
        block = source.read(COPY_CHUNK_SIZE)
        if not block:
            return
        total += len(block)
        if total > MAX_EXPANDED_ARCHIVE_SIZE:
            raise RuntimeError("Debian payload expands beyond the 4 GiB safety limit")
        destination.write(block)


def _write_uncompressed_tar(blob: bytes, destination) -> None:
    """Materialize supported Debian tar compression without external tools."""
    try:
        if blob.startswith(b"\x28\xb5\x2f\xfd"):
            try:
                zstandard = importlib.import_module("zstandard")
            except ImportError as error:
                raise RuntimeError(
                    "Zstandard support is missing from the managed 0-Sky Python "
                    "environment. In 0-Sky Bridge, choose Repair, run Repair Host "
                    "Dependencies, then Resume. The signed release includes the "
                    "required offline zstandard wheel; Homebrew is not required."
                ) from error
            try:
                with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(blob)) as reader:
                    _copy_bounded(reader, destination)
            except RuntimeError:
                raise
            except zstandard.ZstdError as error:
                raise RuntimeError("Debian Zstandard payload decompression failed") from error
        elif blob.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(blob), mode="rb") as reader:
                _copy_bounded(reader, destination)
        elif blob.startswith(b"\xfd7zXZ\x00"):
            with lzma.LZMAFile(io.BytesIO(blob), mode="rb") as reader:
                _copy_bounded(reader, destination)
        elif blob.startswith(b"BZh"):
            with bz2.BZ2File(io.BytesIO(blob), mode="rb") as reader:
                _copy_bounded(reader, destination)
        else:
            if len(blob) > MAX_EXPANDED_ARCHIVE_SIZE:
                raise RuntimeError("Debian payload exceeds the 4 GiB safety limit")
            destination.write(blob)
    except RuntimeError:
        raise
    except (EOFError, OSError, ValueError) as error:
        raise RuntimeError("Debian payload decompression failed") from error


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
        _write_uncompressed_tar(blob, stream); stream.flush()
        listing=subprocess.run(["/usr/bin/bsdtar","-tf",stream.name],capture_output=True,
                               text=True,timeout=60,check=False)
        if listing.returncode:
            detail=(listing.stderr or listing.stdout).strip()[-2048:]
            raise RuntimeError("bsdtar could not list Debian payload" +
                               (f": {detail}" if detail else ""))
        for raw in listing.stdout.splitlines():
            path=pathlib.PurePosixPath(raw.removeprefix("./"))
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("Debian payload contains an unsafe path")
        result=subprocess.run(["/usr/bin/bsdtar","--no-same-owner","--no-same-permissions",
                               "-xf",stream.name,"-C",str(destination)],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, timeout=120, check=False)
    if result.returncode:
        detail=result.stderr.decode("utf-8","replace").strip()[-2048:]
        raise RuntimeError("bsdtar could not extract Debian payload" +
                           (f": {detail}" if detail else ""))
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


def archive_member(name: str, payload: bytes, epoch: int) -> bytes:
    """Create one deterministic System V ar member."""
    encoded=(name+"/").encode("ascii")
    if len(encoded)>16: raise ValueError("ar member name is too long")
    header=(encoded.ljust(16,b" ") + str(epoch).encode("ascii").ljust(12,b" ")
            + b"0".ljust(6,b" ") + b"0".ljust(6,b" ")
            + b"100644".ljust(8,b" ") + str(len(payload)).encode("ascii").ljust(10,b" ")
            + b"`\n")
    if len(header)!=60: raise ValueError("invalid ar header")
    return header+payload+(b"\n" if len(payload)%2 else b"")


def normalized_tar(root: pathlib.Path, *, exclude_debian: bool, epoch: int) -> bytes:
    """Archive a package subtree without host ownership, timestamps, or traversal."""
    if root.is_symlink() or not root.is_dir(): raise ValueError("package root is not a directory")
    output=io.BytesIO()
    with gzip.GzipFile(filename="",mode="wb",fileobj=output,mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed,mode="w",format=tarfile.GNU_FORMAT) as bundle:
            for path in sorted(root.rglob("*"),key=lambda item:item.relative_to(root).as_posix()):
                relative=path.relative_to(root)
                if exclude_debian and relative.parts[0]=="DEBIAN": continue
                if not exclude_debian and relative.parts[0]=="DEBIAN":
                    relative=path.relative_to(root/"DEBIAN")
                    if not relative.parts: continue
                elif not exclude_debian:
                    continue
                observed=path.lstat(); info=tarfile.TarInfo("./"+relative.as_posix())
                info.uid=info.gid=0; info.uname=info.gname="root"; info.mtime=epoch
                info.mode=stat.S_IMODE(observed.st_mode)&0o777
                if stat.S_ISDIR(observed.st_mode):
                    info.type=tarfile.DIRTYPE; info.size=0; bundle.addfile(info)
                elif stat.S_ISREG(observed.st_mode):
                    if observed.st_size>MAX_BUILD_FILE_SIZE:
                        raise ValueError("package input exceeds the 256 MiB per-file safety limit")
                    info.type=tarfile.REGTYPE; info.size=observed.st_size
                    with path.open("rb") as stream: bundle.addfile(info,stream)
                elif stat.S_ISLNK(observed.st_mode):
                    target=os.readlink(path); pure=pathlib.PurePosixPath(target)
                    if pure.is_absolute() or ".." in pure.parts:
                        raise ValueError("package input contains an unsafe symbolic link")
                    resolved=(path.parent/pathlib.Path(target)).resolve(strict=False)
                    if resolved != root and root not in resolved.parents:
                        raise ValueError("package input symbolic link escapes its root")
                    info.type=tarfile.SYMTYPE; info.linkname=target; info.size=0; bundle.addfile(info)
                else:
                    raise ValueError("package input contains an unsupported file type")
    return output.getvalue()


def build_package(root: pathlib.Path, destination: pathlib.Path) -> None:
    """Build the exact Debian subset needed by 0-Sky's offline runtime."""
    if root.is_symlink(): raise ValueError("package root is a symbolic link")
    root=root.resolve(strict=True)
    control=root/"DEBIAN/control"
    if control.is_symlink() or not control.is_file():
        raise ValueError("package control file is missing")
    fields=control_fields(normalized_tar(root,exclude_debian=False,epoch=0))
    for required in ("Package","Version","Architecture","Description"):
        if not fields.get(required): raise ValueError(f"package control field is missing: {required}")
    try: epoch=int(os.environ.get("SOURCE_DATE_EPOCH","0"))
    except ValueError as error: raise ValueError("SOURCE_DATE_EPOCH is invalid") from error
    if epoch<0 or epoch>9_999_999_999: raise ValueError("SOURCE_DATE_EPOCH is out of range")
    control_archive=normalized_tar(root,exclude_debian=False,epoch=epoch)
    data_archive=normalized_tar(root,exclude_debian=True,epoch=epoch)
    package=(b"!<arch>\n"+archive_member("debian-binary",b"2.0\n",epoch)
             +archive_member("control.tar.gz",control_archive,epoch)
             +archive_member("data.tar.gz",data_archive,epoch))
    if len(package)>MAX_PACKAGE_SIZE: raise ValueError("built Debian package exceeds 1 GiB")
    destination.parent.mkdir(parents=True,exist_ok=True)
    descriptor,temporary=tempfile.mkstemp(prefix="."+destination.name+".",dir=destination.parent)
    try:
        with os.fdopen(descriptor,"wb") as stream:
            stream.write(package); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary,0o644); os.replace(temporary,destination)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def main(argv: list[str]) -> int:
    if argv == ["--version"]:
        print("0-Sky dpkg-deb compatibility 1.2")
        return 0
    if len(argv)==4 and argv[:2]==["--root-owner-group","-b"]:
        build_package(pathlib.Path(argv[2]),pathlib.Path(argv[3])); return 0
    if len(argv) not in {2,3} or argv[0] not in {"-x","--extract","-f","--field"}:
        print("usage: dpkg-deb [--root-owner-group -b ROOT OUTPUT] | "
              "{-x|--extract|-f|--field} PACKAGE [DESTINATION|FIELD]",
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
