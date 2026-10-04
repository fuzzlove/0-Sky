#!/usr/bin/env python3
"""Read one paired SRD and generate its exact AFC2 compatibility profile."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import re
import shlex
import sys


POC = Path(__file__).resolve().parents[2]
if str(POC) not in sys.path:
    sys.path.insert(0, str(POC))

from compatibility import (MachO64, binary_identity,
                           discover_lockdownd_offset_records)  # noqa: E402
from repair_device_connection import profiles, usb_identity, worker_namespace  # noqa: E402


SAFE_NAME = re.compile(r"^[A-Za-z0-9,._+-]+$")


def atomic_write(path: Path, data: bytes, *, replace: bool) -> None:
    if path.is_symlink():
        raise FileExistsError(f"refusing to replace symbolic link {path}")
    if path.exists() and not replace:
        if path.is_file() and path.read_bytes() == data:
            return
        raise FileExistsError(f"refusing to replace {path} without --replace")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".tmp-" + str(os.getpid()))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_binary(worker: dict, path: str) -> bytes:
    result = worker["ssh"]("cat " + path, timeout=90, check=False)
    if result.returncode:
        raise RuntimeError(
            f"could not read {path}: "
            + result.stderr.decode("utf-8", "replace")[-800:]
        )
    if not 4096 <= len(result.stdout) <= 32 * 1024 * 1024:
        raise RuntimeError(f"unexpected {path} size: {len(result.stdout)}")
    return result.stdout


def read_shared_cache_identity(worker: dict) -> dict:
    code = r'''import ctypes,json,uuid
library=ctypes.CDLL(None)
value=(ctypes.c_ubyte*16)()
get_uuid=library._dyld_get_shared_cache_uuid
get_uuid.argtypes=[ctypes.POINTER(ctypes.c_ubyte)]
get_uuid.restype=ctypes.c_bool
size=ctypes.c_size_t()
get_range=library._dyld_get_shared_cache_range
get_range.argtypes=[ctypes.POINTER(ctypes.c_size_t)]
get_range.restype=ctypes.c_void_p
base=get_range(ctypes.byref(size))
if not get_uuid(value) or not base or not size.value:
 raise RuntimeError('dyld shared cache identity is unavailable')
print(json.dumps({'kind':'process_primary_shared_cache','uuid':str(uuid.UUID(bytes=bytes(value))).upper(),'mapped_size':size.value,'discovery_method':'_dyld_get_shared_cache_uuid and _dyld_get_shared_cache_range'}))
'''
    result = worker["ssh"](
        "/var/jb/usr/bin/python3 -c " + shlex.quote(code),
        timeout=30, check=False,
    )
    if result.returncode:
        raise RuntimeError("could not inventory dyld shared cache: "
                           + result.stderr.decode("utf-8", "replace")[-800:])
    return json.loads(result.stdout.decode("utf-8", "replace"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--inputs-dir", type=Path,
                        default=Path(__file__).resolve().parents[1] / "inputs")
    parser.add_argument("--profiles-dir", type=Path,
                        default=Path(__file__).resolve().parents[1] / "profiles")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    identity = asyncio.run(usb_identity(args.udid))
    for key in ("product", "version", "build"):
        if not isinstance(identity.get(key), str) or not SAFE_NAME.fullmatch(identity[key]):
            raise ValueError(f"unsafe or missing device identity field: {key}")
    selected = profiles(instance_name=args.instance)
    if set(selected) != {args.udid}:
        raise RuntimeError("paired worker profile does not uniquely match the USB UDID")
    worker = worker_namespace(selected[args.udid][1])
    lockdownd_data = read_binary(worker, "/usr/libexec/lockdownd")
    afcd_data = read_binary(worker, "/usr/libexec/afcd")
    shared_cache = read_shared_cache_identity(worker)
    suffix = identity["product"] + "-" + identity["build"]
    lockdownd_path = args.inputs_dir / ("lockdownd-" + suffix)
    afcd_path = args.inputs_dir / ("afcd-" + suffix)
    atomic_write(lockdownd_path, lockdownd_data, replace=args.replace)
    atomic_write(afcd_path, afcd_data, replace=args.replace)
    lockdownd = MachO64(lockdownd_data)
    profile = {
        "schema": 2,
        "status": "discovered",
        "architecture": "arm64e",
        "device": {key: identity[key] for key in ("product", "version", "build")},
        "system_binaries": {
            "/usr/libexec/lockdownd": binary_identity(lockdownd_path),
            "/usr/libexec/afcd": binary_identity(afcd_path),
        },
        "dyld_shared_caches": [shared_cache],
        "offsets": discover_lockdownd_offset_records(lockdownd),
    }
    profile_path = args.profiles_dir / (suffix + ".json")
    atomic_write(
        profile_path,
        (json.dumps(profile, indent=2, sort_keys=True) + "\n").encode(),
        replace=args.replace,
    )
    print(json.dumps({
        "result": "PROFILE_DISCOVERED",
        "profile": str(profile_path),
        "device": profile["device"],
        "system_binaries": profile["system_binaries"],
        "offsets": {name: record["value"]
                    for name, record in profile["offsets"].items()},
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
