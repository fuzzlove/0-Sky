#!/usr/bin/env python3
"""Generate an exact-binary AFC2 compatibility profile."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from compatibility import (MachO64, binary_identity,
                           discover_lockdownd_offset_records)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--lockdownd", required=True, type=Path)
    parser.add_argument("--afcd", required=True, type=Path)
    parser.add_argument("--shared-cache-uuid", required=True)
    parser.add_argument("--shared-cache-size", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reviewed", action="store_true",
                        help="mark a separately reviewed result as buildable")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    if (args.output.exists() or args.output.is_symlink()) and not args.replace:
        raise FileExistsError("refusing to replace an existing profile without --replace")
    lockdownd = MachO64.read(args.lockdownd)
    profile = {
        "schema": 2,
        "status": "reviewed" if args.reviewed else "discovered",
        "architecture": "arm64e",
        "device": {
            "product": args.product,
            "version": args.version,
            "build": args.build,
        },
        "system_binaries": {
            "/usr/libexec/lockdownd": binary_identity(args.lockdownd),
            "/usr/libexec/afcd": binary_identity(args.afcd),
        },
        "dyld_shared_caches": [{
            "kind": "process_primary_shared_cache",
            "uuid": args.shared_cache_uuid.upper(),
            "mapped_size": args.shared_cache_size,
            "discovery_method": "_dyld_get_shared_cache_uuid and "
                                "_dyld_get_shared_cache_range",
        }],
        "offsets": discover_lockdownd_offset_records(lockdownd),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"result": "PROFILE_GENERATED", "profile": str(args.output),
                      "status": profile["status"],
                      "offsets": {name: record["value"]
                                  for name, record in profile["offsets"].items()}},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
