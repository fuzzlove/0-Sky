#!/usr/bin/env python3
"""Remove a redundant [HostKeyAlias]:port record without changing its key pin."""

import argparse
import os
from pathlib import Path
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("alias")
    parser.add_argument("port")
    args = parser.parse_args()
    if args.path.is_symlink() or not args.path.is_file():
        raise RuntimeError("known-hosts pin is not a regular file")
    rows = [row.split() for row in args.path.read_text().splitlines() if row.strip()]
    allowed = {args.alias, f"[{args.alias}]:{args.port}"}
    if not rows or any(len(row) != 3 or row[0] not in allowed for row in rows):
        raise RuntimeError("known-hosts pin contains an unexpected identity")
    keys = {(row[1], row[2]) for row in rows}
    if len(keys) != 1 or not any(row[0] == args.alias for row in rows):
        raise RuntimeError("redundant records do not contain one identical pinned key")
    backup = args.path.with_name(args.path.name + f".before-normalize-{time.time_ns()}")
    backup.write_bytes(args.path.read_bytes())
    os.chmod(backup, 0o600)
    key_type, blob = next(iter(keys))
    temporary = args.path.with_name("." + args.path.name + f".{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(f"{args.alias} {key_type} {blob}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, args.path)
    os.chmod(args.path, 0o600)
    print(f"PIN_NORMALIZED=PASS BACKUP={backup.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
