#!/usr/bin/env python3
"""Create a stable ZIP/IPA from already finalized, signed input files."""
from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
import shutil
import stat
import zipfile


DEFAULT_EPOCH = 946684800  # 2000-01-01 UTC; supported by ZIP timestamps.


def build(source: Path, output: Path, epoch: int = DEFAULT_EPOCH) -> None:
    source = source.resolve(strict=True)
    if source in output.resolve().parents:
        raise ValueError("archive output must be outside its input tree")
    if epoch < 315532800 or epoch > 4354819199:
        raise ValueError("SOURCE_DATE_EPOCH is outside the ZIP timestamp range")
    timestamp = dt.datetime.fromtimestamp(epoch, dt.timezone.utc)
    date = (timestamp.year, timestamp.month, timestamp.day,
            timestamp.hour, timestamp.minute, timestamp.second // 2 * 2)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", allowZip64=True) as archive:
        for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
            relative = path.relative_to(source).as_posix()
            mode = path.lstat().st_mode
            is_dir = stat.S_ISDIR(mode)
            info = zipfile.ZipInfo(relative + ("/" if is_dir else ""), date_time=date)
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_STORED if is_dir or path.is_symlink() else zipfile.ZIP_DEFLATED
            if is_dir:
                archive.writestr(info, b"")
            elif path.is_symlink():
                target = os.readlink(path)
                if Path(target).is_absolute() or ".." in Path(target).parts:
                    raise ValueError("archive input contains unsafe symlink")
                resolved = path.resolve(strict=True)
                if source not in resolved.parents:
                    raise ValueError("archive input symlink escapes its root")
                archive.writestr(info, target.encode("utf-8"))
            else:
                with path.open("rb") as incoming, archive.open(info, "w") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", DEFAULT_EPOCH))
    build(args.source, args.output, epoch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
