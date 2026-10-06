#!/usr/bin/env python3
"""Bind exact locally built package bytes to a compatibility profile."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from compatibility import validate_profile


def field(package: Path, name: str) -> str:
    result = subprocess.run(
        ["dpkg-deb", "--field", str(package), name],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def describe(package: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="0sky-profile-package-") as temporary:
        root = Path(temporary)
        subprocess.run(
            ["dpkg-deb", "--raw-extract", str(package), str(root)],
            capture_output=True, check=True,
        )
        files = {}
        payload = root / "var/jb"
        if not payload.is_dir():
            raise ValueError(f"package has no rootless /var/jb payload: {package}")
        for path in sorted(payload.rglob("*")):
            if path.is_file() and not path.is_symlink():
                relative = "/" + path.relative_to(root).as_posix()
                files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "package": field(package, "Package"),
        "installable": True,
        "version": field(package, "Version"),
        "filename": package.name,
        "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
        "files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("packages", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    output = args.output or args.profile
    if output != args.profile and (output.exists() or output.is_symlink()) and not args.replace:
        raise FileExistsError("refusing to replace output without --replace")
    profile = json.loads(args.profile.read_text())
    validate_profile(profile)
    if profile.get("schema") != 2 or profile.get("status") != "reviewed":
        raise ValueError("packages may only be bound to a reviewed schema-2 profile")
    packages = [describe(path.resolve(strict=True)) for path in args.packages]
    identifiers = [item["package"] for item in packages]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate package identifiers")
    profile["packages"] = packages
    encoded = (json.dumps(profile, indent=2, sort_keys=True) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name("." + output.name + ".tmp-" + str(os.getpid()))
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    print(json.dumps({"result": "PACKAGES_BOUND", "profile": str(output),
                      "packages": identifiers}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
