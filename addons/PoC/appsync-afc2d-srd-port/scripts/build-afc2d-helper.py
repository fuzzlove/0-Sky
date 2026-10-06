#!/usr/bin/env python3
"""Derive an AFC2 helper from the exact iOS 27 afcd on the target SRD."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


MEDIA_ROOT = b"/private/var/mobile/Media\0"
FULL_ROOT = b"/\0" + b"\0" * (len(MEDIA_ROOT) - 2)
SYSTEM_XPC_SERVICE = b"com.apple.afcd\0"
# lockdownd's iOS 27 sandbox permits the lockdown.* Mach-service namespace.
# The extra NUL keeps this in-place rewrite the same size as the source string.
AFC2_XPC_SERVICE = b"lockdown.afc2\0\0"
RESTRICT_SEGMENT = b"__RESTRICT" + b"\0" * 6
RESTRICT_SECTION = b"__restrict" + b"\0" * 6
AFC2_SEGMENT = b"__0SKY" + b"\0" * 10
AFC2_SECTION = b"__0sky" + b"\0" * 10


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    source = args.source.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    if digest != args.expected_sha256.lower():
        raise ValueError(f"unexpected system afcd SHA-256: {digest}")
    if source.count(MEDIA_ROOT) != 1:
        raise ValueError("expected exactly one compiled-in AFC media root")
    if source.count(SYSTEM_XPC_SERVICE) != 2:
        raise ValueError("expected exactly two compiled-in system AFC XPC service names")
    if source.count(RESTRICT_SEGMENT) != 2 or source.count(RESTRICT_SECTION) != 1:
        raise ValueError("unexpected __RESTRICT load-command layout")

    patched = source.replace(MEDIA_ROOT, FULL_ROOT).replace(
        SYSTEM_XPC_SERVICE, AFC2_XPC_SERVICE
    ).replace(RESTRICT_SEGMENT, AFC2_SEGMENT).replace(
        RESTRICT_SECTION, AFC2_SECTION
    )
    if (len(patched) != len(source) or MEDIA_ROOT in patched
            or SYSTEM_XPC_SERVICE in patched or RESTRICT_SEGMENT in patched
            or RESTRICT_SECTION in patched):
        raise ValueError("in-place AFC root/XPC/restriction rewrite failed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    args.output.chmod(0o755)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
