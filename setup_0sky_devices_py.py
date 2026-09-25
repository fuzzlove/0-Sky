#!/usr/bin/env python3
"""Compatibility entry point for the exact-device 0-Sky host installer."""
from pathlib import Path
import subprocess
import sys


def main() -> int:
    setup = Path(__file__).resolve().parent / "bridge/macos_host_setup.py"
    return subprocess.call([sys.executable, str(setup), "--setup", *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
