#!/usr/bin/env python3
"""Install the pinned Mac requirements from the kit without network indexes."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def offline_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update({
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_REQUIRE_VIRTUALENV": "1",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
    })
    return environment


def verify(kit: Path, python: Path) -> str:
    wheelhouse = kit / "host-mac/wheelhouse"
    requirements = kit / "host-mac/requirements-lock.txt"
    if not wheelhouse.is_dir() or not requirements.is_file():
        return "OFFLINE_INPUT_MISSING"
    with tempfile.TemporaryDirectory(prefix="0sky-offline-install-") as folder:
        venv = Path(folder) / "venv"
        try:
            create = subprocess.run([str(python), "-m", "venv", str(venv)],
                                    capture_output=True, timeout=120, check=False)
            if create.returncode:
                return "VENV_CREATION_FAILED"
            managed = venv / "bin/python3"
            install = subprocess.run([
                str(managed), "-m", "pip", "install", "--isolated", "--no-index",
                "--find-links", str(wheelhouse), "--requirement", str(requirements),
            ], env=offline_environment(), capture_output=True, timeout=600, check=False)
            if install.returncode:
                return "OFFLINE_PIP_INSTALL_FAILED"
            check = subprocess.run([str(managed), "-m", "pip", "check"],
                                   env=offline_environment(), capture_output=True,
                                   timeout=60, check=False)
            if check.returncode:
                return "OFFLINE_DEPENDENCY_CONFLICT"
            import_check = subprocess.run([
                str(managed), "-c", "import pymobiledevice3,zstandard,Crypto,pydantic_core._pydantic_core"
            ], env=offline_environment(), capture_output=True, timeout=30, check=False)
            if import_check.returncode:
                return "OFFLINE_IMPORT_FAILED"
        except (OSError, subprocess.TimeoutExpired):
            return "OFFLINE_INSTALL_TIMEOUT_OR_TOOL_ERROR"
    return "PASS"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kit", type=Path)
    parser.add_argument("--python", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.kit, args.python)
    print(f"OFFLINE_INSTALL={result}")
    return 0 if result == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
