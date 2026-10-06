#!/usr/bin/env python3
"""Validate the locked Theos source-build input without modifying it."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "manifests/source-dependencies.json"


class TheosError(RuntimeError):
    def __init__(self, code: str, detail: str, remediation: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.remediation = remediation


THEOS_INSTALL = (
    "Create a new locked Theos checkout (do not overwrite an existing checkout):\n"
    "  git clone --recursive https://github.com/theos/theos.git '/absolute/path/to/theos'\n"
    "  git -C '/absolute/path/to/theos' checkout dd5c14bb9d91311e221d51b5bfb8c9e5948156db\n"
    "  git -C '/absolute/path/to/theos' submodule update --init --recursive\n"
    "Then rerun the build with: --theos '/absolute/path/to/theos'"
)


def failure(code: str, detail: str, remediation: str) -> TheosError:
    return TheosError(code, detail, remediation)


def command(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        name = Path(argv[0]).name
        action = ("Install Apple's Command Line Tools by running `xcode-select --install`, "
                  "finish the installer, and verify `git --version`." if name == "git" else
                  f"Confirm `{name}` is executable and on PATH, run `{name} --version`, then rerun preflight.")
        raise failure(
            "TOOL_EXECUTION_FAILED", f"unable to execute {name}",
            action,
        ) from error
    if result.returncode:
        name = Path(argv[0]).name
        raise failure(
            "TOOL_RETURNED_ERROR", f"{name} returned {result.returncode}",
            f"Run `{name} --version` and correct the reported installation error before retrying."
        )
    return result.stdout.rstrip()


def succeeds(argv: list[str]) -> bool:
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def output_if_success(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.rstrip() if result.returncode == 0 else ""


def verify(theos: Path) -> dict[str, object]:
    try:
        theos = theos.expanduser().resolve(strict=True)
    except OSError as error:
        raise failure("THEOS_NOT_FOUND", f"Theos directory is unavailable: {theos}",
                      THEOS_INSTALL) from error
    lock = json.loads(LOCK.read_text(encoding="utf-8"))["theos"]
    if not (theos / "makefiles/common.mk").is_file():
        raise failure("THEOS_INCOMPLETE", "makefiles/common.mk is missing", THEOS_INSTALL)
    head = command(["git", "-C", str(theos), "rev-parse", "HEAD"])
    if head != lock["commit"]:
        raise failure(
            "THEOS_REVISION_MISMATCH",
            "Theos revision differs from manifests/source-dependencies.json",
            "Preserve the current checkout if it contains work. Create a separate locked checkout:\n"
            + THEOS_INSTALL,
        )
    status = command(["git", "-C", str(theos), "status", "--porcelain", "--untracked-files=no"])
    if status:
        raise failure(
            "THEOS_MODIFIED", "Theos checkout has tracked modifications",
            "Do not discard those edits automatically. Use `git -C '/path/to/theos' status`, "
            "preserve or commit the work, then build from a separate clean checkout at the locked revision.",
        )
    observed: dict[str, str] = {}
    for row in command(["git", "-C", str(theos), "submodule", "status", "--recursive"]).splitlines():
        if not row or row[0] != " ":
            raise failure(
                "THEOS_SUBMODULE_INVALID", "Theos submodule is absent, modified, or conflicted",
                "From a clean checkout at the locked revision run: `git -C '/path/to/theos' "
                "submodule update --init --recursive`, then rerun preflight.",
            )
        fields = row[1:].split()
        if len(fields) < 2:
            raise failure("THEOS_SUBMODULE_INVALID", "invalid Theos submodule inventory",
                          "Create a new checkout using the locked Theos commands printed above.")
        observed[fields[1]] = fields[0]
    if observed != lock["submodules"]:
        raise failure(
            "THEOS_SUBMODULE_REVISION_MISMATCH",
            "Theos submodule revisions differ from the dependency lock",
            "Create a separate clean checkout with `git clone --recursive`, check out the locked "
            "commit, and run `git submodule update --init --recursive`; do not force-reset a working checkout.",
        )
    tool_actions = {
        "xcrun": ("Install full Xcode from the Mac App Store or Apple Developer downloads, then run: "
                  "`sudo xcode-select -s /Applications/Xcode.app/Contents/Developer` and "
                  "`sudo xcodebuild -license accept`."),
        "make": ("Install Apple's Command Line Tools by running `xcode-select --install`, finish the "
                 "installer, then run `make --version`."),
        "ldid": "After installing Homebrew from https://brew.sh, run: `brew install ldid`.",
        "pkg-config": "After installing Homebrew from https://brew.sh, run: `brew install pkgconf`.",
    }
    for tool, action in tool_actions.items():
        if not shutil.which(tool):
            raise failure("TOOL_MISSING", f"required source-build tool is missing: {tool}", action)
    if not succeeds(["pkg-config", "--exists", "openssl"]):
        raise failure(
            "OPENSSL_NOT_RESOLVED", "pkg-config cannot resolve OpenSSL",
            "Run `brew install openssl@3 pkgconf`, then export "
            "`PKG_CONFIG_PATH=\"$(brew --prefix openssl@3)/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}\"` "
            "in the same terminal and rerun preflight.",
        )
    prefix = os.environ.get("LIBARCHIVE_PREFIX", "")
    if not prefix and shutil.which("brew"):
        prefix = output_if_success(["brew", "--prefix", "libarchive"])
    if not prefix or not (Path(prefix) / "include/archive.h").is_file():
        raise failure(
            "LIBARCHIVE_NOT_RESOLVED",
            "LIBARCHIVE_PREFIX does not name a libarchive development prefix containing include/archive.h",
            "Run `brew install libarchive`, then in the same terminal run "
            "`export LIBARCHIVE_PREFIX=\"$(brew --prefix libarchive)\"` and rerun preflight.",
        )
    sdk = command(["xcrun", "--sdk", "iphoneos", "--show-sdk-version"])
    return {"status": "PASS", "theos_commit": head,
            "submodules": len(observed), "iphoneos_sdk": sdk}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--theos", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.theos)
    except TheosError as error:
        print(f"THEOS_PREFLIGHT=FAIL code={error.code} detail={error.detail}")
        print("REQUIRED_ACTION:")
        for line in error.remediation.splitlines():
            print(f"  {line}")
        return 2
    except (OSError, ValueError, KeyError) as error:
        print(f"THEOS_PREFLIGHT=FAIL code=INVALID_LOCK detail={error}")
        print("REQUIRED_ACTION:")
        print("  Restore manifests/source-dependencies.json from the audited repository revision and retry.")
        return 2
    print("THEOS_PREFLIGHT=PASS " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
