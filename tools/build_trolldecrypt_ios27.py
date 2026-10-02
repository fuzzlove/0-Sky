#!/usr/bin/env python3
"""Build the reviewed 0-Sky TrollDecrypt Cryptex discovery adaptation.

The upstream checkout is disposable. The adaptation lives only in the
reviewed patch, and the original TrollDecrypt installation is not replaced.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

from deterministic_zip import build as build_zip


UPSTREAM = "https://github.com/donato-fiore/TrollDecrypt.git"
REVISION = "c4bd8c1b7efd248068fb82d7efacbf9d98a9ccf7"
PATCH = Path(__file__).resolve().parent / "patches/trolldecrypt-ios27-discovery.patch"
PATCH_SHA256 = "2f8f42e73107e6b43a0e0e67d378680b133d37898a0af2905ac0554b16ef1486"
BUNDLE_ID = "com.liquidsky.TrollDecryptResearch"


def run(arguments: list[str], *, cwd: Path | None = None,
        env: dict[str, str] | None = None, timeout: int = 900) -> str:
    result = subprocess.run(arguments, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout, check=False)
    if result.returncode:
        error = re.sub(r"https?://[^/@\s]+:[^/@\s]+@", "https://<redacted>@",
                       result.stderr[-1200:])
        error = re.sub(r"/Users/[^/\s]+", "/Users/<redacted>", error)
        error = re.sub(r"(?i)(token|password|secret)=\S+", r"\1=<redacted>", error)
        raise RuntimeError(f"{Path(arguments[0]).name} failed ({result.returncode}): "
                           + error)
    return result.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_source(source: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError("source checkout is absent or symbolic")
    if run(["git", "rev-parse", "HEAD"], cwd=source) != REVISION:
        raise RuntimeError("TrollDecrypt source is not the reviewed commit")
    origin = run(["git", "remote", "get-url", "origin"], cwd=source)
    if origin.rstrip("/") not in {UPSTREAM, UPSTREAM.removesuffix(".git")}:
        raise RuntimeError("TrollDecrypt source is not the reviewed upstream")
    if run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=source):
        raise RuntimeError("TrollDecrypt source has unreviewed edits")


def build(source: Path | None, theos: Path, output: Path) -> dict:
    if sha256(PATCH) != PATCH_SHA256:
        raise RuntimeError("0-Sky adaptation patch hash changed")
    theos = theos.expanduser().resolve(strict=True)
    if not (theos / "makefiles/common.mk").is_file():
        raise RuntimeError("THEOS does not contain makefiles/common.mk")
    output = output.expanduser().resolve()
    if output.suffix.lower() not in {".ipa", ".tipa"}:
        raise ValueError("output must end in .ipa or .tipa")
    if output.exists() or output.is_symlink():
        raise FileExistsError("output artifact already exists")
    if output.with_suffix(output.suffix + ".json").exists():
        raise FileExistsError("output receipt already exists")
    with tempfile.TemporaryDirectory(prefix="0sky-trolldecrypt-build-") as temporary:
        workspace = Path(temporary)
        checkout = workspace / "source"
        if source is None:
            run(["git", "clone", "--quiet", UPSTREAM, str(checkout)], timeout=300)
            run(["git", "checkout", "--quiet", "--detach", REVISION], cwd=checkout)
            verify_source(checkout)
        else:
            source = source.expanduser()
            if source.is_symlink():
                raise RuntimeError("source checkout is symbolic")
            source = source.resolve(strict=True)
            verify_source(source)
            run(["git", "clone", "--quiet", "--no-hardlinks", str(source),
                 str(checkout)], timeout=300)
            run(["git", "checkout", "--quiet", "--detach", REVISION], cwd=checkout)
        run(["git", "apply", "--check", str(PATCH)], cwd=checkout)
        run(["git", "apply", str(PATCH)], cwd=checkout)
        environment = os.environ.copy()
        environment["THEOS"] = str(theos)
        environment["PACKAGE_TIPA"] = "0"
        run(["make", "package"], cwd=checkout, env=environment)
        app = checkout / ".theos/_/var/jb/Applications/TrollDecrypt.app"
        if app.is_symlink() or not app.is_dir():
            raise RuntimeError("Theos did not stage the expected app")
        info = plistlib.loads((app / "Info.plist").read_bytes())
        if (info.get("CFBundleIdentifier") != BUNDLE_ID or
                info.get("0SkyAdaptation") != "ios27-cryptex-discovery-1" or
                info.get("CFBundleVersion") != "1.2.4.1"):
            raise RuntimeError("staged app identity does not match the adaptation")
        executable = app / info["CFBundleExecutable"]
        if not executable.is_file() or set(run(["lipo", "-archs", str(executable)]).split()) != {"arm64", "arm64e"}:
            raise RuntimeError("staged app lacks the required iOS architectures")
        for framework in sorted((app / "Frameworks").glob("*.framework")):
            run(["codesign", "--force", "--sign", "-", "--timestamp=none",
                 "--generate-entitlement-der", str(framework)])
        run(["codesign", "--force", "--sign", "-", "--timestamp=none",
             "--generate-entitlement-der", "--entitlements",
             str(checkout / "TrollDecrypt.entitlements"), str(app)])
        run(["codesign", "--verify", "--deep", "--strict", str(app)])
        stage = workspace / "ipa/Payload"
        stage.mkdir(parents=True)
        shutil.copytree(app, stage / app.name, symlinks=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        build_zip(stage.parent, output)
    receipt = {"upstream": UPSTREAM, "revision": REVISION,
               "adaptation_patch_sha256": PATCH_SHA256, "bundle_id": BUNDLE_ID,
               "version": "1.2.4.1", "architectures": ["arm64", "arm64e"],
               "artifact_sha256": sha256(output), "artifact_size": output.stat().st_size,
               "signature": "ad-hoc; SRD worker signs and verifies for the target device"}
    output.with_suffix(output.suffix + ".json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path,
                        help="clean local checkout of the pinned upstream commit")
    parser.add_argument("--theos", type=Path,
                        default=Path(os.environ.get("THEOS", "")),
                        help="Theos root, or set THEOS")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if str(args.theos) == ".":
        parser.error("--theos or THEOS is required")
    print(json.dumps(build(args.source, args.theos, args.output), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
