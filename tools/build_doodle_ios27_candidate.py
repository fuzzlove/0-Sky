#!/usr/bin/env python3
"""Build the private Doodle iOS 27 source-port candidate twice and compare it.

The output is a signed research dylib, not an installable package. Device
signature acceptance, injection, and lock-screen behavior require separate UAT.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile

if __package__:
    from .build_doodle_ios27_probe import (EXPECTED_ARCHS, PINNED_COMMIT,
        checked_run, ensure_no_symlinks, sha256)
else:
    from build_doodle_ios27_probe import (EXPECTED_ARCHS, PINNED_COMMIT,
        checked_run, ensure_no_symlinks, sha256)


PATCH_SHA256 = "e82810a108649a670c5bb02ca5a74b20ae56a42d0cb1d4de9cd30c6d72d6eec4"


def build(source: Path, theos: Path, patch: Path, artifact: Path) -> dict:
    if not source.is_dir() or not (source / ".git").exists():
        raise ValueError("a local Doodle source checkout is required")
    if checked_run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source) != PINNED_COMMIT:
        raise ValueError("Doodle source commit differs from the reviewed 1.1 revision")
    if checked_run(["/usr/bin/git", "status", "--porcelain"], cwd=source):
        raise ValueError("Doodle source checkout has local changes")
    if not patch.is_file() or sha256(patch) != PATCH_SHA256:
        raise ValueError("Doodle iOS 27 source port patch is not reviewed")
    if not (theos / "makefiles/common.mk").is_file():
        raise ValueError("THEOS does not point to a usable toolchain")
    if artifact.exists() or artifact.is_symlink():
        raise FileExistsError("refusing to replace a prior candidate artifact")
    hashes = []
    with tempfile.TemporaryDirectory(prefix="0sky-doodle-port-") as temporary:
        for attempt in (1, 2):
            work = Path(temporary) / f"build-{attempt}"
            checked_run(["/usr/bin/git", "clone", "--no-hardlinks", "--quiet",
                         str(source), str(work)], timeout=120)
            checked_run(["/usr/bin/git", "checkout", "--detach", "--quiet", PINNED_COMMIT],
                        cwd=work)
            ensure_no_symlinks(work)
            checked_run(["/usr/bin/git", "apply", "--check", str(patch)], cwd=work)
            checked_run(["/usr/bin/git", "apply", str(patch)], cwd=work)
            env = {key: os.environ[key] for key in
                   ("PATH", "DEVELOPER_DIR", "SDKROOT", "LANG") if key in os.environ}
            env.update(THEOS=str(theos), HOME=str(work), TMPDIR=str(work))
            checked_run(["/usr/bin/make", "-j2", "all", "FINALPACKAGE=1", "DEBUG=0",
                         "OSKY_DOODLE_IOS27_ENABLE=1"], cwd=work, env=env, timeout=1200)
            binary = work / ".theos/obj/Doodle.dylib"
            if not binary.is_file() or binary.is_symlink():
                raise ValueError("Doodle candidate dylib is absent")
            archs = set(checked_run(["/usr/bin/lipo", "-archs", str(binary)]).split())
            if archs != EXPECTED_ARCHS:
                raise ValueError("Doodle candidate architecture differs")
            signed = work / "Doodle.ios27.signed.dylib"
            shutil.copy2(binary, signed)
            checked_run(["/usr/bin/codesign", "--force", "--sign", "-",
                         "--timestamp=none", str(signed)], timeout=30)
            checked_run(["/usr/bin/codesign", "--verify", "--strict", str(signed)],
                        timeout=30)
            hashes.append(sha256(signed))
            if attempt == 2:
                artifact.parent.mkdir(parents=True, exist_ok=True)
                staging = artifact.with_name(artifact.name + ".pending")
                shutil.copy2(signed, staging)
        if hashes[0] != hashes[1]:
            staging.unlink(missing_ok=True)
            raise RuntimeError("two clean Doodle source-port builds differ")
        if sha256(staging) != hashes[0]:
            staging.unlink(missing_ok=True)
            raise RuntimeError("candidate changed while staging")
        staging.replace(artifact)
    return {"schema": 1, "component": "com.nahtedetihw.doodle",
            "source_version": "1.1", "source_commit": PINNED_COMMIT,
            "patch_sha256": PATCH_SHA256, "candidate_sha256": hashes[0],
            "architectures": sorted(EXPECTED_ARCHS), "reproducible": True,
            "host_signature": "PASS", "device_signature": "UNVERIFIED",
            "hooks_compiled": True, "device_runtime": "UNVERIFIED",
            "installable_package": False, "repo_admission": "BLOCKED"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--theos", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("refusing to replace a prior build report")
    repo = Path(__file__).resolve().parents[1]
    patch = repo / "tools/patches/doodle-ios27-source-port.patch"
    report = build(args.source.resolve(), args.theos.resolve(), patch,
                   args.artifact.absolute())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    pending = args.report.with_name(args.report.name + ".pending")
    pending.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    pending.replace(args.report)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
