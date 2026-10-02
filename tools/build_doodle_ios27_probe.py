#!/usr/bin/env python3
"""Rebuild the pinned Doodle 1.1 source as a non-installable iOS 27 probe.

This command deliberately emits evidence, not a package or repository artifact.
No hook in this build is active on iOS 17 or later.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


PINNED_COMMIT = "a364b0cdcae3198336eee16e62ca56b3f540cc18"
PATCH_SHA256 = "42387e4778e7cdb89d418b54c0094e45f3ea4bc8b8c1473c0134b21685dbe43d"
EXPECTED_ARCHS = {"arm64", "arm64e"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_run(argv: list[str], *, cwd: Path | None = None,
                env: dict[str, str] | None = None, timeout: int = 120) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout, check=False)
    if result.returncode:
        # Tool stderr may contain local paths or credentials. Keep only the stage.
        raise RuntimeError(f"{Path(argv[0]).name} exited {result.returncode}")
    return result.stdout.strip()


def validate_source(source: Path, patch: Path, theos: Path) -> None:
    if not source.is_dir() or not (source / ".git").exists():
        raise ValueError("a local Doodle source checkout is required")
    if checked_run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source) != PINNED_COMMIT:
        raise ValueError("Doodle checkout does not match the reviewed 1.1 commit")
    if checked_run(["/usr/bin/git", "status", "--porcelain"], cwd=source):
        raise ValueError("Doodle checkout has local changes")
    if not patch.is_file() or sha256(patch) != PATCH_SHA256:
        raise ValueError("Doodle port patch does not match the reviewed hash")
    if not (theos / "makefiles" / "common.mk").is_file():
        raise ValueError("THEOS does not point to a usable toolchain")


def ensure_no_symlinks(root: Path) -> None:
    if any(item.is_symlink() for item in root.rglob("*")):
        raise ValueError("source checkout contains a symbolic link")


def build_probe(source: Path, patch: Path, theos: Path) -> dict:
    validate_source(source, patch, theos)
    hashes = []
    adhoc_hashes = []
    archs = []
    signatures = []
    with tempfile.TemporaryDirectory(prefix="0sky-doodle-probe-") as temporary:
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
            checked_run(["/usr/bin/make", "-j2", "all", "FINALPACKAGE=1", "DEBUG=0"],
                        cwd=work, env=env, timeout=1200)
            binary = work / ".theos" / "obj" / "Doodle.dylib"
            if not binary.is_file() or binary.is_symlink():
                raise ValueError("Doodle probe dylib missing after build")
            observed_archs = set(checked_run(["/usr/bin/lipo", "-archs", str(binary)]).split())
            if observed_archs != EXPECTED_ARCHS:
                raise ValueError("Doodle probe architecture mismatch")
            archs.append(sorted(observed_archs))
            hashes.append(sha256(binary))
            signature = subprocess.run(["/usr/bin/codesign", "--verify", "--strict",
                                        str(binary)], stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=30, check=False)
            signatures.append("PASS" if signature.returncode == 0 else "FAIL")
            adhoc = work / "Doodle.host-adhoc.dylib"
            shutil.copy2(binary, adhoc)
            checked_run(["/usr/bin/codesign", "--force", "--sign", "-", str(adhoc)],
                        timeout=30)
            checked_run(["/usr/bin/codesign", "--verify", "--strict", str(adhoc)],
                        timeout=30)
            adhoc_hashes.append(sha256(adhoc))
    if hashes[0] != hashes[1]:
        raise ValueError("two clean Doodle probe builds differ")
    if adhoc_hashes[0] != adhoc_hashes[1]:
        raise ValueError("two local ad-hoc signature probes differ")
    return {"schema": 1, "component": "com.nahtedetihw.doodle",
            "source_version": "1.1", "source_commit": PINNED_COMMIT,
            "patch_sha256": PATCH_SHA256, "probe_sha256": hashes[0],
            "architectures": archs[0], "reproducible": True,
            "codesign_verification": signatures,
            "host_adhoc_probe_sha256": adhoc_hashes[0],
            "host_adhoc_verification": "PASS",
            "device_signature_acceptance": "UNVERIFIED",
            "functional_port": False, "installable_package": False,
            "repo_admission": "BLOCKED",
            "reason": "iOS 27 hooks are disabled; preference controller, credential handling, device signature acceptance, and runtime UAT are unresolved"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True,
                        help="local clean checkout at the pinned Doodle 1.1 commit")
    parser.add_argument("--theos", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    patch = repo / "tools/patches/doodle-ios27-source-probe.patch"
    report = build_probe(args.source.resolve(), patch, args.theos.resolve())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("refusing to replace existing probe report")
    staging = args.report.with_name(args.report.name + ".pending")
    staging.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    staging.replace(args.report)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
