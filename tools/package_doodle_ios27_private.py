#!/usr/bin/env python3
"""Package a reviewed private Doodle iOS 27 candidate without the old Preferences code."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

if __package__:
    from .build_doodle_ios27_candidate import PATCH_SHA256
    from .build_doodle_ios27_probe import PINNED_COMMIT, checked_run, sha256
else:
    from build_doodle_ios27_candidate import PATCH_SHA256
    from build_doodle_ios27_probe import PINNED_COMMIT, checked_run, sha256


PACKAGE = "com.nahtedetihw.doodle"
VERSION = "1:1.1+0sky27.2"
FIXED_MTIME = 1_700_000_000


def canonical_filter(source: Path) -> bytes:
    reviewed = source.read_text()
    if reviewed.count("com.apple.springboard") != 1 or "Filter" not in reviewed:
        raise ValueError("reviewed Doodle process filter changed")
    return plistlib.dumps({"Filter": {"Bundles": ["com.apple.springboard"]}},
                          fmt=plistlib.FMT_XML, sort_keys=True)


def package(source: Path, patch: Path, candidate: Path, build_report: Path,
            output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise FileExistsError("refusing to replace a prior private package")
    if not source.is_dir() or not (source / ".git").exists():
        raise ValueError("a local Doodle source checkout is required")
    if checked_run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source) != PINNED_COMMIT:
        raise ValueError("Doodle source commit differs from the reviewed 1.1 revision")
    if checked_run(["/usr/bin/git", "status", "--porcelain"], cwd=source):
        raise ValueError("Doodle source checkout has local changes")
    if sha256(patch) != PATCH_SHA256:
        raise ValueError("Doodle source port patch differs from the reviewed bytes")
    if not candidate.is_file() or candidate.is_symlink():
        raise ValueError("signed candidate is absent or unsafe")
    if not build_report.is_file() or build_report.is_symlink():
        raise ValueError("candidate build report is absent or unsafe")
    report = json.loads(build_report.read_text())
    if (report.get("component") != PACKAGE or report.get("source_commit") != PINNED_COMMIT or
            report.get("patch_sha256") != PATCH_SHA256 or
            report.get("candidate_sha256") != sha256(candidate) or
            report.get("host_signature") != "PASS" or
            report.get("reproducible") is not True):
        raise ValueError("candidate and reviewed build report do not match")
    checked_run(["/usr/bin/codesign", "--verify", "--strict", str(candidate)])
    if set(checked_run(["/usr/bin/lipo", "-archs", str(candidate)]).split()) != {"arm64", "arm64e"}:
        raise ValueError("signed candidate lacks required slices")
    if not shutil.which("dpkg-deb"):
        raise RuntimeError("dpkg-deb is required")
    hashes = []
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="0sky-doodle-package-") as temporary:
        for attempt in (1, 2):
            work = Path(temporary) / f"package-{attempt}"
            checkout = work / "checkout"
            checked_run(["/usr/bin/git", "clone", "--no-hardlinks", "--quiet",
                         str(source), str(checkout)])
            checked_run(["/usr/bin/git", "checkout", "--detach", "--quiet", PINNED_COMMIT],
                        cwd=checkout)
            checked_run(["/usr/bin/git", "apply", "--check", str(patch)], cwd=checkout)
            checked_run(["/usr/bin/git", "apply", str(patch)], cwd=checkout)
            root = work / "root"
            control = root / "DEBIAN"
            dylib = root / "var/jb/Library/MobileSubstrate/DynamicLibraries/Doodle.dylib"
            filter_plist = dylib.with_suffix(".plist")
            dylib.parent.mkdir(parents=True)
            control.mkdir(parents=True)
            shutil.copy2(candidate, dylib)
            filter_plist.write_bytes(canonical_filter(checkout / "Doodle.plist"))
            (control / "control").write_text(
                f"Package: {PACKAGE}\nVersion: {VERSION}\nArchitecture: iphoneos-arm64\n"
                "Section: Tweaks\nPriority: optional\nDepends: ellekit (>= 1.2)\n"
                "Maintainer: 0-Sky private research build\n"
                "Description: Private iOS 27 source port of Doodle 1.1\n"
                " This package excludes the old Preferences executable.\n"
            )
            for path in root.rglob("*"):
                if path.is_symlink():
                    raise ValueError("package staging contains a symbolic link")
                os.utime(path, (FIXED_MTIME, FIXED_MTIME))
            artifact = work / "candidate.deb"
            env = {key: os.environ[key] for key in ("PATH", "LANG") if key in os.environ}
            env["SOURCE_DATE_EPOCH"] = str(FIXED_MTIME)
            completed = subprocess.run(["dpkg-deb", "--build", "--root-owner-group",
                "--uniform-compression", "--compression=xz", str(root), str(artifact)],
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=120, check=False)
            if completed.returncode:
                raise RuntimeError("dpkg-deb failed to package the private port")
            hashes.append(sha256(artifact))
            if attempt == 2:
                pending = output.with_name(output.name + ".pending")
                if pending.exists() or pending.is_symlink():
                    raise FileExistsError("prior package staging file exists")
                shutil.copy2(artifact, pending)
        if hashes[0] != hashes[1] or sha256(pending) != hashes[0]:
            pending.unlink(missing_ok=True)
            raise RuntimeError("private Doodle packages differ across clean staging")
        pending.replace(output)
    return {"schema": 1, "package": PACKAGE, "version": VERSION,
            "source_version": "1.1", "source_commit": PINNED_COMMIT,
            "candidate_sha256": report["candidate_sha256"],
            "package_sha256": hashes[0], "reproducible": True,
            "preference_executable_included": False,
            "private_research_only": True, "repo_admission": "BLOCKED"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--build-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("refusing to replace a prior package report")
    patch = Path(__file__).resolve().parents[1] / "tools/patches/doodle-ios27-source-port.patch"
    result = package(args.source.resolve(), patch, args.candidate.resolve(),
                     args.build_report.resolve(), args.output.absolute())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    pending = args.report.with_name(args.report.name + ".pending")
    if pending.exists() or pending.is_symlink():
        raise FileExistsError("prior report staging file exists")
    pending.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    pending.replace(args.report)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
