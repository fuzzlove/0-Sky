#!/usr/bin/env python3
"""Compile the pinned Sileo source with reviewed iOS 27 SDK adaptations.

The output is an unsigned app archive for inspection. It is deliberately not
an installable IPA: SRD signing, Cryptex registration, and package integration
must be verified separately before Sileo can be offered as READY.
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
import tempfile

from deterministic_zip import build as build_zip


UPSTREAM = "https://github.com/fuzzlove/Sileo.git"
REVISION = "c9f70158a037dc76b91c450e72af2de0514dd3ee"
DEPICTION_KIT = "1ae6ad6ad6f8a7fc3194683c865d3f4b5a4072f9"
ALDERIS = "95030bfc6afc5d58a22aaa013e0f4c77317b57a1"
PATCHES = (
    ("sileo-ios27-sdk.patch", "fcf2a157068ebddd3bafe5a7113840dda13c47aa48586724f1c0b90dcf23aab1"),
    ("sileo-alderis-ios27-sdk.patch", "b1e08a5eb4a0c61246a5bf11c2ecc824c800282dcc14614e48f0cddeaf960c4a"),
    ("sileo-ios27-bridge.patch", "af16406072151137510990025512bd6b5048baf83464c4eb97eba6b8dbd73941"),
    ("sileo-ios27-sources.patch", "5e2a1adc04f369c1e6f24cdbaa9b3d152def3f91b141c8cddbdbb5bbcae00eeb"),
    ("sileo-ios27-removal.patch", "210afed36fdc4e5192eb561ecd7e2de258151fcce67ab37ea21476eb692d5018"),
    ("sileo-ios27-confirm.patch", "c92b34cfe928c337510ba6f09a22507cd187b44cf1333f78945666cb47885570"),
    ("sileo-ios27-confirm-control.patch", "987e15b6969b6863ece1764bd2e2ce922a4be30c90252baf5fec00d8069aabf8"),
    ("sileo-ios27-queue-state.patch", "3bd221ad6c9a73895f3f67dc855cfc308dfb052082e0ff46ea7e546ab0a62e57"),
    ("sileo-ios27-popup-touch.patch", "1f425a58ca56361150d507d3854989926e3c682b835a59ddd85fa9f2388b2e72"),
    ("sileo-ios27-install-lifecycle.patch", "f1e0b1d469bb648f616c9d419191cfe89b1e3f0f36dad4ed4dadad58fa7dd436"),
    ("sileo-ios27-havoc.patch", "65fd528ef4595c52fda50899278a738fdfcdfb98d0a0a0a84953f401d4d13225"),
    ("sileo-ios27-download-transition.patch", "11e121b018c2d4b17519a396eca5e981c809f1184797b36883bdae56564d607a"),
    ("sileo-ios27-cfnetwork-recovery.patch", "f9767c8cc1f649114a866f289a62b7ee8aa433f96df4226a8002f2886ff647a2"),
    ("sileo-ios27-download-diagnostic.patch", "08556b4027f9bbc64db620f9b9302f59ea870e3d56bcb65a7c6f21cfdefd1e2a"),
    ("sileo-ios27-directory-validation.patch", "755786492172b2b1387baed0451bd6c360590c752deb7365d6f1ecabf0b39703"),
    ("sileo-ios27-hash-key.patch", "ca8ab9df74e6a6afbeb3fb6b06f15fc56a53400f6941ac58316b12ef458b8069"),
    ("sileo-ios27-compatibility-status-ui.patch", "84695c813363104615248079ccc11f7d793f2e7ae30e1b8f2888512596223b7f"),
    ("sileo-ios27-verified-archive-gate.patch", "5df160cd2c3d83c1be464c33595fb434618433723d6fe8d2880575370dda0d82"),
    ("sileo-ios27-archive-identity.patch", "0047ee24795c8f9a3793e6d40c42811e77e0a759fe2711e422c5d94f812399e3"),
)
BUNDLE_ID = "com.amywhile.sileo"
VERSION = "2.5.1"
ENTITLEMENTS = Path(__file__).resolve().parent / "entitlements/sileo-srd-candidate.plist"
ENTITLEMENTS_SHA256 = "cfbf4ab4c72d41f0e4256f97a192318ed18466d6e0ba3693468b54d9fe98c427"
RUNTIME_LIBRARIES = {
    "liblzma.5.dylib": ("liblzma5", "5.4.4", "aa8bb2e3ab53ac83e2c150453556d42250f62f2d948e818ad8b7b0b0ee2bd33c"),
    "libzstd.1.dylib": ("libzstd1", "1.5.5", "6bed58a4ac51578706da4eebccb38431fc84a90c73d7a6dc95010edf3e200fd2"),
    "libiosexec.1.dylib": ("libiosexec1", "1.3.1", "e94faf783cbd809400816c8339ce8f2137f331c2371c5a961d86393bf16cec28"),
}


def run(arguments: list[str], *, cwd: Path | None = None,
        timeout: int = 900) -> str:
    result = subprocess.run(arguments, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout, check=False)
    if result.returncode:
        combined = result.stdout + "\n" + result.stderr
        diagnostics = [line for line in combined.splitlines()
                       if " error:" in line or "fatal error:" in line]
        error = "\n".join(diagnostics[:12]) if diagnostics else combined[-1500:]
        error = re.sub(r"https?://[^/@\s]+:[^/@\s]+@", "https://<redacted>@", error)
        error = re.sub(r"/Users/[^/\s]+", "/Users/<redacted>", error)
        error = re.sub(r"(?i)(token|password|secret)=\S+", r"\1=<redacted>", error)
        raise RuntimeError(f"{Path(arguments[0]).name} failed ({result.returncode}): {error}")
    return result.stdout.strip()


def run_bytes(arguments: list[str], *, timeout: int = 60) -> bytes:
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(Path(arguments[0]).name + " failed reading signed metadata")
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_patch(path: Path, expected: str) -> None:
    if path.is_symlink() or not path.is_file() or sha256(path) != expected:
        raise RuntimeError("reviewed adaptation patch is missing or changed: " + path.name)


def verify_checkout(source: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError("source checkout is absent or symbolic")
    if run(["git", "rev-parse", "HEAD"], cwd=source) != REVISION:
        raise RuntimeError("Sileo source is not the reviewed revision")
    origin = run(["git", "remote", "get-url", "origin"], cwd=source)
    if origin.rstrip("/") not in {UPSTREAM, UPSTREAM.removesuffix(".git")}:
        raise RuntimeError("Sileo source does not have the reviewed upstream origin")
    if run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=source):
        raise RuntimeError("Sileo source has unreviewed edits")


def remove_host_only_plist_keys(path: Path) -> list[str]:
    """Drop the upstream macOS privileged-helper rule from an iOS app."""
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("compiled Info.plist is absent or symbolic")
    info = plistlib.loads(path.read_bytes())
    removed = []
    for key in ("SMPrivilegedExecutables",):
        if key in info:
            del info[key]
            removed.append(key)
    if removed:
        path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
    return removed


def build(source: Path | None, output: Path, *, srd_candidate: bool = False,
          runtime_libraries: Path | None = None) -> dict:
    output = output.expanduser().resolve()
    suffix = ".ipa" if srd_candidate else ".app.zip"
    if not output.name.endswith(suffix):
        raise ValueError("candidate output must end in .ipa" if srd_candidate else
                         "unsigned inspection output must end in .app.zip")
    receipt_path = Path(str(output) + ".json")
    if output.exists() or output.is_symlink() or receipt_path.exists():
        raise FileExistsError("output or receipt already exists")
    patch_dir = Path(__file__).resolve().parent / "patches"
    for name, digest in PATCHES:
        verify_patch(patch_dir / name, digest)
    if srd_candidate:
        verify_patch(ENTITLEMENTS, ENTITLEMENTS_SHA256)
        required_entitlements = plistlib.loads(ENTITLEMENTS.read_bytes())
        if runtime_libraries is None:
            raise ValueError("SRD candidate requires hash-pinned runtime libraries")
        runtime_libraries = runtime_libraries.expanduser()
        if runtime_libraries.is_symlink() or not runtime_libraries.is_dir():
            raise ValueError("runtime library input is absent or symbolic")
        runtime_libraries = runtime_libraries.resolve(strict=True)
        for name, (_, _, expected) in RUNTIME_LIBRARIES.items():
            verify_patch(runtime_libraries / name, expected)
    signed_library_hashes: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="0sky-sileo-build-") as temporary:
        workspace = Path(temporary)
        checkout = workspace / "source"
        if source is None:
            run(["git", "clone", "--quiet", UPSTREAM, str(checkout)], timeout=300)
            run(["git", "checkout", "--quiet", "--detach", REVISION], cwd=checkout)
            verify_checkout(checkout)
        else:
            source = source.expanduser().resolve(strict=True)
            verify_checkout(source)
            run(["git", "clone", "--quiet", "--no-hardlinks", str(source), str(checkout)],
                timeout=300)
            run(["git", "checkout", "--quiet", "--detach", REVISION], cwd=checkout)
        run(["git", "submodule", "update", "--init", "--recursive"], cwd=checkout,
            timeout=300)
        depiction = checkout / "Deps/DepictionKit"
        if run(["git", "rev-parse", "HEAD"], cwd=depiction) != DEPICTION_KIT:
            raise RuntimeError("DepictionKit is not the reviewed revision")
        source_patch = patch_dir / PATCHES[0][0]
        run(["git", "apply", "--check", str(source_patch)], cwd=checkout)
        run(["git", "apply", str(source_patch)], cwd=checkout)
        bridge_patch = patch_dir / PATCHES[2][0]
        run(["git", "apply", "--check", str(bridge_patch)], cwd=checkout)
        run(["git", "apply", str(bridge_patch)], cwd=checkout)
        sources_patch = patch_dir / PATCHES[3][0]
        run(["git", "apply", "--check", str(sources_patch)], cwd=checkout)
        run(["git", "apply", str(sources_patch)], cwd=checkout)
        removal_patch = patch_dir / PATCHES[4][0]
        run(["git", "apply", "--check", str(removal_patch)], cwd=checkout)
        run(["git", "apply", str(removal_patch)], cwd=checkout)
        confirm_patch = patch_dir / PATCHES[5][0]
        run(["git", "apply", "--check", str(confirm_patch)], cwd=checkout)
        run(["git", "apply", str(confirm_patch)], cwd=checkout)
        confirm_control_patch = patch_dir / PATCHES[6][0]
        run(["git", "apply", "--check", str(confirm_control_patch)], cwd=checkout)
        run(["git", "apply", str(confirm_control_patch)], cwd=checkout)
        queue_state_patch = patch_dir / PATCHES[7][0]
        run(["git", "apply", "--check", str(queue_state_patch)], cwd=checkout)
        run(["git", "apply", str(queue_state_patch)], cwd=checkout)
        popup_touch_patch = patch_dir / PATCHES[8][0]
        run(["git", "apply", "--check", str(popup_touch_patch)], cwd=checkout)
        run(["git", "apply", str(popup_touch_patch)], cwd=checkout)
        lifecycle_patch = patch_dir / PATCHES[9][0]
        run(["git", "apply", "--check", str(lifecycle_patch)], cwd=checkout)
        run(["git", "apply", str(lifecycle_patch)], cwd=checkout)
        havoc_patch = patch_dir / PATCHES[10][0]
        run(["git", "apply", "--check", str(havoc_patch)], cwd=checkout)
        run(["git", "apply", str(havoc_patch)], cwd=checkout)
        transition_patch = patch_dir / PATCHES[11][0]
        run(["git", "apply", "--check", str(transition_patch)], cwd=checkout)
        run(["git", "apply", str(transition_patch)], cwd=checkout)
        recovery_patch = patch_dir / PATCHES[12][0]
        run(["git", "apply", "--check", str(recovery_patch)], cwd=checkout)
        run(["git", "apply", str(recovery_patch)], cwd=checkout)
        diagnostic_patch = patch_dir / PATCHES[13][0]
        run(["git", "apply", "--check", str(diagnostic_patch)], cwd=checkout)
        run(["git", "apply", str(diagnostic_patch)], cwd=checkout)
        directory_validation_patch = patch_dir / PATCHES[14][0]
        run(["git", "apply", "--check", str(directory_validation_patch)], cwd=checkout)
        run(["git", "apply", str(directory_validation_patch)], cwd=checkout)
        hash_key_patch = patch_dir / PATCHES[15][0]
        run(["git", "apply", "--check", str(hash_key_patch)], cwd=checkout)
        run(["git", "apply", str(hash_key_patch)], cwd=checkout)
        status_ui_patch = patch_dir / PATCHES[16][0]
        run(["git", "apply", "--check", str(status_ui_patch)], cwd=checkout)
        run(["git", "apply", str(status_ui_patch)], cwd=checkout)
        archive_gate_patch = patch_dir / PATCHES[17][0]
        run(["git", "apply", "--check", str(archive_gate_patch)], cwd=checkout)
        run(["git", "apply", str(archive_gate_patch)], cwd=checkout)
        archive_identity_patch = patch_dir / PATCHES[18][0]
        run(["git", "apply", "--check", str(archive_identity_patch)], cwd=checkout)
        run(["git", "apply", str(archive_identity_patch)], cwd=checkout)

        derived = workspace / "derived"
        project = checkout / "Sileo.xcodeproj"
        common = ["-project", str(project), "-scheme", "Sileo",
                  "-configuration", "Release", "-sdk", "iphoneos",
                  "-destination", "generic/platform=iOS",
                  "-derivedDataPath", str(derived)]
        run(["xcodebuild", *common, "-resolvePackageDependencies"], timeout=900)
        alderis = derived / "SourcePackages/checkouts/Alderis"
        if run(["git", "rev-parse", "HEAD"], cwd=alderis) != ALDERIS:
            raise RuntimeError("Alderis is not the reviewed revision")
        dep_patch = patch_dir / PATCHES[1][0]
        # SwiftPM may mark its checkout read-only; allow only the reviewed file
        # to be patched inside this disposable derived-data tree.
        target = alderis / "Alderis/ColorPickerInnerViewController.swift"
        target.chmod(target.stat().st_mode | 0o200)
        run(["git", "apply", "--check", str(dep_patch)], cwd=alderis)
        run(["git", "apply", str(dep_patch)], cwd=alderis)
        resolved = json.loads((project / "project.xcworkspace/xcshareddata/swiftpm/Package.resolved").read_text())
        pins = {item["package"]: item["state"]["revision"] for item in resolved["object"]["pins"]}
        if pins.get("Alderis") != ALDERIS:
            raise RuntimeError("resolved Alderis pin changed")

        run(["xcodebuild", *common, "-disableAutomaticPackageResolution",
             "IPHONEOS_DEPLOYMENT_TARGET=15.0", "CODE_SIGNING_ALLOWED=NO",
             "DEVELOPMENT_TEAM=", "build"], timeout=1800)
        app = derived / "Build/Products/Release-iphoneos/Sileo.app"
        if app.is_symlink() or not app.is_dir():
            raise RuntimeError("Sileo app was not built")
        removed_host_keys = remove_host_only_plist_keys(app / "Info.plist")
        info = plistlib.loads((app / "Info.plist").read_bytes())
        if (info.get("CFBundleIdentifier") != BUNDLE_ID or
                info.get("CFBundleShortVersionString") != VERSION):
            raise RuntimeError("compiled Sileo identity differs from the reviewed source")
        executable = app / info["CFBundleExecutable"]
        if (not executable.is_file() or executable.is_symlink() or
                set(run(["lipo", "-archs", str(executable)]).split()) != {"arm64"}):
            raise RuntimeError("compiled Sileo executable lacks the expected arm64 architecture")
        if subprocess.run(["codesign", "--verify", str(app)], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode == 0:
            raise RuntimeError("inspection build unexpectedly has a code signature")
        if srd_candidate:
            frameworks = app / "Frameworks"
            frameworks.mkdir(exist_ok=True)
            for name in RUNTIME_LIBRARIES:
                library = frameworks / name
                shutil.copy2(runtime_libraries / name, library)
                # Device dylibs are installed root-owned while Sileo runs as
                # mobile.  The source package's private 0600/0700 mode must
                # not make the bundled library invisible to dyld.
                library.chmod(0o644)
                if set(run(["lipo", "-archs", str(library)]).split()) != {"arm64"}:
                    raise RuntimeError("bundled runtime library has wrong architecture: " + name)
                run(["codesign", "--force", "--sign", "-", "--timestamp=none",
                     "--generate-entitlement-der", str(library)])
                signed_library_hashes[name] = sha256(library)
            run(["install_name_tool", "-add_rpath", "@executable_path/Frameworks",
                 str(executable)])
            run(["codesign", "--force", "--sign", "-", "--timestamp=none",
                 "--generate-entitlement-der", "--entitlements", str(ENTITLEMENTS),
                 str(app)])
            run(["codesign", "--verify", "--deep", "--strict", str(app)])
            effective = plistlib.loads(run_bytes(
                ["codesign", "--display", "--entitlements", ":-", str(app)]))
            if effective != required_entitlements:
                raise RuntimeError("candidate effective entitlements differ from manifest")
        stage = workspace / "archive" / ("Payload" if srd_candidate else "")
        stage.mkdir(parents=True)
        shutil.copytree(app, stage / "Sileo.app", symlinks=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        build_zip(stage.parent if srd_candidate else stage, output)
    receipt = {
        "upstream": UPSTREAM, "source_revision": REVISION,
        "depiction_kit_revision": DEPICTION_KIT,
        "alderis_revision": ALDERIS,
        "adaptation_patches": {name: digest for name, digest in PATCHES},
        "bundle_id": BUNDLE_ID, "version": VERSION,
        "host_only_plist_keys_removed": removed_host_keys,
        "architectures": ["arm64"],
        "signature": "ad-hoc SRD test candidate" if srd_candidate else "unsigned inspection build",
        "entitlements_sha256": ENTITLEMENTS_SHA256 if srd_candidate else None,
        "bundled_runtime_libraries": {
            name: {"package": package, "version": version,
                   "source_sha256": digest,
                   "signed_sha256": signed_library_hashes[name]}
            for name, (package, version, digest) in RUNTIME_LIBRARIES.items()
        } if srd_candidate else {},
        "runtime_library_provenance": (
            "hash-matched installed Procursus packages on both authorized SRDs; UAT only"
            if srd_candidate else None),
        "installation_state": "NOT_INSTALLED",
        "runtime_state": "UNVERIFIED",
        "artifact_sha256": sha256(output), "artifact_size": output.stat().st_size,
    }
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="clean checkout of the pinned upstream")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--srd-candidate", action="store_true",
                        help="sign a minimal-permission test IPA; never marks it production-ready")
    parser.add_argument("--runtime-libraries", type=Path,
                        help="directory containing the exact pinned Procursus runtime dylibs")
    args = parser.parse_args()
    print(json.dumps(build(args.source, args.output, srd_candidate=args.srd_candidate,
                           runtime_libraries=args.runtime_libraries), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
