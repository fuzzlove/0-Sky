#!/usr/bin/env python3
"""Rebuild the Link payload from a verified external kit, then stage release inputs."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

try:
    from .kit_manifest import (APPROVAL_NAME, APPROVAL_STATES,
                               generate as generate_kit_manifest, verify as verify_kit_manifest)
    from .stage_verified_kit import digest, stage
    from .stage_control_payload import stage as stage_control_payload
    from .verify_release import architecture_of, platform_of, wheel_coverage
    from .host_runtime_manifest import verify as verify_host_runtime
    from .build_host_runtime import RuntimeBuildError, build as build_host_runtime
except ImportError:
    from kit_manifest import (APPROVAL_NAME, APPROVAL_STATES,
                              generate as generate_kit_manifest, verify as verify_kit_manifest)
    from stage_verified_kit import digest, stage
    from stage_control_payload import stage as stage_control_payload
    from verify_release import architecture_of, platform_of, wheel_coverage
    from host_runtime_manifest import verify as verify_host_runtime
    from build_host_runtime import RuntimeBuildError, build as build_host_runtime


ROOT = Path(__file__).resolve().parents[1]
LINK_NAME = "0-Sky-Link-1.9.0-universal.ipa"
OVERRIDES = {
    "automation/CrypStoreAutomation/native-install/install_cryptex_native.py": ROOT / "bridge/KitScripts/automation/CrypStoreAutomation/native-install/install_cryptex_native.py",
    "runtime-generation/install_cryptex_native.py": ROOT / "bridge/KitScripts/runtime-generation/install_cryptex_native.py",
    "host-mac/install.py": ROOT / "bridge/HostTools/install.py",
    "host-mac/uninstall.py": ROOT / "bridge/HostTools/uninstall.py",
    "host-mac/instance.py": ROOT / "bridge/HostTools/instance.py",
    "host-mac/refresh.py": ROOT / "bridge/HostTools/refresh.py",
    "host-mac/apple_device_transport.py": ROOT / "bridge/HostTools/apple_device_transport.py",
    "host-mac/pair.py": ROOT / "bridge/HostTools/pair.py",
    "host-mac/bootstrap_device.py": ROOT / "bridge/HostTools/bootstrap_device.py",
    "host-mac/audit_device.py": ROOT / "bridge/HostTools/audit_device.py",
    "automation/CrypStoreAutomation/crypstore_worker.py": ROOT / "bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py",
    "automation/CrypStoreAutomation/device_bridge_supervisor.sh": ROOT / "bridge/KitScripts/automation/CrypStoreAutomation/device_bridge_supervisor.sh",
    "automation/CrypStoreAutomation/native-install/build_and_install.sh": ROOT / "bridge/KitScripts/automation/CrypStoreAutomation/native-install/build_and_install.sh",
    "runtime-generation/build_and_install.sh": ROOT / "bridge/KitScripts/runtime-generation/build_and_install.sh",
    "srdssh/rekey_image.py": ROOT / "bridge/KitScripts/srdssh/rekey_image.py",
    "automation/tools/srd-runtime-manager/sync_runtime_cryptex.py": ROOT / "bridge/KitScripts/automation/tools/srd-runtime-manager/sync_runtime_cryptex.py",
}

RUNTIME_MANAGER_SOURCE = ROOT / "bridge/KitScripts/automation/tools/srd-runtime-manager"
for relative in (
    "runtime_manager_launcher.c",
    "codes.openai.research.srd-runtime-manager.plist",
    "sandboxed-injector/LICENSE",
    "sandboxed-injector/README.md",
    "sandboxed-injector/arm64.h",
    "sandboxed-injector/arm64.m",
    "sandboxed-injector/dyld.h",
    "sandboxed-injector/dyld.m",
    "sandboxed-injector/entitlements.plist",
    "sandboxed-injector/main.m",
    "sandboxed-injector/pac.h",
    "sandboxed-injector/rop_inject.h",
    "sandboxed-injector/rop_inject.m",
    "sandboxed-injector/sandbox.h",
    "sandboxed-injector/shellcode_inject.h",
    "sandboxed-injector/shellcode_inject.m",
    "sandboxed-injector/task_utils.h",
    "sandboxed-injector/task_utils.m",
    "sandboxed-injector/thread_utils.h",
    "sandboxed-injector/thread_utils.m",
):
    OVERRIDES["automation/tools/srd-runtime-manager/" + relative] = (
        RUNTIME_MANAGER_SOURCE / relative
    )


def stage_link_control_only(verified_kit: Path, destination: Path) -> None:
    """Embed the canonical Control payload without copying host/bootstrap assets into Link."""
    relative = "packages/Commissary-Universal.ipa"
    source = verified_kit / relative
    manifest = verified_kit / "SHA256SUMS"
    if (source.is_symlink() or not source.is_file() or manifest.is_symlink() or
            not manifest.is_file() or destination.exists()):
        raise RuntimeError("verified Link Control payload slot is absent or unsafe")
    slot = "./" + relative
    rows = [row for row in manifest.read_text(encoding="utf-8").splitlines()
            if row.split(None, 1)[-1] == slot]
    if len(rows) != 1 or rows[0].split(None, 1)[0] != digest(source):
        raise RuntimeError("Link Control payload differs from its verified kit manifest")
    target = destination / relative
    target.parent.mkdir(parents=True, exist_ok=False)
    shutil.copy2(source, target)
    (destination / "SHA256SUMS").write_text(rows[0] + "\n", encoding="utf-8")


def apply_portability_overrides(kit: Path) -> None:
    """Overlay versioned scripts onto verified vendor input and rehash exactly."""
    manifest = kit / "SHA256SUMS"
    rows = manifest.read_text(encoding="utf-8").splitlines()
    for relative, source in OVERRIDES.items():
        target = kit / relative
        if not source.is_file() or not target.is_file() or target.is_symlink():
            raise RuntimeError(f"required portable script is missing: {relative}")
        slot = "./" + relative
        matches = [index for index, row in enumerate(rows) if row.split(None, 1)[-1] == slot]
        if len(matches) != 1:
            raise RuntimeError(f"portable script has no unique manifest entry: {relative}")
        shutil.copy2(source, target)
        rows[matches[0]] = f"{digest(target)}  {slot}"
    # Both transports ship byte-identical code from one authoritative source.
    compatibility = ROOT / "bridge/DeviceRuntime/zero_sky_compat"
    runtime_sources = ROOT / "bridge/DeviceRuntime/zero_sky_core"
    overlays = {
        "automation/CrypStoreAutomation/trollstorelite-srd-bridge.py": ROOT / "bridge/DeviceRuntime/trollstorelite-srd-bridge.py",
        "automation/CrypStoreAutomation/bootsplash-launch.py": ROOT / "bridge/DeviceRuntime/bootsplash_launch.py",
    }
    for package, destinations in (
        (compatibility, ("automation/CrypStoreAutomation/zero_sky_compat", "automation/tools/srd-runtime-manager/zero_sky_compat")),
        (runtime_sources, ("automation/tools/srd-runtime-manager/zero_sky_core",)),
    ):
        for source in sorted(package.rglob("*.py")):
            for destination in destinations:
                overlays[destination + "/" + source.relative_to(package).as_posix()] = source
    # The toolkit catalog is runtime policy, so it must be shipped and hashed
    # alongside its Python evaluator in the immutable SRD kit.
    overlays["automation/tools/srd-runtime-manager/zero_sky_core/research_toolkit_manifest.json"] = \
        runtime_sources / "research_toolkit_manifest.json"
    for relative, source in sorted(overlays.items()):
        target = kit / relative
        if target.is_symlink():
            raise RuntimeError("unsafe compatibility overlay target")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        slot = "./" + relative
        rows = [row for row in rows if row.split(None, 1)[-1] != slot]
        rows.append(f"{digest(target)}  {slot}")
    # Old vendor entry points are retained only in the verified input kit.
    # Release-facing wrappers delegate to the canonical compatibility engine.
    guard = ROOT / "bridge/HostTools/compatibility_guard.py"
    for relative in (
        "srdssh/bootstrap.py",
        "srdssh/install_cryptex_native.py",
        "filza/install_cryptex_native.py",
        "automation/CrypStoreAutomation/crypstore_keeper.py",
        "automation/CrypStoreAutomation/sileo-package-bridge-v8.py",
        "automation/CrypStoreAutomation/sileo-research-bridge.py",
    ):
        target = kit / relative
        if not target.is_file() or target.is_symlink():
            raise RuntimeError("required legacy route missing from verified kit: " + relative)
        wrapper = ("#!/usr/bin/env python3\n"
                   "from pathlib import Path\nimport runpy, sys\n"
                   "for parent in Path(__file__).resolve().parents:\n"
                   "    guard = parent / 'host-mac/compatibility_guard.py'\n"
                   "    if guard.is_file():\n"
                   "        sys.argv = [str(guard), " + repr(relative) + "]\n"
                   "        runpy.run_path(str(guard), run_name='__main__')\n"
                   "        raise SystemExit(193)\n"
                   "raise SystemExit('Compatibility engine unavailable; installation blocked')\n")
        target.write_text(wrapper, encoding="utf-8")
        slot = "./" + relative
        rows = [row for row in rows if row.split(None, 1)[-1] != slot]
        rows.append(f"{digest(target)}  {slot}")
    target = kit / "host-mac/compatibility_guard.py"
    shutil.copy2(guard, target)
    rows = [row for row in rows if row.split(None, 1)[-1] != "./host-mac/compatibility_guard.py"]
    rows.append(f"{digest(target)}  ./host-mac/compatibility_guard.py")
    marker = kit / "PORTABILITY.json"
    marker.write_text(json.dumps({"schema": 1, "overrides": "source-controlled"},
                                 sort_keys=True) + "\n", encoding="utf-8")
    marker_rows = [index for index, row in enumerate(rows)
                   if row.split(None, 1)[-1] == "./PORTABILITY.json"]
    if len(marker_rows) > 1:
        raise RuntimeError("portability marker appears multiple times")
    marker_row = f"{digest(marker)}  ./PORTABILITY.json"
    if marker_rows:
        rows[marker_rows[0]] = marker_row
    else:
        rows.append(marker_row)
    manifest.write_text("\n".join(sorted(rows)) + "\n", encoding="utf-8")


def prepare(source: Path, output: Path, *, deny_file: Path | None = None) -> int:
    source = source.resolve(strict=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".0sky-release-input-", dir=output.parent) as temporary:
        work = Path(temporary)
        embedded = work / "link-kit"
        link_payload = work / "link-control-payload"
        link_output = work / "link-output"
        stage(source, embedded, link_embed=True)
        stage_control_payload(embedded)
        stage_link_control_only(embedded, link_payload)
        environment = dict(os.environ)
        environment["ZERO_SKY_KIT_SOURCE"] = str(link_payload)
        environment["LINK_OUTPUT"] = str(link_output)
        subprocess.run([str(ROOT / "link/build.sh")], cwd=ROOT, env=environment,
                       timeout=300, check=True)
        built = link_output / "0-Sky-Link-1.9.0-source.ipa"
        if not built.is_file():
            raise RuntimeError("Link builder did not create its expected IPA")
        subprocess.run([sys.executable, str(ROOT / "tools/verify_link_ipa.py"), str(built),
                        "--require-control"],
                       timeout=60, check=True)
        scan = [sys.executable, str(ROOT / "tools/release_sanitize.py"), str(built)]
        if deny_file:
            scan += ["--deny-file", str(deny_file.resolve(strict=True))]
        subprocess.run(scan, timeout=60, check=True)
        candidate = work / "release-kit"
        count = stage(source, candidate, release=True)
        apply_portability_overrides(candidate)
        if not (candidate / "host-mac/HOST_RUNTIME_MANIFEST.json").is_file():
            print("HOST_RUNTIME_BUILD=START pinned dual-architecture runtime", flush=True)
            build_host_runtime(candidate, ROOT / ".build/host-runtime-cache")
        verify_host_runtime(candidate)
        staged_control = stage_control_payload(candidate, build=False)
        if staged_control["sha256"] != digest(embedded / "packages/Commissary-Universal.ipa"):
            raise RuntimeError("Link and release kit have different Control payload bytes")
        target = candidate / "payloads" / LINK_NAME
        if not target.is_file():
            raise RuntimeError("verified source kit lacks the Link payload slot")
        shutil.copy2(built, target)
        wheel_count, wheel_issues = wheel_coverage(candidate / "host-mac")
        if wheel_count == 0 or wheel_issues:
            raise RuntimeError("offline Mac wheel architecture coverage failed")
        for relative in ("host-mac/zero-sky-bluetooth-tunnel",
                         "automation/CrypStoreAutomation/device_bridge_supervisor"):
            binary = candidate / relative
            if architecture_of(binary) != {"arm64", "x86_64"} or platform_of(binary) != "MACOS":
                raise RuntimeError("required Mac helper lacks Universal 2 slices")
        scan = [sys.executable, str(ROOT / "tools/release_sanitize.py"), str(candidate)]
        if deny_file:
            scan += ["--deny-file", str(deny_file.resolve(strict=True))]
        subprocess.run(scan, timeout=120, check=True)
        python312 = str(candidate / "host-mac/runtime/bin/python3")
        if not Path(python312).is_file():
            python312 = shutil.which("python3.12") or ""
        if not python312:
            raise RuntimeError("Python 3.12 is required for the offline install test")
        subprocess.run([sys.executable, str(ROOT / "tools/test_offline_install.py"),
                        str(candidate), "--python", python312],
                       timeout=900, check=True)
        subprocess.run([sys.executable, str(ROOT / "tools/wheel_inventory.py"),
                        str(candidate)], timeout=120, check=True)
        (candidate / APPROVAL_NAME).write_text(
            json.dumps({"schema_version": 1, "states": list(APPROVAL_STATES)},
                       sort_keys=True) + "\n", encoding="utf-8")
        generate_kit_manifest(candidate)
        if verify_kit_manifest(candidate):
            raise RuntimeError("generated release kit manifest failed validation")
        subprocess.run(scan, timeout=120, check=True)
        previous = output.with_name(output.name + f".previous.{os.getpid()}")
        if previous.exists():
            raise RuntimeError("previous release-kit backup already exists")
        if output.exists():
            output.replace(previous)
        try:
            candidate.replace(output)
        except Exception:
            if previous.exists():
                previous.replace(output)
            raise
        if previous.exists():
            shutil.rmtree(previous)
        print(f"RELEASE_KIT=PASS FILES={count}")
        return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="externally supplied manifest-verified kit")
    parser.add_argument("output", type=Path, help="separate release-kit output directory")
    parser.add_argument("--deny-file", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error("source and output must be different directories")
    try:
        prepare(args.source, args.output, deny_file=args.deny_file)
    except RuntimeBuildError as error:
        print(json.dumps({"category": "host-runtime-source-missing",
                          "detail": error.detail}), file=sys.stderr)
        print("REQUIRED_ACTION:", file=sys.stderr)
        for line in error.remediation.splitlines():
            print(f"  {line}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as error:
        operation = Path(error.cmd[1] if len(error.cmd) > 1 else error.cmd[0]).name
        print(f"RELEASE_KIT=FAIL operation={operation} exit={error.returncode}",
              file=sys.stderr)
        return 2
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"RELEASE_KIT=FAIL {type(error).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
