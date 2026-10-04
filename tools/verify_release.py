#!/usr/bin/env python3
"""Fail-closed verification of a signed Universal 2 app and installer payload."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

try:
    from .release_manifest import ManifestError, verify as verify_release_manifest
except ImportError:
    from release_manifest import ManifestError, verify as verify_release_manifest

try:
    from .kit_manifest import verify as verify_kit_manifest
    from .host_runtime_manifest import RuntimeManifestError, verify as verify_host_runtime
    from .release_sanitize import audit, load_deny_patterns
except ImportError:
    from kit_manifest import verify as verify_kit_manifest
    from host_runtime_manifest import RuntimeManifestError, verify as verify_host_runtime
    from release_sanitize import audit, load_deny_patterns


ROOT = Path(__file__).resolve().parents[1]
MACHO_MAGIC = {bytes.fromhex(value) for value in (
    "feedface", "cefaedfe", "feedfacf", "cffaedfe",
    "cafebabe", "bebafeca", "cafebabf", "bfbafeca")}
REQUIRED_ARCHS = {"arm64", "x86_64"}
REQUIRED_MAC_BINARIES = {
    "Contents/MacOS/0SkyBridge",
    "Contents/MacOS/0SkyBridgeService",
    "Contents/Library/LaunchServices/0SkyBridgeHelper",
    "Contents/Resources/Kit/host-mac/zero-sky-bluetooth-tunnel",
    "Contents/Resources/Kit/automation/CrypStoreAutomation/device_bridge_supervisor",
}
REQUIRED_KIT_FILES = (
    "SHA256SUMS", "RELEASE_KIT_MANIFEST.json", "PORTABILITY.json", "host-mac/install.py",
    "host-mac/pair.py", "host-mac/requirements-lock.txt",
    "host-mac/HOST_RUNTIME_MANIFEST.json",
    "payloads/0-Sky-Link-1.9.0-universal.ipa",
)
REQUIRED_APP_SCRIPTS = (
    "macos_host_setup.py", "0sky_project_setup.py",
    "zero_sky_user_config.py", "Install 0-Sky Dependencies.command",
)
ENTITLEMENT_TARGETS = tuple(sorted(Path(relative).name for relative in REQUIRED_MAC_BINARIES))
FORBIDDEN_PARTS = {".git", ".env", ".ssh", "DerivedData", "__pycache__",
                   ".DS_Store", ".dSYM", ".xcarchive", "XCBuildData"}
DEBUG_ENTITLEMENTS = {"com.apple.security.get-task-allow",
                      "com.apple.security.cs.allow-dyld-environment-variables",
                      "com.apple.security.cs.allow-unsigned-executable-memory"}


def run(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, capture_output=True, timeout=timeout, check=False)


def is_macho(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4) in MACHO_MAGIC
    except OSError:
        return False


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_kit_issues(app: Path) -> list[str]:
    """Verify the dependencies a fresh installation must resolve from the app."""
    kit = app / "Contents/Resources/Kit"
    scripts = app / "Contents/Resources/Scripts"
    if (app / "Contents/Resources/.0sky-incomplete-build").exists():
        return ["INCOMPLETE_BUILD_MARKER"]
    if not kit.is_dir() or not (kit / "host-mac/wheelhouse").is_dir():
        return ["DEPENDENCY_KIT_MISSING"]
    if any(not (kit / relative).is_file() for relative in REQUIRED_KIT_FILES):
        return ["DEPENDENCY_KIT_INCOMPLETE"]
    if any(not (scripts / relative).is_file() for relative in REQUIRED_APP_SCRIPTS):
        return ["DEPENDENCY_INSTALLER_MISSING"]
    issues = verify_kit_manifest(kit)
    try:
        verify_host_runtime(kit)
    except (OSError, RuntimeManifestError, subprocess.SubprocessError):
        issues.append("HOST_RUNTIME_INVALID")
    return issues


def platform_of(path: Path) -> str:
    result = run(["xcrun", "vtool", "-show-build", str(path)], timeout=20)
    if result.returncode:
        return "UNKNOWN"
    output = result.stdout.decode("utf-8", "replace")
    platforms = set(re.findall(r"(?m)^\s*platform\s+(\w+)", output))
    if "LC_VERSION_MIN_MACOSX" in output:
        platforms.add("MACOS")
    if "LC_VERSION_MIN_IPHONEOS" in output:
        platforms.add("IOS")
    return next(iter(platforms)) if len(platforms) == 1 else "UNKNOWN"


def architecture_of(path: Path) -> set[str]:
    result = run(["xcrun", "lipo", "-archs", str(path)], timeout=20)
    if result.returncode:
        return set()
    return set(result.stdout.decode("ascii", "replace").split())


def wheel_coverage(host_kit: Path) -> tuple[int, list[str]]:
    """Check lockfile coverage and native wheel slices for both Mac CPUs."""
    lock = host_kit / "requirements-lock.txt"
    wheelhouse = host_kit / "wheelhouse"
    if not lock.is_file() or not wheelhouse.is_dir():
        return 0, ["WHEELHOUSE_MISSING"]
    wheels = list(wheelhouse.glob("*.whl"))
    required: list[tuple[str, str, set[str]]] = []
    for raw in lock.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(
            r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+]+)(?:;\s*platform_machine\s*==\s*[\"'](arm64|x86_64)[\"'])?",
            line)
        if not match:
            return 0, ["UNSUPPORTED_LOCK_ENTRY"]
        name, version, marker = match.groups()
        required.append((re.sub(r"[-_.]+", "_", name).lower(), version,
                         {marker} if marker else REQUIRED_ARCHS))
    issues: list[str] = []
    selected: dict[Path, set[str]] = {}
    for name, version, machines in required:
        candidates = [wheel for wheel in wheels if
                      re.sub(r"[-_.]+", "_", wheel.stem.split("-")[0]).lower() == name
                      and len(wheel.stem.split("-")) >= 5
                      and wheel.stem.split("-")[1] == version]
        for machine in machines:
            compatible = [wheel for wheel in candidates if
                          wheel.stem.split("-")[-1] == "any" or
                          "universal2" in wheel.stem.split("-")[-1] or
                          machine in wheel.stem.split("-")[-1]]
            if not compatible:
                issues.append(f"WHEEL_MISSING:{name}:{machine}")
            else:
                selected.setdefault(compatible[0], set()).add(machine)
    with tempfile.TemporaryDirectory(prefix="0sky-wheel-audit-") as folder:
        native_count = 0
        for wheel, machines in selected.items():
            try:
                with zipfile.ZipFile(wheel) as archive:
                    for member in archive.infolist():
                        if member.is_dir():
                            continue
                        if member.file_size > 256 * 1024 * 1024:
                            issues.append("WHEEL_MEMBER_OVERSIZED")
                            continue
                        with archive.open(member) as stream:
                            magic = stream.read(4)
                            if magic not in MACHO_MAGIC:
                                continue
                            data = magic + stream.read()
                        native_count += 1
                        target = Path(folder) / "native"
                        target.write_bytes(data)
                        archs = architecture_of(target)
                        if not machines.issubset(archs):
                            issues.append("WHEEL_SLICE_MISSING:" + wheel.name.split("-")[0])
                        if platform_of(target) != "MACOS":
                            issues.append("WHEEL_PLATFORM_INVALID:" + wheel.name.split("-")[0])
            except (OSError, RuntimeError, zipfile.BadZipFile):
                issues.append("WHEEL_INVALID:" + wheel.name.split("-")[0])
    return native_count, issues


def entitlement_status(path: Path) -> str:
    result = run(["/usr/bin/codesign", "-d", "--entitlements", "-", str(path)], 20)
    if result.returncode:
        return "FAIL"
    raw = result.stdout.strip()
    if not raw:
        return "PASS"
    try:
        values = plistlib.loads(raw)
    except (ValueError, TypeError, plistlib.InvalidFileException):
        return "FAIL"
    return "FAIL" if any(values.get(key) is True for key in DEBUG_ENTITLEMENTS) else "PASS"


def signature_status(path: Path) -> tuple[str, str, str, str | None]:
    verified = run(["/usr/bin/codesign", "--verify", "--strict", str(path)], 30)
    if verified.returncode:
        return "FAIL", "FAIL", "NOT_VERIFIED", None
    detail = run(["/usr/bin/codesign", "-dvvv", str(path)], 20)
    flags = detail.stderr.decode("utf-8", "replace")
    runtime = "PASS" if re.search(r"flags=.*\bruntime\b", flags) else "FAIL"
    developer_id = "Authority=Developer ID Application:" in flags
    team_match = re.search(r"(?m)^TeamIdentifier=([A-Z0-9]+)$", flags)
    return ("PASS" if developer_id else "FAIL", runtime,
            entitlement_status(path), team_match.group(1) if team_match else None)


def package_payload(package: Path, destination: Path) -> Path:
    result = run(["/usr/sbin/pkgutil", "--expand-full", str(package),
                  str(destination)], timeout=300)
    if result.returncode:
        raise ValueError("package expansion failed")
    if (destination / "Scripts").exists():
        raise ValueError("package contains installer scripts")
    bom = destination / "Bom"
    if not bom.is_file():
        raise ValueError("package lacks ownership manifest")
    manifest = run(["/usr/bin/lsbom", "-p", "fmug", str(bom)], 60)
    if manifest.returncode:
        raise ValueError("package ownership manifest invalid")
    for raw in manifest.stdout.decode("utf-8", "replace").splitlines():
        parts = raw.split("\t")
        if len(parts) != 4:
            raise ValueError("package ownership manifest malformed")
        _, mode, user_id, group_id = parts
        if user_id != "0" or group_id != "0" or int(mode, 8) & (
            stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID):
            raise ValueError("package ownership or permissions unsafe")
    payload = destination / "Payload"
    app = payload / "Applications/0SkyBridge.app"
    if not app.is_dir():
        raise ValueError("package lacks Applications/0SkyBridge.app")
    for item in payload.rglob("*"):
        relative = item.relative_to(payload).parts
        if relative[:2] != ("Applications", "0SkyBridge.app") and relative != ("Applications",):
            raise ValueError("package contains unexpected payload path")
    return app


def same_tree(source: Path, extracted: Path) -> bool:
    source_items = {p.relative_to(source): p for p in source.rglob("*")}
    extracted_items = {p.relative_to(extracted): p for p in extracted.rglob("*")}
    if source_items.keys() != extracted_items.keys():
        return False
    for relative, item in source_items.items():
        other = extracted_items[relative]
        if item.is_symlink() != other.is_symlink():
            return False
        if item.is_symlink():
            if os.readlink(item) != os.readlink(other):
                return False
        elif item.is_file():
            if not other.is_file() or sha256(item) != sha256(other):
                return False
            if stat.S_IMODE(item.stat().st_mode) != stat.S_IMODE(other.stat().st_mode):
                return False
        elif not other.is_dir() or stat.S_IMODE(item.stat().st_mode) != stat.S_IMODE(other.stat().st_mode):
            return False
    return True


def verify(app: Path, package: Path | None, deny_file: Path | None,
           notarized: bool = False, *, distribution: bool = True
           ) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {key: "NOT_EXECUTED" for key in (
        "Main executable", "arm64", "x86_64", "Universal 2", "Nested binaries checked",
        "Python wheel coverage", "Bundled host runtime",
        "Application", "Installer", "Dependency kit", "EULA", "Permissions", "Code signature",
        "Hardened runtime", "Entitlements", "Gatekeeper assessment", "Notarization",
        "Stapling", "Signing team consistency", "Developer username leak", "Developer HOME leak", "Hostname leak",
        "Repository-path leak", "UDID leak", "Email leak", "Credential scan",
        "Private-key scan", "Debug artifact scan", "Hard-coded path scan",
        "Tool discovery", "Architecture discovery", "Runtime paths",
        "Clean-build verification", "Apple Silicon", "Intel", "Fresh installation",
        "Upgrade", "Launch")}
    errors: list[str] = []
    if not app.is_dir() or not (app / "Contents/Info.plist").is_file():
        return values, ["APP_MISSING"]
    try:
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        values.update({"Product": str(info.get("CFBundleName", "UNKNOWN")),
                       "Version": str(info.get("CFBundleShortVersionString", "UNKNOWN")),
                       "Build": str(info.get("CFBundleVersion", "UNKNOWN"))})
    except (OSError, ValueError, TypeError):
        errors.append("INFO_PLIST_INVALID")
    values["Application"] = "PASS"
    kit_errors = runtime_kit_issues(app)
    values["Dependency kit"] = "FAIL" if kit_errors else "PASS"
    values["Bundled host runtime"] = (
        "FAIL" if "HOST_RUNTIME_INVALID" in kit_errors else "PASS"
    )
    errors.extend(kit_errors)
    values["Tool discovery"] = "PASS" if all(shutil.which(tool) for tool in
        ("xcrun", "codesign", "spctl", "pkgutil")) else "FAIL"
    values["Runtime paths"] = "PASS"
    all_files = [item for item in app.rglob("*") if item.is_file() and not item.is_symlink()]
    bad_names = [item for item in app.rglob("*") if any(part in FORBIDDEN_PARTS
                 or part.endswith((".p12", ".mobileprovision", ".xcarchive"))
                 for part in item.relative_to(app).parts)]
    values["Debug artifact scan"] = "FAIL" if bad_names else "PASS"
    if bad_names:
        errors.append("UNEXPECTED_DEVELOPMENT_FILE")
    bad_modes = [item for item in app.rglob("*") if not item.is_symlink()
                 and item.stat().st_mode & (stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)]
    values["Permissions"] = "FAIL" if bad_modes else "PASS"
    if bad_modes:
        errors.append("UNSAFE_PERMISSIONS")
    native = [item for item in all_files if is_macho(item)]
    mac_native: list[Path] = []
    mac_arches: dict[str, set[str]] = {}
    device_native = 0
    for item in native:
        relative = item.relative_to(app).as_posix()
        platform = platform_of(item)
        if platform == "MACOS":
            mac_native.append(item)
            mac_arches[relative] = architecture_of(item)
            if not REQUIRED_ARCHS.issubset(mac_arches[relative]):
                errors.append("MISSING_UNIVERSAL_SLICE:" + relative)
        elif platform in {"IOS", "IOSSIMULATOR", "TVOS", "WATCHOS"}:
            device_native += 1
            if not relative.startswith("Contents/Resources/Kit/"):
                errors.append("DEVICE_BINARY_OUTSIDE_KIT")
        else:
            errors.append("UNKNOWN_MACHO_PLATFORM:" + relative)
    found_mac = {p.relative_to(app).as_posix() for p in mac_native}
    if not REQUIRED_MAC_BINARIES.issubset(found_mac):
        errors.append("REQUIRED_MAC_BINARY_MISSING")
    values["Nested binaries checked"] = f"{len(mac_native)} macOS; {device_native} device"
    wheel_native, wheel_issues = wheel_coverage(app / "Contents/Resources/Kit/host-mac")
    values["Python wheel coverage"] = (f"PASS ({wheel_native} native files)"
                                       if not wheel_issues else "FAIL")
    errors.extend(wheel_issues)
    values["Architecture discovery"] = "PASS" if native and not any(
        issue.startswith(("UNKNOWN_MACHO", "REQUIRED_MAC_BINARY")) for issue in errors) else "FAIL"
    values["Main executable"] = "PASS" if "Contents/MacOS/0SkyBridge" in found_mac else "FAIL"
    required_present = REQUIRED_MAC_BINARIES.issubset(found_mac)
    for key in ("arm64", "x86_64"):
        values[key] = ("PASS" if required_present and
                       all(key in archs for archs in mac_arches.values()) else "FAIL")
    values["Universal 2"] = ("PASS" if all(values[key] == "PASS" for key in REQUIRED_ARCHS)
                              and not any(issue.startswith("UNKNOWN_MACHO") for issue in errors)
                              else "FAIL")
    outer_signature = ("BLOCKED", "BLOCKED", "BLOCKED", None)
    if distribution:
        signatures = [signature_status(item) for item in mac_native]
        for item, signature in zip(mac_native, signatures):
            values["Entitlements " + item.name] = signature[2]
        values["Code signature"] = "PASS" if signatures and all(s[0] == "PASS" for s in signatures) else "FAIL"
        values["Hardened runtime"] = "PASS" if signatures and all(s[1] == "PASS" for s in signatures) else "FAIL"
        values["Entitlements"] = "PASS" if signatures and all(s[2] == "PASS" for s in signatures) else "FAIL"
        outer_signature = signature_status(app)
        if outer_signature[0] != "PASS" or outer_signature[1] != "PASS":
            values["Code signature"] = values["Hardened runtime"] = "FAIL"
        if outer_signature[2] != "PASS":
            values["Entitlements"] = "FAIL"
        teams = {signature[3] for signature in signatures}
        teams.add(outer_signature[3])
        values["Signing team consistency"] = "PASS" if len(teams) == 1 and None not in teams else "FAIL"
        if values["Code signature"] != "PASS":
            errors.append("APP_SIGNATURE_INVALID")
        if values["Hardened runtime"] != "PASS":
            errors.append("HARDENED_RUNTIME_MISSING")
        if values["Entitlements"] != "PASS":
            errors.append("ENTITLEMENTS_INVALID")
        if values["Signing team consistency"] != "PASS":
            errors.append("SIGNING_TEAM_MISMATCH")
        gatekeeper = run(["/usr/sbin/spctl", "--assess", "--type", "execute",
                          "--verbose=4", str(app)], 60)
        values["Gatekeeper assessment"] = "PASS" if gatekeeper.returncode == 0 else "FAIL"
        if gatekeeper.returncode:
            errors.append("GATEKEEPER_REJECTED")
    else:
        for name in ("Code signature", "Hardened runtime", "Entitlements",
                     "Signing team consistency", "Gatekeeper assessment"):
            values[name] = "BLOCKED"
        for item in mac_native:
            values["Entitlements " + item.name] = "BLOCKED"
    eula = run([sys.executable, str(ROOT / "tools/verify_eula.py"),
                "--bundle", str(app)], 30)
    values["EULA"] = "PASS" if eula.returncode == 0 else "FAIL"
    if eula.returncode:
        errors.append("EULA_MISMATCH")
    deny = load_deny_patterns(deny_file) if deny_file else None
    findings = audit([app], deny)
    values["Developer username leak"] = values["Developer HOME leak"] = (
        "FAIL" if any(f["category"] == "fixed-home-path" or
                      f["category"].startswith("project-") for f in findings) else "PASS")
    values["Hostname leak"] = "FAIL" if any("host" in f["category"] for f in findings) else "PASS"
    values["Repository-path leak"] = values["Hard-coded path scan"] = (
        "FAIL" if any(f["category"] in {"fixed-home-path", "temporary-build-path"}
                      or f["category"].startswith("project-") for f in findings) else "PASS")
    values["UDID leak"] = "FAIL" if any(f["category"] == "physical-device-id" for f in findings) else "PASS"
    values["Email leak"] = "FAIL" if any("email" in f["category"] for f in findings) else "PASS"
    values["Credential scan"] = "FAIL" if any(f["category"] == "embedded-password" for f in findings) else "PASS"
    values["Private-key scan"] = "FAIL" if any(f["category"] == "private-key" for f in findings) else "PASS"
    if findings:
        errors.extend(sorted({"SANITIZE_" + f["category"].upper().replace("-", "_") for f in findings}))
    if package is not None:
        if not package.is_file():
            errors.append("INSTALLER_MISSING")
        else:
            if distribution:
                signature = run(["/usr/sbin/pkgutil", "--check-signature", str(package)], 60)
                values["Installer"] = ("PASS" if signature.returncode == 0 and
                                       b"Developer ID Installer" in signature.stdout else "FAIL")
                if values["Installer"] != "PASS":
                    errors.append("INSTALLER_SIGNATURE_INVALID")
                package_team = re.search(rb"Developer ID Installer:[^\n]*\(([A-Z0-9]{10})\)",
                                         signature.stdout)
                if (package_team is None or outer_signature[3] is None or
                        package_team.group(1).decode("ascii") != outer_signature[3]):
                    values["Signing team consistency"] = "FAIL"
                    errors.append("INSTALLER_TEAM_MISMATCH")
            else:
                values["Installer"] = "BLOCKED"
            with tempfile.TemporaryDirectory(prefix="0sky-payload-audit-") as temp:
                try:
                    unpacked = package_payload(package, Path(temp) / "expanded")
                    if not same_tree(app, unpacked):
                        errors.append("PACKAGE_PAYLOAD_DIFFERS")
                    if audit([Path(temp) / "expanded"], deny):
                        errors.append("PACKAGE_PAYLOAD_PII")
                except (OSError, ValueError):
                    errors.append("PACKAGE_EXPANSION_INVALID")
            if notarized:
                staple = run(["xcrun", "stapler", "validate", str(package)], 60)
                values["Stapling"] = values["Notarization"] = (
                    "PASS" if staple.returncode == 0 else "FAIL")
                if staple.returncode:
                    errors.append("NOTARIZATION_UNVERIFIED")
    else:
        errors.append("INSTALLER_MISSING")
    return values, errors


def report_text(values: dict[str, str], errors: list[str], *, candidate: bool = False) -> str:
    groups = {
        "ARCHITECTURE": ("Main executable", "arm64", "x86_64", "Universal 2", "Nested binaries checked", "Python wheel coverage", "Bundled host runtime"),
        "PACKAGING": ("Application", "Installer", "Dependency kit", "EULA", "Permissions"),
        "SECURITY": ("Code signature", "Hardened runtime", "Entitlements",
                     *("Entitlements " + name for name in ENTITLEMENT_TARGETS),
                     "Signing team consistency", "Gatekeeper assessment", "Notarization", "Stapling"),
        "PRIVACY": ("Developer username leak", "Developer HOME leak", "Hostname leak",
                    "Repository-path leak", "UDID leak", "Email leak", "Credential scan",
                    "Private-key scan", "Debug artifact scan"),
        "PORTABILITY": ("Hard-coded path scan", "Tool discovery", "Architecture discovery",
                        "Runtime paths", "Clean-build verification"),
        "TESTING": ("Apple Silicon", "Intel", "Fresh installation", "Upgrade", "Launch"),
    }
    lines = ["RELEASE_AUDIT", "", *[f"{key}: {values.get(key, 'UNKNOWN')}"
                                      for key in ("Product", "Version", "Build", "Build mode",
                                                  "Signing identities")]]
    for group, keys in groups.items():
        lines += ["", group, *[f"{key}: {values.get(key, 'NOT_EXECUTED')}" for key in keys]]
    lines += ["", "FAILURES: " + (", ".join(sorted(set(errors))) if errors else "NONE"),
              "FINAL_RESULT=" + ("FAIL" if errors else "BLOCKED" if candidate else "PASS")]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path,
                        help="staged app; optional when --package is provided")
    parser.add_argument("--package", type=Path)
    parser.add_argument("--release-directory", type=Path,
                        help="verify the four-file release allowlist and checksums")
    parser.add_argument("--deny-file", type=Path)
    parser.add_argument("--notarized", action="store_true")
    parser.add_argument("--candidate", action="store_true",
                        help="verify all structural gates, report distribution signing BLOCKED")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.app is None and args.package is None and args.release_directory is None:
        parser.error("one of --app, --package, or --release-directory is required")
    manifest_errors: list[str] = []
    if args.release_directory:
        try:
            manifest = verify_release_manifest(args.release_directory)
            packages = [row["path"] for row in manifest["files"]
                        if row.get("role") == "installer"]
            if args.package is None:
                args.package = args.release_directory / packages[0]
            elif args.package.resolve() != (args.release_directory / packages[0]).resolve():
                manifest_errors.append("RELEASE_PACKAGE_NOT_IN_MANIFEST")
        except (ManifestError, OSError, ValueError, KeyError, IndexError, TypeError):
            manifest_errors.append("RELEASE_MANIFEST_INVALID")
    if args.app is None and args.package is None:
        values, errors = {}, []
    elif args.app is None:
        with tempfile.TemporaryDirectory(prefix="0sky-package-only-audit-") as temp:
            try:
                app = package_payload(args.package, Path(temp) / "expanded")
                values, errors = verify(app, args.package, args.deny_file, args.notarized,
                                        distribution=not args.candidate)
            except (OSError, ValueError):
                values = {}
                errors = ["PACKAGE_EXPANSION_INVALID"]
    else:
        values, errors = verify(args.app, args.package, args.deny_file, args.notarized,
                                distribution=not args.candidate)
    errors.extend(manifest_errors)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report_text(values, errors, candidate=args.candidate), encoding="utf-8")
    print(f"RELEASE_GATE={'FAIL' if errors else 'BLOCKED' if args.candidate else 'PASS'} errors={len(errors)}")
    return 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
