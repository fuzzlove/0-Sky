#!/usr/bin/env python3
"""Build a signed Universal 2 package from explicit, verified release inputs."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile

try:
    from .release_manifest import ManifestError, generate as generate_release_manifest
    from .release_paths import ReleasePaths
    from .signing_identities import discover, require_identity, resolve_identity
    from .verify_release import REQUIRED_MAC_BINARIES, report_text
except ImportError:
    from release_manifest import ManifestError, generate as generate_release_manifest
    from release_paths import ReleasePaths
    from signing_identities import discover, require_identity, resolve_identity
    from verify_release import REQUIRED_MAC_BINARIES, report_text


ROOT = Path(__file__).resolve().parents[1]


class ReleaseFailure(Exception):
    def __init__(self, stage: str, code: str):
        super().__init__(code)
        self.stage = stage
        self.code = code


def preflight_failure_code(payload: bytes) -> str:
    """Return a stable actionable code without copying local paths to logs."""
    try:
        value = json.loads(payload)
    except (TypeError, ValueError):
        return "BLOCKED_ENVIRONMENT"
    if value.get("host_runtime", {}).get("status") == "BLOCKED":
        return "BLOCKED_HOST_RUNTIME_MISSING_OR_INVALID"
    if value.get("kit", {}).get("status") == "BLOCKED":
        return "BLOCKED_KIT_HASH_MANIFEST_INVALID"
    failed_tools = sorted(item.get("tool", "unknown") for item in value.get("toolchain", [])
                          if item.get("status") == "FAIL")
    if failed_tools:
        return "BLOCKED_TOOL_MISSING_OR_INCOMPATIBLE:" + ",".join(failed_tools)
    if value.get("configuration", {}).get("status") == "BLOCKED":
        return "BLOCKED_CONFIGURATION_INVALID"
    return "BLOCKED_ENVIRONMENT"


def remediation_for(code: str) -> str:
    if "NOTARY_PROFILE" in code:
        return ("Create an app-specific password at appleid.apple.com, then store the profile with "
                "`xcrun notarytool store-credentials 0-sky-release --apple-id YOUR_APPLE_ID "
                "--team-id YOUR_TEAM_ID --password YOUR_APP_SPECIFIC_PASSWORD`; rerun with "
                "--notary-profile 0-sky-release")
    if "NOT_ACCEPTED" in code or "NOTARIZE" in code:
        return ("Run `xcrun notarytool history --keychain-profile 0-sky-release` to obtain the "
                "submission ID, then `xcrun notarytool log SUBMISSION_ID --keychain-profile "
                "0-sky-release`; correct every reported signing or bundle issue and rebuild")
    if "EXTERNAL_KIT_MISSING" in code or "KIT_HASH_MANIFEST_INVALID" in code:
        return ("Obtain the complete authorized offline kit from the release owner, copy it to a "
                "writable directory outside the repository, confirm it contains SHA256SUMS, then "
                "rerun with --kit '/absolute/path/to/authorized kit'. Do not copy pairing records, "
                "device credentials, or an installed app's kit into the source tree")
    if "SIGNING_IDENTITY" in code:
        return ("Import valid Developer ID Application and Developer ID Installer certificates "
                "with their private keys into the login keychain. If exactly one valid identity "
                "of each type is present, the release command selects them automatically. If "
                "multiple identities of either type are present, list SHA-1 fingerprints with "
                "`security find-identity -v -p basic`, then pass the intended values through "
                "--app-identity and --installer-identity")
    if code == "BLOCKED_HOST_RUNTIME_MISSING_OR_INVALID" or "HOST_RUNTIME_SOURCE_MISSING" in code:
        return ("Run `python3 tools/build_host_runtime.py /absolute/path/to/a-writable-kit-copy`; "
                "the command prints the exact pinned archive URL, cache destination, expected "
                "SHA-256, and verification command when an input is unavailable; the canonical "
                "build normally performs this repair automatically")
    privacy_categories = ("FIXED_HOME_PATH", "DERIVED_DATA_PATH", "ABSOLUTE_FILE_URI",
                          "MOUNTED_VOLUME_PATH", "LOCAL_IP_ADDRESS", "PRIVATE_KEY",
                          "EMBEDDED_PASSWORD", "PERSONAL_PAYMENT")
    if any(category in code for category in privacy_categories):
        return ("Run `python3 tools/kit_pii_report.py KIT artifacts/release-kit-pii.json` and keep "
                "that mode-0600 report outside Git. For every native or signed finding, correct "
                "the canonical source/build prefix maps, rebuild, re-sign, and update SHA256SUMS. "
                "For wheel/DEB examples or test fixtures, replace them with a minimal reproducible "
                "source build that omits non-runtime tests; never globally allowlist the pattern. "
                "Remove payment/personal URLs in canonical source and rebuild. Then rerun "
                "the release command")
    if "THEOS" in code:
        return ("Run `git clone --recursive https://github.com/theos/theos.git "
                "'/absolute/path/to/theos'`, `git -C '/absolute/path/to/theos' checkout "
                "dd5c14bb9d91311e221d51b5bfb8c9e5948156db`, and `git -C "
                "'/absolute/path/to/theos' submodule update --init --recursive`; then rerun with "
                "--theos '/absolute/path/to/theos'. Preserve any existing modified checkout")
    if "TOOL_MISSING_OR_INCOMPATIBLE" in code or "TOOL_MISSING:" in code:
        return ("Run `python3 tools/environment_preflight.py --human --mode release "
                "--kit /absolute/path/to/kit --skip-device` and perform each printed command")
    return ("Run `python3 tools/environment_preflight.py --human --mode development "
            "--kit /absolute/path/to/kit --skip-device`, correct the first non-PASS item, and retry")


def execute(stage: str, argv: list[str], *, timeout: int,
            environment: dict[str, str] | None = None) -> None:
    try:
        result = subprocess.run(argv, cwd=ROOT, env=environment, capture_output=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseFailure(stage, type(error).__name__.upper()) from error
    if result.returncode:
        categories = sorted(set(re.findall(rb'"category"\s*:\s*"([a-z0-9-]+)"',
                                           result.stdout + result.stderr)))
        category_code = ":" + ",".join(x.decode("ascii").upper().replace("-", "_")
                                       for x in categories) if categories else ""
        raise ReleaseFailure(stage, f"EXIT_{result.returncode}{category_code}")
    print(f"[PASS] {stage}", flush=True)


def submit_notarization(package: Path, profile: str) -> None:
    try:
        result = subprocess.run(
            ["xcrun", "notarytool", "submit", str(package),
             "--keychain-profile", profile, "--wait", "--output-format", "json"],
            cwd=ROOT, capture_output=True, timeout=3600, check=False)
        if result.returncode or json.loads(result.stdout).get("status") != "Accepted":
            raise ReleaseFailure("NOTARIZE", "NOT_ACCEPTED")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        raise ReleaseFailure("NOTARIZE", type(error).__name__.upper()) from error
    print("[PASS] NOTARIZE", flush=True)


def make_deny_file(destination: Path, staging: Path, output: Path,
                   extra: Path | None = None) -> None:
    """Keep build-machine identifiers in a private temporary file only."""
    values: dict[str, str] = {}
    home = str(Path.home().resolve())
    for label, value in (("builder-home", home),
                         ("checkout", str(ROOT.resolve())),
                         ("staging", str(staging.resolve())),
                         ("output", str(output.resolve()))):
        if value and len(value) > 3:
            values[label] = re.escape(value)
    for label, value in (("username", os.environ.get("USER", "")),
                         ("hostname", socket.gethostname()),
                         ("git-email", os.environ.get("GIT_AUTHOR_EMAIL", ""))):
        if value and len(value) > 3 and value not in {"root", "admin", "user"}:
            values[label] = "(?i)" + re.escape(value)
    try:
        local_addresses = {item[4][0].split("%")[0]
                           for item in socket.getaddrinfo(socket.gethostname(), None)}
    except OSError:
        local_addresses = set()
    for index, address in enumerate(sorted(local_addresses)):
        parsed = ipaddress.ip_address(address)
        if parsed.is_private and not parsed.is_loopback:
            values[f"local-address-{index}"] = re.escape(address)
    for index, identifier in enumerate(os.environ.get("ZERO_SKY_RELEASE_DEVICE_IDS", "").split(",")):
        identifier = identifier.strip()
        if identifier:
            if not re.fullmatch(r"[A-Za-z0-9-]{20,80}", identifier):
                raise ReleaseFailure("DENYLIST", "INVALID_DEVICE_IDENTIFIER")
            values[f"device-{index}"] = re.escape(identifier)
    if extra:
        data = json.loads(extra.read_text(encoding="utf-8"))
        additional = data.get("patterns")
        if not isinstance(additional, dict):
            raise ReleaseFailure("DENYLIST", "INVALID_EXTRA_DENYLIST")
        for label, pattern in additional.items():
            if not isinstance(label, str) or not isinstance(pattern, str):
                raise ReleaseFailure("DENYLIST", "INVALID_EXTRA_DENYLIST")
            re.compile(pattern)
            values["custom-" + label] = pattern
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump({"patterns": values}, stream, sort_keys=True)
        stream.write("\n")


def build(kit: Path, output: Path, mode: str, app_identity: str | None,
          installer_identity: str | None, notary_profile: str | None,
          extra_deny: Path | None, theos: Path | None = None) -> int:
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        print("RELEASE_GATE=FAIL stage=OUTPUT error=UNSAFE_OUTPUT_DIRECTORY", file=sys.stderr)
        return 2
    output.mkdir(parents=True, exist_ok=True)
    existing = {item.name for item in output.iterdir()}
    if existing - {"RELEASE_AUDIT.txt"}:
        print("RELEASE_GATE=FAIL stage=OUTPUT error=OUTPUT_NOT_EMPTY", file=sys.stderr)
        return 2
    prior_report = output / "RELEASE_AUDIT.txt"
    if prior_report.is_symlink():
        print("RELEASE_GATE=FAIL stage=OUTPUT error=UNSAFE_OUTPUT_REPORT", file=sys.stderr)
        return 2
    if prior_report.exists():
        prior_report.unlink()
    report = output / "RELEASE_AUDIT.txt"
    stage = "PREFLIGHT"
    state: dict[str, str] = {"Product": "0-Sky Bridge", "Version": "UNKNOWN",
                             "Build": "UNKNOWN", "EULA": "NOT_EXECUTED"}
    try:
        try:
            identities = discover()
        except RuntimeError as error:
            raise ReleaseFailure("SIGNING_PREFLIGHT", "IDENTITY_DISCOVERY_FAILED") from error
        state["Signing identities"] = ",".join(sorted({item.category for item in identities})) or "NONE"
        state["Build mode"] = mode
        if mode == "distribution":
            try:
                app_identity = resolve_identity(
                    app_identity, "Developer ID Application", identities)
                installer_identity = resolve_identity(
                    installer_identity, "Developer ID Installer", identities)
            except RuntimeError as error:
                raise ReleaseFailure("SIGNING_PREFLIGHT", str(error)) from error
            if not notary_profile:
                raise ReleaseFailure("SIGNING_PREFLIGHT", "BLOCKED_MISSING_NOTARY_PROFILE")
        elif mode == "development" and app_identity:
            try:
                app_identity = require_identity(app_identity, "Apple Development", identities)
            except RuntimeError as error:
                raise ReleaseFailure("SIGNING_PREFLIGHT", "DEVELOPMENT_IDENTITY_UNAVAILABLE") from error
        else:
            app_identity = None
        if mode != "distribution":
            installer_identity = None
            notary_profile = None
        source_info = plistlib.loads((ROOT / "bridge/0SkyBridge/Info.plist").read_bytes())
        state["Version"] = str(source_info.get("CFBundleShortVersionString", "UNKNOWN"))
        state["Build"] = str(source_info.get("CFBundleVersion", "UNKNOWN"))
        required = ("python3", "xcodebuild", "xcrun", "codesign", "pkgbuild",
                    "productsign", "pkgutil", "spctl", "ditto")
        missing = [tool for tool in required if not shutil.which(tool)]
        if missing:
            raise ReleaseFailure(stage, "TOOL_MISSING:" + ",".join(missing))
        if not kit.is_dir() or not (kit / "SHA256SUMS").is_file():
            raise ReleaseFailure(stage, "EXTERNAL_KIT_MISSING")
        theos = (theos or (Path(os.environ["THEOS"]) if os.environ.get("THEOS") else None))
        if theos is None or not (theos / "makefiles/common.mk").is_file():
            raise ReleaseFailure("THEOS_PREFLIGHT", "THEOS_UNAVAILABLE")
        theos = theos.resolve()
        try:
            preflight = subprocess.run(
                [sys.executable, str(ROOT / "tools/environment_preflight.py"),
                 "--mode", "development", "--kit", str(kit),
                 "--theos", str(theos), "--skip-device"],
                cwd=ROOT, capture_output=True, timeout=90, check=False)
        except subprocess.TimeoutExpired as error:
            raise ReleaseFailure(stage, "ENVIRONMENT_TIMEOUT") from error
        if preflight.returncode:
            code = preflight_failure_code(preflight.stdout)
            if code == "BLOCKED_HOST_RUNTIME_MISSING_OR_INVALID":
                print("[REPAIR] PREFLIGHT pinned host runtime will be assembled", flush=True)
            else:
                raise ReleaseFailure(stage, code)
        discovered = json.loads(preflight.stdout)
        if discovered.get("kit", {}).get("status") != "PASS" or any(
            item.get("status") != "PASS" for item in discovered.get("toolchain", [])
            if item.get("tool") in {"xcrun", "xcodebuild", "python3", "ssh"}
        ):
            raise ReleaseFailure(stage, "DEPENDENCY_BLOCKED")
        state["Tool discovery"] = state["Architecture discovery"] = "PASS"
        print("[PASS] PREFLIGHT", flush=True)
        execute("EULA", [sys.executable, str(ROOT / "tools/verify_eula.py")],
                timeout=30)
        state["EULA"] = "PASS"
        build_environment = dict(os.environ)
        build_environment["THEOS"] = str(theos)
        execute("THEOS_PREFLIGHT", [sys.executable,
                str(ROOT / "tools/theos_preflight.py"), "--theos", str(theos)],
                timeout=60, environment=build_environment)
        with tempfile.TemporaryDirectory(prefix=".0sky-release-", dir=output.parent) as temp:
            work = Path(temp)
            paths = ReleasePaths.from_work(ROOT, work)
            deny = work / "deny.json"
            make_deny_file(deny, work, output, extra_deny)
            stage = "PREPARE_KIT"
            prepared = paths.kit_root
            execute(stage, [sys.executable, str(ROOT / "tools/prepare_release_kit.py"),
                            str(kit), str(prepared), "--deny-file", str(deny)], timeout=900,
                    environment=build_environment)
            execute("HOST_RUNTIME", [sys.executable,
                    str(ROOT / "tools/host_runtime_manifest.py"), str(prepared)], timeout=60)
            stage = "BUILD_UNIVERSAL_APP"
            derived = paths.build_root
            environment = dict(build_environment)
            environment["ZERO_SKY_RELEASE_DENY_FILE"] = str(deny)
            execute(stage, [str(ROOT / "build.sh"), "--kit", str(prepared),
                            "--derived-data", str(derived)], timeout=1800,
                    environment=environment)
            built = derived / "Build/Products/Release/0SkyBridge.app"
            if not built.is_dir():
                raise ReleaseFailure(stage, "APP_MISSING")
            stage = "STAGE_APP"
            staged_root = paths.staging_root
            app = paths.app_bundle
            app.parent.mkdir(parents=True)
            execute(stage, ["/usr/bin/ditto", "--noqtn", str(built), str(app)],
                    timeout=300)
            stage = "SIGN_NESTED_CODE"
            entitlement = {
                "Contents/MacOS/0SkyBridgeService": ROOT / "bridge/0SkyBridgeService/0SkyBridgeService.entitlements",
                "Contents/Library/LaunchServices/0SkyBridgeHelper": ROOT / "bridge/0SkyBridgeHelper/0SkyBridgeHelper.entitlements",
            }
            if app_identity:
                for relative in sorted(REQUIRED_MAC_BINARIES - {"Contents/MacOS/0SkyBridge"}):
                    target = app / relative
                    if not target.is_file():
                        raise ReleaseFailure(stage, "REQUIRED_BINARY_MISSING")
                    command = ["/usr/bin/codesign", "--force", "--sign", app_identity,
                               "--options", "runtime",
                               "--timestamp" if mode == "distribution" else "--timestamp=none"]
                    if relative in entitlement:
                        command += ["--entitlements", str(entitlement[relative])]
                    execute(stage, command + [str(target)], timeout=120)
                execute("REHASH_SIGNED_KIT", [sys.executable,
                        str(ROOT / "tools/kit_manifest.py"), "generate",
                        str(app / "Contents/Resources/Kit")], timeout=180)
                stage = "SIGN_APP"
                execute(stage, ["/usr/bin/codesign", "--force", "--sign", app_identity,
                                "--options", "runtime",
                                "--timestamp" if mode == "distribution" else "--timestamp=none",
                                "--entitlements",
                                str(ROOT / "bridge/0SkyBridge/0SkyBridge.entitlements"),
                                str(app)], timeout=180)
                execute("VERIFY_APP_SIGNATURE", ["/usr/bin/codesign", "--verify", "--deep",
                                                  "--strict", str(app)], timeout=120)
            stage = "PACKAGE"
            info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
            version = str(info.get("CFBundleShortVersionString", ""))
            if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
                raise ReleaseFailure(stage, "INVALID_VERSION")
            unsigned_pkg = work / "unsigned.pkg"
            package = work / f"0-Sky-Bridge-{version}-{mode}-universal.pkg"
            execute(stage, ["/usr/bin/pkgbuild", "--root", str(staged_root),
                            "--identifier", "com.liquidsky.0sky.bridge.pkg",
                            "--version", version, "--install-location", "/",
                            "--ownership", "recommended",
                            str(unsigned_pkg)], timeout=300)
            if mode == "distribution":
                execute("SIGN_INSTALLER", ["/usr/bin/productsign", "--sign",
                                           installer_identity, str(unsigned_pkg), str(package)],
                        timeout=300)
            else:
                unsigned_pkg.replace(package)
            notarized = False
            if notary_profile:
                stage = "NOTARIZE"
                submit_notarization(package, notary_profile)
                execute("STAPLE", ["xcrun", "stapler", "staple", str(package)],
                        timeout=180)
                notarized = True
            stage = "VERIFY_RELEASE"
            command = [sys.executable, str(ROOT / "tools/verify_release.py"),
                       "--app", str(app), "--package", str(package),
                       "--deny-file", str(deny), "--report", str(report)]
            if mode != "distribution":
                command.append("--candidate")
            if notarized:
                command.append("--notarized")
            execute(stage, command, timeout=900)
            content = report.read_text(encoding="utf-8")
            content = content.replace("Clean-build verification: NOT_EXECUTED",
                                      "Clean-build verification: PASS")
            content = content.replace("Build mode: UNKNOWN", f"Build mode: {mode}")
            content = content.replace("Signing identities: UNKNOWN",
                                      f"Signing identities: {state['Signing identities']}")
            report.write_text(content, encoding="utf-8")
            stage = "RELEASE_MANIFEST"
            release_directory = work / "release"
            release_directory.mkdir(mode=0o755)
            package.replace(release_directory / package.name)
            report.replace(release_directory / report.name)
            generate_release_manifest(
                release_directory, package.name, product="0-Sky Bridge", version=version,
                build=state["Build"], mode=mode)
            stage = "PUBLISH"
            if output.is_symlink() or any(output.iterdir()):
                raise ReleaseFailure(stage, "OUTPUT_CHANGED_DURING_BUILD")
            output.rmdir()
            os.replace(release_directory, output)
            print(f"{'RELEASE' if mode == 'distribution' else 'NON_PUBLIC_CANDIDATE'}_PACKAGE={package.name}")
            return 0
    except (ReleaseFailure, ManifestError, OSError, ValueError, json.JSONDecodeError) as error:
        if not output.exists():
            output.mkdir(parents=True, mode=0o755)
        report = output / "RELEASE_AUDIT.txt"
        if output.is_symlink() or not output.is_dir() or report.is_symlink():
            print("RELEASE_GATE=FAIL stage=OUTPUT error=UNSAFE_FAILURE_REPORT",
                  file=sys.stderr)
            return 2
        if isinstance(error, ReleaseFailure):
            stage, code = error.stage, error.code
        else:
            code = type(error).__name__.upper()
        if stage == "VERIFY_RELEASE" and report.is_file():
            with report.open("a", encoding="utf-8") as stream:
                stream.write(f"FIRST_FAILING_STAGE={stage}\nSANITIZED_ERROR={code}\n"
                             f"REQUIRED_ACTION={remediation_for(code)}\n")
        else:
            if "FIXED_HOME_PATH" in code:
                state["Developer HOME leak"] = state["Developer username leak"] = "FAIL"
            text = report_text(state, [code]).rstrip()
            if code.startswith("BLOCKED_"):
                text = text.replace("FINAL_RESULT=FAIL", "FINAL_RESULT=BLOCKED")
            report.write_text(text +
                              f"\nFIRST_FAILING_STAGE={stage}\nSANITIZED_ERROR={code}\n"
                              f"REQUIRED_ACTION={remediation_for(code)}\n",
                              encoding="utf-8")
        status = "BLOCKED" if code.startswith("BLOCKED_") else "FAIL"
        print(f"RELEASE_GATE={status} stage={stage} error={code}", file=sys.stderr)
        print(f"NEXT_STEP={remediation_for(code)}", file=sys.stderr)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit", type=Path, required=True,
                        help="separately obtained, manifest-verified external kit")
    parser.add_argument("--mode", choices=("development", "release-candidate", "distribution"),
                        required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--app-identity", default=os.environ.get("ZERO_SKY_APP_IDENTITY"))
    parser.add_argument("--installer-identity", default=os.environ.get("ZERO_SKY_INSTALLER_IDENTITY"))
    parser.add_argument("--notary-profile", default=os.environ.get("ZERO_SKY_NOTARY_PROFILE"))
    parser.add_argument("--deny-file", type=Path)
    parser.add_argument("--theos", type=Path,
                        help="reviewed Theos checkout (or set THEOS)")
    args = parser.parse_args()
    return build(args.kit.resolve(), args.output.resolve(), args.mode, args.app_identity,
                 args.installer_identity, args.notary_profile,
                 args.deny_file.resolve() if args.deny_file else None,
                 args.theos.resolve() if args.theos else None)


if __name__ == "__main__":
    raise SystemExit(main())
