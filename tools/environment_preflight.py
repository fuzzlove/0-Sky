#!/usr/bin/env python3
"""Read-only 0-Sky host, toolchain, kit, configuration, and device preflight."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bridge"))
from zero_sky_user_config import UserConfigError, config_path, load  # noqa: E402
try:
    from .host_runtime_manifest import RuntimeManifestError, verify as verify_host_runtime
    from .signing_identities import discover as discover_signing_identities
    from .theos_preflight import THEOS_INSTALL, TheosError, verify as verify_theos
except ImportError:
    from host_runtime_manifest import RuntimeManifestError, verify as verify_host_runtime
    from signing_identities import discover as discover_signing_identities
    from theos_preflight import THEOS_INSTALL, TheosError, verify as verify_theos


def command(argv: list[str], timeout: int = 8) -> tuple[int | None, str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=timeout, check=False)
        return result.returncode, (result.stdout.strip() or result.stderr.strip())[:512]
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def architecture(machine: str, translated: bool = False) -> dict[str, object]:
    process = machine.lower()
    if process not in {"arm64", "x86_64"}:
        return {"status": "BLOCKED", "process": process, "native": None,
                "rosetta": False}
    return {"status": "PASS", "process": process,
            "native": "arm64" if translated else process,
            "rosetta": translated}


def safe_tool_path(value: str | None) -> str | None:
    """Keep useful system locations without disclosing account-local paths."""
    if value is None:
        return None
    home = str(Path.home())
    if value.startswith(home + os.sep):
        return "~" + value[len(home):]
    if value.startswith(("/usr/", "/bin/", "/sbin/", "/opt/homebrew/",
                         "/usr/local/", "/Applications/")):
        return value
    return "<configured-tool>/" + Path(value).name


def resolve_tool(name: str, *, required: bool,
                 search_path: str | None = None,
                 version_args: tuple[str, ...] = ("--version",),
                 required_prefix: str | None = None) -> dict[str, object]:
    """Discover one executable; version mismatch is a failure, not success."""
    path = shutil.which(name, path=search_path)
    if path is None:
        instructions = {
            "xcrun": "Install full Xcode from the Mac App Store, open it once, then run: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer && sudo xcodebuild -license accept; verify with: xcrun --version",
            "xcodebuild": "Install full Xcode from the Mac App Store, open it once, then run: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer && sudo xcodebuild -license accept; verify with: xcodebuild -version",
            "python3": "Install Python 3.12 or later using the universal2 macOS installer from https://www.python.org/downloads/macos/ or run: brew install python@3.12; open a new Terminal and verify: python3 --version",
            "ssh": "Install all pending macOS updates. If /usr/bin/ssh is still absent, reinstall the current macOS release from macOS Recovery; do not download an SSH binary from an unverified site",
            "iproxy": "No manual install is needed for a packaged build; rebuild the pinned host runtime. Source-only fallback: brew install libusbmuxd",
            "idevice_id": "No manual install is needed for a packaged build; rebuild the pinned host runtime. Source-only fallback: brew install libimobiledevice",
        }
        return {"tool": name, "status": "FAIL" if required else "DEGRADED",
                "resolved_path": None, "version": None,
                "source": "PATH", "remediation": instructions.get(name, f"Install {name} and add its executable directory to PATH")}
    path = str(Path(path).resolve())
    code, version = command([path, *version_args])
    if code != 0 or not version or (required_prefix and not version.startswith(required_prefix)):
        instructions = {
            "xcrun": ("Install or repair full Xcode, then run: sudo xcode-select -s "
                      "/Applications/Xcode.app/Contents/Developer && sudo xcodebuild -license accept; "
                      "verify with: xcrun --version"),
            "xcodebuild": ("Open Xcode once to finish component installation, then run: sudo "
                           "xcode-select -s /Applications/Xcode.app/Contents/Developer && sudo "
                           "xcodebuild -license accept; verify with: xcodebuild -version"),
            "python3": ("Install Python 3.12 or later using the universal2 macOS installer from "
                        "https://www.python.org/downloads/macos/ or run: brew install python@3.12; "
                        "open a new Terminal and verify: python3 --version"),
            "ssh": ("Install all pending macOS updates. If /usr/bin/ssh still fails, reinstall the "
                    "current macOS release from macOS Recovery; do not download an SSH binary from an unverified site."),
        }
        return {"tool": name, "status": "FAIL" if required else "DEGRADED",
                "resolved_path": path, "version": version or None,
                "source": "PATH", "remediation": instructions.get(
                    name, f"Replace {name} with a compatible version and confirm it by running: "
                    f"{name} {' '.join(version_args)}")}
    return {"tool": name, "status": "PASS", "resolved_path": path,
            "version": version.splitlines()[0], "source": "PATH"}


def inspect_kit(kit: Path) -> dict[str, object]:
    manifest = kit / "SHA256SUMS"
    if not manifest.is_file() or manifest.is_symlink():
        return {"status": "BLOCKED", "manifest_entries": 0,
                "remediation": "Obtain the authorized 0-Sky offline kit, then pass its directory with: --kit '/absolute/path/to/kit'; the directory must contain SHA256SUMS"}
    try:
        lines = [line for line in manifest.read_text(encoding="utf-8").splitlines()
                 if line.strip()]
        if len(lines) < 10:
            raise ValueError("small manifest")
        for line in lines:
            digest, raw = line.split(None, 1)
            relative = raw.strip().lstrip("*").removeprefix("./")
            if not re.fullmatch(r"[0-9a-f]{64}", digest) or not relative:
                raise ValueError("invalid manifest")
            path = kit / relative
            if (Path(relative).is_absolute() or ".." in Path(relative).parts
                    or not path.is_file() or kit.resolve() not in path.resolve().parents):
                raise ValueError("unsafe or missing kit file")
            value = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    value.update(chunk)
            if value.hexdigest() != digest:
                raise ValueError("kit digest mismatch")
        return {"status": "PASS", "manifest_entries": len(lines)}
    except (OSError, ValueError):
        return {"status": "BLOCKED", "manifest_entries": 0,
                "remediation": "Do not edit payloads in place. Restore the authorized kit and verify it with: python3 tools/stage_verified_kit.py KIT /tmp/verified-kit"}


def inspect_device(udid: str | None, xcrun: str | None) -> dict[str, object]:
    if udid is None:
        return {"status": "DEGRADED", "selected": False,
                "remediation": "Pass --udid for exact-device verification"}
    if not re.fullmatch(r"[A-Za-z0-9-]{20,80}", udid):
        return {"status": "BLOCKED", "selected": True,
                "remediation": "Supply a valid exact device UDID"}
    identifier = hashlib.sha256(udid.encode()).hexdigest()[:12]
    if xcrun is None:
        return {"status": "BLOCKED", "selected": True, "device_hash": identifier,
                "remediation": "Install/select Xcode before device discovery"}
    with tempfile.TemporaryDirectory(prefix="0sky-preflight-") as temporary:
        destination = Path(temporary) / "devices.json"
        code, _ = command([xcrun, "devicectl", "list", "devices",
                           "--json-output", str(destination)], timeout=30)
        if code != 0 or not destination.is_file():
            return {"status": "DEGRADED", "selected": True, "device_hash": identifier,
                    "remediation": "CoreDevice did not provide a device inventory"}
        try:
            data = json.loads(destination.read_text(encoding="utf-8"))
            devices = data.get("result", {}).get("devices", [])
            matches = [item for item in devices if
                       item.get("hardwareProperties", {}).get("udid") == udid]
        except (OSError, ValueError, AttributeError):
            matches = []
        return {"status": "PASS" if len(matches) == 1 else "BLOCKED",
                "selected": True, "device_hash": identifier,
                "exact_matches": len(matches),
                **({} if len(matches) == 1 else
                   {"remediation": "Connect and select the exact authorized SRD"})}


def validate_notary_profile(profile: str) -> bool:
    """Authenticate a named Keychain profile without exposing account data."""
    code, _ = command(["/usr/bin/xcrun", "notarytool", "history",
                       "--keychain-profile", profile,
                       "--output-format", "json"], timeout=45)
    return code == 0


def report(*, mode: str, kit: Path | None = None, udid: str | None = None,
           config_file: Path | None = None,
           theos: Path | None = None,
           notary_profile: str | None = None,
           environment: Mapping[str, str] | None = None,
           search_path: str | None = None,
           discover_device: bool = True) -> dict[str, object]:
    env = os.environ if environment is None else environment
    source = kit or Path(env.get("ZERO_SKY_KIT_SOURCE",
                                  ROOT / "bridge/0SkyBridge/Resources/Scripts/kit"))
    try:
        config = load(ROOT, config_file, environment=env)
        configuration: dict[str, object] = {
            "status": "PASS", "source": "explicit config" if config_file else
            ("ZERO_SKY_CONFIG" if env.get("ZERO_SKY_CONFIG") else "per-user default"),
            "loaded": config_path(config_file, env).is_file(),
            "support": "~" + config["paths"]["support"][len(str(Path.home())):]
            if config["paths"]["support"].startswith(str(Path.home()) + os.sep)
            else "<configured-path>",
        }
    except (UserConfigError, OSError, ValueError) as error:
        configuration = {"status": "BLOCKED", "source": "configuration",
                         "remediation": type(error).__name__}
    tools = [
        resolve_tool("xcrun", required=True, search_path=search_path,
                     version_args=("--version",)),
        resolve_tool("xcodebuild", required=True, search_path=search_path,
                     version_args=("-version",)),
        resolve_tool("python3", required=True, search_path=search_path,
                     version_args=("--version",)),
        resolve_tool("ssh", required=True, search_path=search_path,
                     version_args=("-V",)),
        resolve_tool("iproxy", required=False, search_path=search_path,
                     version_args=("--version",)),
        resolve_tool("idevice_id", required=False, search_path=search_path,
                     version_args=("--version",)),
    ]
    xcrun = next(item["resolved_path"] for item in tools if item["tool"] == "xcrun")
    device = inspect_device(udid, xcrun if isinstance(xcrun, str) else None) if discover_device else {
        "status": "DEGRADED", "selected": bool(udid), "remediation": "Device discovery skipped"}
    kit_result = inspect_kit(source)
    try:
        runtime_detail = verify_host_runtime(source.resolve(strict=True))
        host_runtime: dict[str, object] = {"status": "PASS", **runtime_detail}
    except (OSError, RuntimeManifestError, subprocess.SubprocessError) as error:
        host_runtime = {"status": "REPAIRABLE", "detail": str(error),
                        "remediation": "No global install is required. The canonical build assembles the pinned Intel/Apple-silicon runtime automatically; manually run: python3 tools/build_host_runtime.py '/absolute/path/to/a-writable-kit-copy'"}
    profile = notary_profile or env.get("ZERO_SKY_NOTARY_PROFILE")
    try:
        identity_categories = [item.category for item in discover_signing_identities()]
        app_count = identity_categories.count("Developer ID Application")
        installer_count = identity_categories.count("Developer ID Installer")
        discovery_error = False
    except RuntimeError:
        app_count = installer_count = 0
        discovery_error = True
    missing: list[str] = []
    if discovery_error:
        missing.append("Keychain identity discovery failed")
    if app_count == 0:
        missing.append("Developer ID Application certificate and private key")
    elif app_count > 1:
        missing.append("an explicit Developer ID Application fingerprint (multiple are installed)")
    if installer_count == 0:
        missing.append("Developer ID Installer certificate and private key")
    elif installer_count > 1:
        missing.append("an explicit Developer ID Installer fingerprint (multiple are installed)")
    notary_authenticated = bool(profile and validate_notary_profile(profile))
    if not profile:
        missing.append("a notarytool keychain profile")
    elif not notary_authenticated:
        missing.append("valid Apple credentials in the selected notarytool profile")
    release_ready = not missing
    security_status = ("PASS" if release_ready else
                       ("BLOCKED" if mode == "release" else "DEGRADED"))
    remediation_parts: list[str] = []
    if app_count == 0 or installer_count == 0:
        remediation_parts.append(
            "Create the missing certificate type at https://developer.apple.com/account/resources/certificates/list, "
            "upload the CSR that matches the private key, download the .cer file, and open it in Keychain Access.")
    if app_count > 1 or installer_count > 1:
        remediation_parts.append(
            "List valid SHA-1 fingerprints with: security find-identity -v -p basic; pass the intended values "
            "to scripts/build_release.sh with --app-identity and --installer-identity.")
    if not profile:
        remediation_parts.append(
            "Create an app-specific password at https://account.apple.com, then store it without placing the "
            "password in shell history: xcrun notarytool store-credentials 0-sky-release --apple-id "
            "YOUR_APPLE_ID --team-id YOUR_TEAM_ID; enter the app-specific password only at the secure prompt. "
            "Then rerun preflight with --notary-profile 0-sky-release.")
    elif not notary_authenticated:
        remediation_parts.append(
            "The selected profile did not authenticate. Generate a new app-specific password at "
            "https://account.apple.com, then replace the profile with: xcrun notarytool "
            "store-credentials 0-sky-release --apple-id YOUR_APPLE_ID --team-id YOUR_TEAM_ID; "
            "enter the password only at the secure prompt and verify with: xcrun notarytool "
            "history --keychain-profile 0-sky-release")
    if discovery_error:
        remediation_parts.append(
            "Open Keychain Access, unlock the login keychain, and verify with: security find-identity -v -p basic")
    security = {
        "status": security_status,
        "developer_id_application": "available" if app_count == 1 else
        ("missing" if app_count == 0 else "ambiguous"),
        "developer_id_installer": "available" if installer_count == 1 else
        ("missing" if installer_count == 0 else "ambiguous"),
        "notary_profile": "authenticated" if notary_authenticated else
        ("invalid" if profile else "missing"),
        "detail": "All distribution credentials are selected." if release_ready else
        "Missing or ambiguous: " + "; ".join(missing),
        "remediation": "\n".join(remediation_parts) or None,
    }
    theos_input = theos or (Path(env["THEOS"]).expanduser() if env.get("THEOS") else None)
    if theos_input is None:
        theos_result: dict[str, object] = {
            "status": "BLOCKED", "detail": "No locked Theos checkout was selected.",
            "remediation": THEOS_INSTALL,
        }
    else:
        try:
            checked = verify_theos(theos_input)
            theos_result = {"status": "PASS", **checked,
                            "path": safe_tool_path(str(theos_input.expanduser()))}
        except TheosError as error:
            theos_result = {"status": "BLOCKED", "code": error.code,
                            "detail": error.detail, "remediation": error.remediation}
        except (OSError, ValueError, KeyError) as error:
            theos_result = {"status": "BLOCKED", "detail": type(error).__name__,
                            "remediation": "Restore manifests/source-dependencies.json from the audited repository revision, then rerun preflight."}
    statuses = [item["status"] for item in tools if item["tool"] not in {"iproxy", "idevice_id"}]
    statuses += [configuration["status"], security["status"], kit_result["status"],
                 host_runtime["status"], theos_result["status"]]
    if udid:
        statuses.append(device["status"])
    _, translated_value = command(["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"], 2)
    host_arch = architecture(platform.machine(), translated_value == "1")
    statuses.append(host_arch["status"])
    overall = "BLOCKED" if "BLOCKED" in statuses or "FAIL" in statuses else (
        "DEGRADED" if {"DEGRADED", "REPAIRABLE"} & set(statuses) else "READY")
    for item in tools:
        item["resolved_path"] = safe_tool_path(item["resolved_path"])
    return {
        "system": {"os": platform.mac_ver()[0] or platform.system(),
                   "architecture": host_arch, "hostname": "<redacted>",
                   "application_support": configuration.get("support", "<unavailable>")},
        "toolchain": tools, "device": device,
        "configuration": configuration, "kit": kit_result,
        "host_runtime": host_runtime,
        "theos": theos_result,
        "security": security, "status": overall,
    }


def human_report(value: dict[str, object]) -> str:
    """Render a path-redacted checklist with exact repair actions."""
    lines = ["0-Sky build and installation preflight", "=" * 39,
             f"Overall status: {value['status']}", ""]
    items: list[tuple[str, dict[str, object]]] = []
    for tool in value.get("toolchain", []):
        items.append((f"Tool: {tool.get('tool')}", tool))
    for key, title in (("kit", "Authorized offline kit"),
                       ("host_runtime", "Bundled host runtime"),
                       ("theos", "Locked Theos source toolchain"),
                       ("configuration", "Per-user configuration"),
                       ("security", "Release signing"),
                       ("device", "Selected device")):
        item = value.get(key)
        if isinstance(item, dict): items.append((title, item))
    for title, item in items:
        status = str(item.get("status", "UNKNOWN"))
        lines.append(f"[{status}] {title}")
        detail = item.get("version") or item.get("detail") or item.get("resolved_path")
        if detail: lines.append(f"  Detected: {detail}")
        remediation = item.get("remediation")
        if remediation:
            lines.append("  Required action:")
            lines.extend(f"    {line}" for line in str(remediation).splitlines())
        lines.append("")
    if value["status"] == "READY":
        lines.append("All mandatory prerequisites are ready.")
    elif value["status"] == "DEGRADED":
        lines.append("The build can repair the REPAIRABLE items automatically. Review DEGRADED optional capabilities above.")
    else:
        lines.append("Resolve every FAIL or BLOCKED item above, then rerun this exact preflight command.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("development", "release"), default="development")
    parser.add_argument("--kit", type=Path)
    parser.add_argument("--theos", type=Path,
                        help="locked Theos checkout (or set THEOS)")
    parser.add_argument("--notary-profile",
                        help="notarytool keychain profile (or set ZERO_SKY_NOTARY_PROFILE)")
    parser.add_argument("--udid")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--skip-device", action="store_true")
    parser.add_argument("--human", action="store_true",
                        help="print a user-facing checklist and exact repair actions")
    args = parser.parse_args()
    value = report(mode=args.mode, kit=args.kit, udid=args.udid, theos=args.theos,
                   config_file=args.config, notary_profile=args.notary_profile,
                   discover_device=not args.skip_device)
    print(human_report(value) if args.human else json.dumps(value, indent=2, sort_keys=True),
          end="" if args.human else "\n")
    return 0 if value["status"] in {"READY", "DEGRADED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
