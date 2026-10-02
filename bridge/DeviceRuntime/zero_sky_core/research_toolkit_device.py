"""Read-only SRD discovery for the 0-Sky Security Research Toolkit."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import time
from zero_sky_compat.environment import _architecture_from_mach, _sysctl_integer

try:
    from .research_toolkit import (compatibility_for, evaluate, load_catalog,
                                   verify_artifact)
    from .sensors import PackageInventory
except ImportError:  # isolated model tests in the PoC workspace
    from research_toolkit import compatibility_for, evaluate, load_catalog, verify_artifact
    PackageInventory = None


APP_ROOTS = ("/private/var/containers/Bundle/Application/",
             "/var/containers/Bundle/Application/",
             "/private/var/run/com.apple.security.cryptexd/mnt/")
COMMAND_ROOTS = ("/var/jb/usr/bin", "/var/jb/usr/sbin", "/usr/bin", "/bin", "/usr/sbin")
COMMAND_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def adapted_tweak_evidence(paths, row: dict, package: dict | None,
                           ios_build: str | None, device_model: str | None, *,
                           receipt_override: Path | None = None,
                           process_run=None) -> dict | None:
    """Recognize one exact tested source port without reclassifying upstream."""
    if not package or not ios_build or not device_model:
        return None
    for variant in row.get("adapted_variants", []):
        if (package.get("version") != variant["package_version"] or
                {"model": device_model, "ios_build": ios_build} not in variant["verified_targets"]):
            continue
        dylib = paths.jailbreak(variant["dylib_path"])
        try:
            if dylib.is_symlink() or not dylib.is_file() or dylib.stat().st_size > 16 * 1024 * 1024:
                return None
            digest = hashlib.sha256()
            with dylib.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
        except OSError:
            return None
        if digest.hexdigest() != variant["dylib_sha256"]:
            return None
        result = {"compatibility": "COMPATIBLE_WITH_ADAPTER",
                  "compatibility_reason": "Exact 0-Sky source port and iOS build match reviewed adaptation metadata; repository admission remains blocked",
                  "runtime": "UNTESTED", "configured": False}
        receipt_path = receipt_override or Path(variant["receipt_path"])
        registry_path = paths.jailbreak("/var/lib/srd-runtime/registry.json")
        state_path = paths.jailbreak("/var/lib/srd-runtime/injection-state.json")
        try:
            if any(path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024
                   for path in (receipt_path, registry_path, state_path)):
                return result
            receipt = plistlib.loads(receipt_path.read_bytes())
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if (not isinstance(receipt, dict) or not isinstance(registry, dict) or
                    not isinstance(registry.get("quarantined", []), list) or
                    not isinstance(state, dict) or not isinstance(state.get("loaded", {}), dict)):
                return result
            required = ("native_authentication", "pattern_unlock", "wrong_pattern_rejected",
                        "keypad_fallback", "repeat_pattern_unlock", "springboard_stable")
            checked_at = receipt.get("verified_at")
            if (receipt.get("schema") != 1 or
                    receipt.get("package_version") != variant["package_version"] or
                    receipt.get("dylib_sha256") != variant["dylib_sha256"] or
                    receipt.get("device_model") != device_model or
                    receipt.get("ios_build") != ios_build or
                    not isinstance(checked_at, (int, float)) or
                    not 0 <= time.time() - checked_at <= 90 * 86400 or
                    any(receipt.get(key) is not True for key in required) or
                    any(isinstance(item, dict) and item.get("package") == row["package_identifier"]
                        for item in registry.get("quarantined", []))):
                return result
            process = (process_run or subprocess.run)(
                ["/bin/ps", "-A", "-o", "pid=", "-o", "comm="],
                capture_output=True, text=True, timeout=10, check=False)
            if process.returncode:
                return result
            pids = {int(parts[0]) for line in process.stdout.splitlines()
                    if len(parts := line.split(None, 1)) == 2 and parts[0].isdigit() and
                    parts[1].endswith("/" + variant["target_process"])}
            loaded = state.get("loaded", {})
            if any(item.get("pid") in pids and
                   item.get("sha256") == variant["dylib_sha256"] and
                   str(item.get("dylib", "")).endswith("/" + Path(variant["dylib_path"]).name)
                   for item in loaded.values() if isinstance(item, dict)):
                result.update(runtime="PASS", configured=True)
        except (OSError, ValueError, TypeError, plistlib.InvalidFileException,
                subprocess.TimeoutExpired):
            return result
        return result
    return None


def registered_apps(uicache: str = "/var/jb/usr/bin/uicache",
                    bundle_ids: set[str] | None = None) -> dict[str, dict]:
    """Accept only unambiguous, registered app bundles with their own code."""
    completed = subprocess.run([uicache, "-l"], capture_output=True, text=True,
                               timeout=20, check=False)
    if completed.returncode:
        raise RuntimeError("LaunchServices inventory is unavailable")
    candidates: dict[str, list[Path]] = {}
    for line in completed.stdout.splitlines():
        if " : " not in line:
            continue
        bundle_id, raw = line.split(" : ", 1)
        if not bundle_id or (bundle_ids is not None and bundle_id not in bundle_ids) or not raw.startswith(APP_ROOTS):
            continue
        path = Path(raw)
        if path.is_symlink() or not path.is_dir() or not str(path.resolve()).startswith(APP_ROOTS):
            continue
        candidates.setdefault(bundle_id, []).append(path)
    result = {}
    for bundle_id, paths in candidates.items():
        if len(paths) != 1:
            continue
        app = paths[0]
        try:
            info = plistlib.loads((app / "Info.plist").read_bytes())
            executable = info.get("CFBundleExecutable")
            if (info.get("CFBundleIdentifier") != bundle_id or
                    not isinstance(executable, str) or not COMMAND_NAME.fullmatch(executable) or
                    not (app / executable).is_file()):
                continue
            published = subprocess.run([uicache, "-i", bundle_id], capture_output=True,
                                       text=True, timeout=10, check=False)
            fields = dict(line.split(": ", 1) for line in published.stdout.splitlines()
                          if ": " in line)
            if (published.returncode or fields.get("Bundle Identifier") != bundle_id or
                    fields.get("Executable Name") != executable or
                    fields.get("Path") != str(app)):
                continue
            result[bundle_id] = {"path": str(app), "version": info.get("CFBundleShortVersionString") or info.get("CFBundleVersion"),
                                 "build": info.get("CFBundleVersion"), "executable": executable}
        except (OSError, ValueError, plistlib.InvalidFileException):
            continue
    return result


def command_path(names: list[str], roots: tuple[str, ...] = COMMAND_ROOTS) -> str | None:
    for name in names:
        if not isinstance(name, str) or not COMMAND_NAME.fullmatch(name):
            continue
        for directory in roots:
            candidate = Path(directory) / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None


def injection_evidence(paths) -> dict[str, dict]:
    """Map package IDs to current loader evidence from the runtime manager."""
    base = paths.jailbreak("/var/lib/srd-runtime")
    values = {}
    for name in ("registry.json", "injection-state.json", "injection-quarantine.json"):
        path = base / name
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
                return {}
            values[name] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return {}
    registry = values["registry.json"]
    loaded = values["injection-state.json"].get("loaded", {})
    quarantine = values["injection-quarantine.json"].get("entries", {})
    if (not isinstance(registry, dict) or not isinstance(loaded, dict)
            or not isinstance(quarantine, dict)):
        return {}
    result: dict[str, dict] = {}
    for entry in quarantine.values():
        package = entry.get("package") if isinstance(entry, dict) else None
        if not isinstance(package, str) or not package:
            continue
        result[package] = {
            "runtime": "FAIL",
            "reason": str(entry.get("reason") or "injection quarantined")[:300],
            "target": entry.get("target"),
            "evidence": "INJECTION_QUARANTINED",
        }
    expected: dict[str, list[tuple[str, str, str]]] = {}
    targets = registry.get("targets", {})
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            target_name = str(target.get("name") or "")
            for dylib in target.get("dylibs", []):
                if not isinstance(dylib, dict):
                    continue
                package = dylib.get("package")
                if isinstance(package, str) and package:
                    expected.setdefault(package, []).append(
                        (target_name, str(dylib.get("path") or ""),
                         str(dylib.get("sha256") or "")))
    loaded_rows = [item for item in loaded.values() if isinstance(item, dict)]
    for package, requirements in expected.items():
        if package in result:
            continue
        passed = sum(any(item.get("target") == target and
                         item.get("dylib") == dylib and
                         item.get("sha256") == digest
                         for item in loaded_rows)
                     for target, dylib, digest in requirements)
        if requirements and passed == len(requirements):
            result[package] = {"runtime": "PASS", "reason":
                               "all discovered injection targets are loaded",
                               "evidence": "INJECTION_LOADED"}
        elif passed:
            result[package] = {"runtime": "DEGRADED", "reason":
                               f"{passed}/{len(requirements)} injection targets are loaded",
                               "evidence": "INJECTION_PARTIAL"}
    return result


def host_status(path: Path = Path("/var/jb/var/run/crypstore-worker.json")) -> dict:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 131072:
        return {"connected": False, "tools": {}, "reason": "Trusted Mac heartbeat unavailable"}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        age = max(0, time.time() - float(value["timestamp"]))
        if age > 15:
            return {"connected": False, "tools": {}, "reason": "Trusted Mac heartbeat is stale"}
        if not (value.get("apple_pairing_verified") is True and
                value.get("lockdown_session_validated") is True and
                value.get("host_identity_verified") is True):
            return {"connected": False, "tools": {}, "reason": "Trusted Mac identity is unverified"}
        raw = value.get("host_tools")
        ssh_uat = value.get("ssh_uat")
        required = {"usb_identity", "pinned_public_key", "root_shell",
                    "server_process", "localhost_listener", "file_round_trip",
                    "cleanup", "reconnect"}
        if not (isinstance(ssh_uat, dict) and ssh_uat.get("result") == "PASS" and
                isinstance(ssh_uat.get("checked_at"), int) and
                0 <= time.time() - ssh_uat["checked_at"] <= 3600 and
                isinstance(ssh_uat.get("checks"), list) and
                all(isinstance(item, str) for item in ssh_uat["checks"]) and
                required.issubset(set(ssh_uat["checks"])) and
                ssh_uat.get("transport") in
                {"configured", "bonjour", "wireless", "bluetooth"}):
            ssh_uat = {"result": "UNVERIFIED"}
        frida_uat = value.get("frida_uat")
        frida_checks = {"usb_identity", "artifact_hash", "server_process",
                        "localhost_listener", "host_version", "process_enumeration"}
        if not (isinstance(frida_uat, dict) and frida_uat.get("result") == "PASS" and
                isinstance(frida_uat.get("checked_at"), int) and
                0 <= time.time() - frida_uat["checked_at"] <= 3600 and
                frida_uat.get("host_version") == "17.18.0" and
                frida_uat.get("device_version") == "17.18.0" and
                frida_uat.get("scope") == "read_only_process_enumeration" and
                frida_uat.get("transport") == "exact_usb_iproxy" and
                isinstance(frida_uat.get("checks"), list) and
                all(isinstance(item, str) for item in frida_uat["checks"]) and
                frida_checks.issubset(set(frida_uat["checks"]))):
            frida_uat = {"result": "UNVERIFIED"}
        return {"connected": True, "tools": raw if isinstance(raw, dict) else {},
                "ssh_uat": ssh_uat, "frida_uat": frida_uat,
                "reason": "Authenticated paired Mac heartbeat"}
    except (OSError, ValueError, TypeError, KeyError):
        return {"connected": False, "tools": {}, "reason": "Trusted Mac heartbeat is malformed"}


def collect(paths, *, catalog: dict | None = None, package_rows: list[dict] | None = None,
            apps: dict[str, dict] | None = None, host: dict | None = None,
            runtime: dict | None = None, prior: dict | None = None,
            ios_version: str | None = None, architecture: str | None = None,
            ios_build: str | None = None) -> dict:
    catalog = catalog or load_catalog()
    if package_rows is None:
        if PackageInventory is None:
            raise RuntimeError("package inventory is unavailable")
        package_rows = PackageInventory(paths).collect(512)
    app_discovery_error = None
    if apps is None:
        try:
            apps = registered_apps(bundle_ids={bundle
                for row in catalog["components"] if row["type"] == "APP"
                for bundle in row.get("bundle_ids", [])})
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
            apps = {}
            app_discovery_error = type(error).__name__
    host = host if host is not None else host_status(paths.jailbreak("/var/run/crypstore-worker.json"))
    runtime = runtime or {}
    prior = prior or {}
    packages = {row["package"]: row for row in package_rows if isinstance(row, dict) and row.get("package")}
    if ios_version is None:
        system = plistlib.loads(paths.system("/System/Library/CoreServices/SystemVersion.plist").read_bytes())
        ios_version = str(system.get("ProductVersion", "unknown"))
        ios_build = ios_build or system.get("ProductBuildVersion")
    elif ios_build is None:
        try:
            system = plistlib.loads(paths.system("/System/Library/CoreServices/SystemVersion.plist").read_bytes())
            ios_build = system.get("ProductBuildVersion")
        except (OSError, ValueError, plistlib.InvalidFileException):
            ios_build = None
    architecture = architecture or os.uname().machine
    cpu = architecture if architecture in ("arm64", "arm64e") else _architecture_from_mach(
        _sysctl_integer("hw.cputype"), _sysctl_integer("hw.cpusubtype"))
    architecture_verified = cpu in ("arm64", "arm64e")
    root_model = "rootless" if paths.jailbreak("/").is_dir() else "unknown"
    injection = injection_evidence(paths)
    observations: dict[str, dict] = {}
    for row in catalog["components"]:
        component = row["id"]
        saved = prior.get(component) if isinstance(prior.get(component), dict) else {}
        item = {"source": "UNVERIFIED", "installation": "NOT_INSTALLED",
                "runtime": "UNTESTED", "smoke": "SKIP",
                "uat": "SKIP", "configured": False,
                "installer_ready": False}
        if (row.get("management") == "EXISTING_PACKAGE_MANAGER"
                and host.get("connected") is True):
            # The paired Bridge provides the transaction, ownership check and
            # rollback boundary. Runtime failure must not hide the explicit
            # removal action for an installed nonfoundational package.
            item["installer_ready"] = True
        artifact = row.get("artifact_path")
        if artifact and row.get("sha256"):
            link = apps.get("codes.liquidsky.research.zerosky", {})
            link_path = link.get("path") if isinstance(link, dict) else None
            candidate = Path(link_path) / "SRDKit" / artifact if isinstance(link_path, str) else None
            if candidate and candidate.is_file():
                item["source"] = verify_artifact(candidate, row["sha256"])["result"]
            if component == "frida_server" and item["source"] == "UNVERIFIED":
                candidate = paths.jailbreak("/usr/sbin/frida-server")
            if candidate and candidate.is_file() and item["source"] == "UNVERIFIED":
                item["source"] = verify_artifact(candidate, row["sha256"])["result"]
        matched = [apps[bundle] for bundle in row.get("bundle_ids", []) if bundle in apps]
        package = next((packages[name] for name in row.get("package_ids", []) if name in packages), None)
        if row["type"] == "APP":
            if app_discovery_error:
                item["installation"] = "UNKNOWN"
                item["registration"] = "UNVERIFIED"
                item["runtime_reason"] = "LaunchServices inventory unavailable: " + app_discovery_error
            elif len(matched) == 1:
                item.update(installation="INSTALLED", installed_version=matched[0].get("version"),
                            registration="PASS", executable="PASS")
            elif package:
                item["installation"] = "PARTIAL"
                item["registration"] = "FAIL"
                item["runtime_reason"] = (
                    "Package database contains the app, but LaunchServices has no "
                    "verified registered app bundle")
        elif row["scope"] == "HOST":
            tools = host.get("tools", {}) if host.get("connected") else {}
            tool = tools.get(component) if isinstance(tools, dict) else None
            if isinstance(tool, dict) and tool.get("detected") is True:
                item.update(installation="INSTALLED", installed_version=tool.get("version"),
                            runtime="PASS" if tool.get("probe") == "PASS" else "UNTESTED")
        elif row["type"] in {"CLI", "RUNTIME"}:
            command = command_path(row.get("device_commands", []))
            if command:
                item.update(installation="INSTALLED", command=command)
            elif package:
                item["installation"] = "PARTIAL"
        elif package:
            item.update(installation="INSTALLED", installed_version=package.get("version"),
                        runtime="FAIL" if package.get("health") in {"Crashing", "Conflict"} else "UNTESTED")
            package_runtime = injection.get(package.get("package"))
            if package_runtime:
                item["runtime"] = package_runtime["runtime"]
                item["runtime_reason"] = package_runtime["reason"]
        if component == "frida":
            if (observations.get("frida_server", {}).get("installation") == "INSTALLED" and
                    observations.get("frida_cli", {}).get("installation") == "INSTALLED"):
                item["installation"] = "INSTALLED"
        saved_current = (saved.get("os_version") == ios_version and
                         saved.get("installed_version") == item.get("installed_version") and
                         isinstance(saved.get("timestamp"), (int, float)) and
                         0 <= time.time() - saved["timestamp"] <= 24 * 3600)
        if saved_current:
            item["smoke"] = saved.get("smoke", "SKIP")
            item["uat"] = saved.get("uat", "SKIP")
            item["last_tested"] = saved.get("timestamp")
            if saved.get("runtime") in {"PASS", "FAIL", "DEGRADED"}:
                item["runtime"] = saved["runtime"]
                item["configured"] = saved.get("configured") is True
                if isinstance(saved.get("runtime_reason"), str):
                    item["runtime_reason"] = saved["runtime_reason"][:300]
        compatibility = compatibility_for(row, ios_version=ios_version,
                                          architecture=cpu if architecture_verified else "unknown",
                                          root_model=root_model,
                                          runtime_evidence=saved.get("compatibility_evidence") if saved_current else None)
        item["compatibility"] = compatibility["result"]
        item["compatibility_reason"] = compatibility["reason"]
        if package and injection.get(package.get("package"), {}).get("runtime") == "FAIL":
            item["compatibility"] = "ADAPTATION_REQUIRED"
            item["compatibility_reason"] = (
                "Current iOS 27 injection failed with recorded runtime evidence; "
                "diagnosis and a distinct repair strategy are required")
        adapted = adapted_tweak_evidence(paths, row, package, ios_build, architecture)
        if adapted and architecture_verified and root_model == "rootless":
            item["compatibility"] = adapted["compatibility"]
            item["compatibility_reason"] = adapted["compatibility_reason"]
            if adapted["runtime"] == "PASS":
                item["runtime"] = "PASS"
                item["configured"] = True
        observations[component] = item
    # Combined Frida is evaluated after its device and host children.
    if (observations.get("frida_server", {}).get("installation") == "INSTALLED" and
            observations.get("frida_cli", {}).get("installation") == "INSTALLED"):
        observations["frida"]["installation"] = "INSTALLED"
    result = evaluate(catalog, observations)
    result["environment"] = {"ios_version": ios_version, "device_model": architecture,
                             "architecture": cpu, "architecture_verified": architecture_verified,
                             "bootstrap": root_model, "host_connected": host.get("connected") is True,
                             "app_discovery_status": "UNAVAILABLE" if app_discovery_error else "PASS",
                             "ssh_uat": host.get("ssh_uat", {"result": "UNVERIFIED"}),
                             "frida_uat": host.get("frida_uat", {"result": "UNVERIFIED"})}
    return result
