"""Read-only SRD discovery for the 0-Sky Security Research Toolkit."""
from __future__ import annotations

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


def registered_apps(uicache: str = "/var/jb/usr/bin/uicache") -> dict[str, dict]:
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
        if not bundle_id or not raw.startswith(APP_ROOTS):
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
            result[bundle_id] = {"path": str(app), "version": info.get("CFBundleShortVersionString"),
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
            ios_version: str | None = None, architecture: str | None = None) -> dict:
    catalog = catalog or load_catalog()
    if package_rows is None:
        if PackageInventory is None:
            raise RuntimeError("package inventory is unavailable")
        package_rows = PackageInventory(paths).collect(512)
    apps = apps if apps is not None else registered_apps()
    host = host if host is not None else host_status(paths.jailbreak("/var/run/crypstore-worker.json"))
    runtime = runtime or {}
    prior = prior or {}
    packages = {row["package"]: row for row in package_rows if isinstance(row, dict) and row.get("package")}
    if ios_version is None:
        system = plistlib.loads(paths.system("/System/Library/CoreServices/SystemVersion.plist").read_bytes())
        ios_version = str(system.get("ProductVersion", "unknown"))
    architecture = architecture or os.uname().machine
    cpu = architecture if architecture in ("arm64", "arm64e") else _architecture_from_mach(
        _sysctl_integer("hw.cputype"), _sysctl_integer("hw.cpusubtype"))
    architecture_verified = cpu in ("arm64", "arm64e")
    root_model = "rootless" if paths.jailbreak("/").is_dir() else "unknown"
    observations: dict[str, dict] = {}
    for row in catalog["components"]:
        component = row["id"]
        saved = prior.get(component) if isinstance(prior.get(component), dict) else {}
        item = {"source": "UNVERIFIED", "installation": "NOT_INSTALLED",
                "runtime": "UNTESTED", "smoke": "SKIP",
                "uat": "SKIP", "configured": False,
                "installer_ready": False}
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
            if len(matched) == 1:
                item.update(installation="INSTALLED", installed_version=matched[0].get("version"),
                            registration="PASS", executable="PASS")
            elif package:
                item["installation"] = "PARTIAL"
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
        observations[component] = item
    # Combined Frida is evaluated after its device and host children.
    if (observations.get("frida_server", {}).get("installation") == "INSTALLED" and
            observations.get("frida_cli", {}).get("installation") == "INSTALLED"):
        observations["frida"]["installation"] = "INSTALLED"
    result = evaluate(catalog, observations)
    result["environment"] = {"ios_version": ios_version, "device_model": architecture,
                             "architecture": cpu, "architecture_verified": architecture_verified,
                             "bootstrap": root_model, "host_connected": host.get("connected") is True,
                             "ssh_uat": host.get("ssh_uat", {"result": "UNVERIFIED"}),
                             "frida_uat": host.get("frida_uat", {"result": "UNVERIFIED"})}
    return result
