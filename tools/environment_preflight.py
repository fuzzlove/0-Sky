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
        return {"tool": name, "status": "FAIL" if required else "DEGRADED",
                "resolved_path": None, "version": None,
                "source": "PATH", "remediation": f"Install {name} or configure PATH"}
    path = str(Path(path).resolve())
    code, version = command([path, *version_args])
    if code != 0 or not version or (required_prefix and not version.startswith(required_prefix)):
        return {"tool": name, "status": "FAIL" if required else "DEGRADED",
                "resolved_path": path, "version": version or None,
                "source": "PATH", "remediation": f"Install a compatible {name}"}
    return {"tool": name, "status": "PASS", "resolved_path": path,
            "version": version.splitlines()[0], "source": "PATH"}


def inspect_kit(kit: Path) -> dict[str, object]:
    manifest = kit / "SHA256SUMS"
    if not manifest.is_file() or manifest.is_symlink():
        return {"status": "BLOCKED", "manifest_entries": 0,
                "remediation": "Supply a verified 0-Sky kit with SHA256SUMS"}
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
                "remediation": "Repair the kit manifest before release"}


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


def report(*, mode: str, kit: Path | None = None, udid: str | None = None,
           config_file: Path | None = None,
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
        resolve_tool("python3.12", required=True, search_path=search_path,
                     required_prefix="Python 3.12."),
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
    signing = bool(env.get("ZERO_SKY_SIGNING_IDENTITY"))
    security = {"status": "PASS" if signing else ("BLOCKED" if mode == "release" else "DEGRADED"),
                "signing_identity_configured": signing,
                "remediation": None if signing else "Configure caller-owned signing identity for release"}
    statuses = [item["status"] for item in tools if item["tool"] not in {"iproxy", "idevice_id"}]
    statuses += [configuration["status"], security["status"], kit_result["status"]]
    if udid:
        statuses.append(device["status"])
    _, translated_value = command(["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"], 2)
    host_arch = architecture(platform.machine(), translated_value == "1")
    statuses.append(host_arch["status"])
    overall = "BLOCKED" if "BLOCKED" in statuses or "FAIL" in statuses else (
        "DEGRADED" if "DEGRADED" in statuses else "READY")
    for item in tools:
        item["resolved_path"] = safe_tool_path(item["resolved_path"])
    return {
        "system": {"os": platform.mac_ver()[0] or platform.system(),
                   "architecture": host_arch, "hostname": "<redacted>",
                   "application_support": configuration.get("support", "<unavailable>")},
        "toolchain": tools, "device": device,
        "configuration": configuration, "kit": kit_result,
        "security": security, "status": overall,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("development", "release"), default="development")
    parser.add_argument("--kit", type=Path)
    parser.add_argument("--udid")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--skip-device", action="store_true")
    args = parser.parse_args()
    value = report(mode=args.mode, kit=args.kit, udid=args.udid,
                   config_file=args.config, discover_device=not args.skip_device)
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0 if value["status"] in {"READY", "DEGRADED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
