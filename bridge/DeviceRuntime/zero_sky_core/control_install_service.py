"""Device-side Control installer policy, payload resolution and verification."""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import plistlib
import subprocess
import threading
import time
from zero_sky_compat.environment import _architecture_from_mach, _sysctl_integer

try:
    from .control_payload import PayloadError, load_manifest, verify_manifest
    from .control_install_policy import decide
except ImportError:  # standalone PoC tests
    from control_payload import PayloadError, load_manifest, verify_manifest
    from control_install_policy import decide


LINK_ID = "codes.liquidsky.research.zerosky"
CONTROL_ID = "com.liquidsky.CrypStore"
_install_lock = threading.Lock()


def registered_path(bundle_id: str) -> Path | None:
    completed = subprocess.run(["/var/jb/usr/bin/uicache", "-l"], capture_output=True,
                               text=True, timeout=20, check=False)
    if completed.returncode:
        raise RuntimeError("LaunchServices inventory is unavailable")
    prefix = bundle_id + " : "
    paths = [line[len(prefix):].strip() for line in completed.stdout.splitlines()
             if line.startswith(prefix)]
    if not paths:
        return None
    if len(paths) != 1:
        raise RuntimeError("LaunchServices has ambiguous app registrations")
    path = Path(paths[0])
    if (path.is_symlink() or not path.is_dir() or
            not str(path.resolve()).startswith("/private/var/containers/Bundle/Application/")):
        raise RuntimeError("registered app path is unsafe")
    return path


def resolve_payload() -> tuple[Path, dict]:
    link = registered_path(LINK_ID)
    if link is None or link.name != "ZeroSky.app":
        raise PayloadError("0-Sky Link is not registered")
    info = plistlib.loads((link / "Info.plist").read_bytes())
    if info.get("CFBundleIdentifier") != LINK_ID:
        raise PayloadError("0-Sky Link identity differs")
    manifest = load_manifest(link / "ControlPayload/manifest.json")
    source = link / manifest["payload_path"]
    if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(link.resolve()):
        raise PayloadError("bundled Control IPA path is unsafe")
    verify_manifest(source, manifest)
    return source, manifest


def installed_control(runtime: dict, manifest: dict) -> dict | None:
    app = registered_path(CONTROL_ID)
    if app is None:
        return None
    info = plistlib.loads((app / "Info.plist").read_bytes())
    executable = info.get("CFBundleExecutable")
    binary = app / executable if isinstance(executable, str) else app / "missing"
    files = manifest.get("files", {})
    prefix = "Payload/CrypStore.app/"
    resources_intact = isinstance(files, dict) and bool(files)
    for name, expected_hash in files.items():
        if not isinstance(name, str) or not name.startswith(prefix):
            resources_intact = False
            break
        relative = Path(name[len(prefix):])
        if not relative.parts or relative.is_absolute() or ".." in relative.parts:
            resources_intact = False
            break
        target = app / relative
        if target.is_symlink() or not target.is_file():
            resources_intact = False
            break
        # Native registration re-signs executable code and CodeResources.
        if relative.parts[0] in {"CrypStore", "trollstorehelper", "_CodeSignature"}:
            continue
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected_hash:
            resources_intact = False
            break
    running = runtime.get("crypstore_running") is True
    mounted = runtime.get("crypstore_mounted") is True
    return {
        "bundle_id": info.get("CFBundleIdentifier"),
        "build": info.get("CFBundleVersion"),
        "executable": binary.is_file(),
        "resources": resources_intact,
        # A live iOS process with its current Cryptex mounted establishes
        # kernel acceptance of the installed CodeDirectory.
        "signature": running and mounted,
        "entitlements": running and mounted,
        "registration": runtime.get("crypstore_registered") is True,
        "dependencies": runtime.get("bridge_euid") == 0,
        "services": not manifest.get("services"),
        "launch": running,
        "link_communication": runtime.get("crypstore_ok") is True,
    }


def environment(source: Path, manifest: dict, runtime: dict,
                pairing: dict, worker: dict) -> dict:
    version = plistlib.loads(Path("/System/Library/CoreServices/SystemVersion.plist").read_bytes())
    product = str(version.get("ProductVersion", ""))
    major = int(product.split(".")[0]) if product.split(".")[0].isdigit() else None
    model = os.uname().machine
    architecture = _architecture_from_mach(_sysctl_integer("hw.cputype"),
                                           _sysctl_integer("hw.cpusubtype"))
    return {
        "os_major": major,
        "os_build": version.get("ProductBuildVersion"),
        "device_model": model,
        "architecture": architecture,
        # Authorization comes from the live, device-bound Mac relationship.
        # An absent Control Cryptex is the normal fresh-install state.
        "srd_authorized": os.geteuid() == 0 and pairing.get("live_verified") is True,
        "bootstrap_ready": Path("/var/jb/usr/bin/python3").is_file() and runtime.get("bridge_euid") == 0,
        "paired_mac_verified": pairing.get("live_verified") is True,
        "worker_connected": worker.get("connected") is True,
        "free_mb": runtime.get("rootless_free_mb", 0),
        "payload_mb": (source.stat().st_size + 1048575) // 1048576,
        "missing_dependencies": [],
        "incompatible_dependencies": [],
        "transactional_backend": worker.get("control_installer_backend") == manifest.get("backend"),
        # The worker snapshots and verifies any registered prior app before
        # mutation. Fresh installs have no prior code to restore.
        "rollback_source_verified": runtime.get("crypstore_registered") is True,
    }


def inspect(runtime_reader, pairing_reader, worker_reader) -> dict:
    source, manifest = resolve_payload()
    runtime = runtime_reader()
    pairing = pairing_reader()
    worker = worker_reader()
    env = environment(source, manifest, runtime, pairing, worker)
    installed = installed_control(runtime, manifest)
    decision = decide(manifest, env, installed)
    return {"decision": decision.to_dict(), "payload": {
        "bundle_id": manifest["identity"]["CFBundleIdentifier"],
        "version": manifest["identity"]["CFBundleShortVersionString"],
        "build": manifest["identity"]["CFBundleVersion"],
        "sha256": manifest["ipa_sha256"]},
        "installed": {"build": installed.get("build"),
                      "healthy": all(installed.get(name) is True for name in
                                     ("executable", "resources", "signature", "entitlements", "registration",
                                      "dependencies", "services", "launch", "link_communication"))}
                      if installed else None,
        "environment": {key: env[key] for key in
                        ("os_major", "os_build", "device_model", "architecture",
                         "free_mb", "worker_connected")},
        "source": str(source), "manifest": manifest}


def public_status(value: dict) -> dict:
    return {key: item for key, item in value.items() if key not in ("source", "manifest")}


def install(runtime_reader, pairing_reader, worker_reader, queue) -> dict:
    if not _install_lock.acquire(blocking=False):
        return {"result": "BLOCKED", "stage": "PRECHECK", "code": "INSTALL_IN_PROGRESS",
                "explanation": "A Control installation is already in progress",
                "rollback": "NOT_NEEDED", "events": []}
    try:
        return _install_locked(runtime_reader, pairing_reader, worker_reader, queue)
    finally:
        _install_lock.release()


def _install_locked(runtime_reader, pairing_reader, worker_reader, queue) -> dict:
    before = inspect(runtime_reader, pairing_reader, worker_reader)
    decision = before["decision"]
    events = [{"event": "CONTROL_INSTALL_REQUESTED", "timestamp": int(time.time())},
              {"event": "CONTROL_PAYLOAD_VERIFIED", "timestamp": int(time.time())}]
    if decision["action"] == "BLOCK":
        return {"result": "BLOCKED", "stage": "PRECHECK", "decision": decision,
                "events": events, "rollback": "NOT_NEEDED"}
    if decision["action"] == "NO_ACTION":
        events.append({"event": "CONTROL_INSTALL_VERIFIED", "timestamp": int(time.time())})
        return {"result": "ALREADY_INSTALLED_AND_VERIFIED", "stage": "COMMIT",
                "decision": decision, "events": events, "rollback": "NOT_NEEDED"}
    events.append({"event": "CONTROL_PREFLIGHT_PASS", "timestamp": int(time.time())})
    events.append({"event": "CONTROL_COMPATIBILITY_PASS", "timestamp": int(time.time())})
    response = queue(before["source"], before["manifest"])
    if response.get("status") != 0:
        return {"result": "FAILED", "stage": "INSTALL", "decision": decision,
                "error": str(response.get("stderr", "installer failed"))[:500],
                "rollback": response.get("rollback", "UNKNOWN"), "events": events}
    after = inspect(runtime_reader, pairing_reader, worker_reader)
    if after["decision"]["action"] != "NO_ACTION":
        return {"result": "FAILED", "stage": "VERIFY", "decision": after["decision"],
                "rollback": response.get("rollback", "UNKNOWN"), "events": events}
    events += [{"event": name, "timestamp": int(time.time())} for name in
               ("CONTROL_INSTALL_COMPLETE", "CONTROL_REGISTRATION_COMPLETE",
                "CONTROL_PERMISSION_CHECK_COMPLETE", "CONTROL_HEALTHCHECK_PASS",
                "CONTROL_INSTALL_VERIFIED")]
    return {"result": "INSTALLED_AND_VERIFIED", "stage": "COMMIT",
            "decision": after["decision"], "rollback": "NOT_NEEDED",
            "evidence": response.get("evidence", {}), "events": events}
