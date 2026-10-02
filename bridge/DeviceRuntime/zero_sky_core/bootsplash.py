"""Read-only early-splash facts for the authenticated 0-Sky device bridge.

The UI is never a source of privilege or trust.  Every value here comes from
the bridge process, its validated pairing implementation, or local services.
"""
from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from .paths import RootlessPaths


def privilege_probe(getuid: Callable[[], int] = os.getuid,
                    geteuid: Callable[[], int] = os.geteuid) -> dict:
    uid, euid = int(getuid()), int(geteuid())
    return {"root_status": "ACTIVE" if euid == 0 else "INACTIVE",
            "uid": uid, "euid": euid}


def _manager_running(paths: RootlessPaths) -> bool:
    ps = paths.jailbreak("/usr/bin/ps")
    if not ps.is_file():
        ps = paths.system("/bin/ps")
    if not ps.is_file():
        return False
    result = subprocess.run([str(ps), "ax", "-o", "command="],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=0.55, check=False)
    command = (str(paths.jailbreak("/usr/local/libexec/srd-runtime-manager.py")) +
               " daemon").encode()
    return result.returncode == 0 and command in result.stdout


def bootstrap_probe(paths: RootlessPaths | None = None,
                    manager_running: Callable[[], bool] | None = None) -> dict:
    paths = paths or RootlessPaths()
    required = {
        "root": paths.jailbreak(),
        "python": paths.jailbreak("/usr/bin/python3"),
        "package_manager": paths.jailbreak("/usr/bin/dpkg"),
        "package_database": paths.jailbreak("/var/lib/dpkg/status"),
        "core_database": paths.database_path,
        "bridge": paths.jailbreak("/usr/local/libexec/trollstorelite-srd-bridge.py"),
        "runtime_manager": paths.jailbreak("/usr/local/libexec/srd-runtime-manager.py"),
        "bridge_service": paths.jailbreak(
            "/Library/LaunchDaemons/com.liquidskysecurity.trollstorelite-srd-bridge.plist"),
        "bridge_config": paths.jailbreak("/etc/trollstorelite-srd-bridge.token"),
    }
    # Check files separately so a directory named after an executable cannot
    # satisfy the probe.  Never open the bridge token.
    missing = ([] if required["root"].is_dir() else ["root"]) + [
        name for name, path in required.items() if name != "root" and not path.is_file()]
    if "bridge_config" not in missing and required["bridge_config"].stat().st_size == 0:
        missing.append("bridge_config")
    if "runtime_manager" not in missing:
        try:
            if not (manager_running() if manager_running else _manager_running(paths)):
                missing.append("runtime_manager_process")
        except (OSError, subprocess.TimeoutExpired):
            missing.append("runtime_manager_process")
    return {"bootstrap_status": "DEGRADED" if missing else "ACTIVE",
            "bootstrap_reasons": missing}


def trust_probe(pairing: dict | None) -> str:
    if not isinstance(pairing, dict):
        return "UNKNOWN"
    if pairing.get("paired") is True:
        return "VERIFIED"
    if pairing.get("relationship_verified") is True:
        return "PAIRED"
    if pairing.get("pairing_registry_valid") is False:
        return "NOT_VERIFIED"
    return "NOT_VERIFIED"


def research_device_probe(pairing: dict | None) -> str:
    # A live, identity-bound 0-Sky pairing is required.  The Mac-side guard's
    # actual research class must also be explicit; UNKNOWN never qualifies.
    if (isinstance(pairing, dict) and pairing.get("paired") is True and
            pairing.get("research_class") in ("SRD", "SECURITY_RESEARCH_DEVICE")):
        return "AUTHORIZED_SRD"
    return "UNKNOWN"


def runtime_probe(info: dict | None) -> dict:
    if not isinstance(info, dict):
        return {"runtime_status": "UNKNOWN", "control_status": "UNKNOWN"}
    runtime = ("ACTIVE" if info.get("ellekit_ok") is True else
               "DEGRADED" if info.get("manager_active") is True else "FAILED")
    control = ("ACTIVE" if info.get("crypstore_ok") is True else
               "DEGRADED" if info.get("crypstore_registered") is True else "FAILED")
    return {"runtime_status": runtime, "control_status": control}


def _ssh_banner(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.75) as peer:
            peer.settimeout(0.75)
            return peer.recv(8).startswith(b"SSH-")
    except (OSError, TimeoutError):
        return False


def ssh_probe(pairing: dict | None,
              banner: Callable[[int], bool] = _ssh_banner) -> str:
    ports = {22}
    if isinstance(pairing, dict):
        for value in pairing.get("ssh_remote_ports", []):
            try:
                port = int(value)
                if 1 <= port <= 65535:
                    ports.add(port)
            except (TypeError, ValueError):
                continue
    return "READY" if any(banner(port) for port in sorted(ports)) else "FAILED"


def _bounded(function: Callable[[], object], timeout: float) -> tuple[object | None, str | None]:
    result: list[object] = []
    error: list[str] = []
    done = threading.Event()

    def work() -> None:
        try:
            result.append(function())
        except Exception as exc:  # startup must remain fail-open
            error.append(type(exc).__name__)
        finally:
            done.set()

    threading.Thread(target=work, name="0sky-splash-probe", daemon=True).start()
    if not done.wait(max(0.0, timeout)):
        return None, "TIMEOUT"
    return (result[0] if result else None), (error[0] if error else None)


def snapshot(pairing_status: Callable[[], dict],
             *, paths: RootlessPaths | None = None,
             uid: Callable[[], int] = os.getuid,
             euid: Callable[[], int] = os.geteuid,
             banner: Callable[[int], bool] = _ssh_banner,
             runtime_reader: Callable[[], dict] | None = None,
             timeout_s: float = 5.0) -> dict:
    started = time.monotonic()
    deadline = started + min(5.0, max(0.0, timeout_s))
    output = {"root_status": "UNKNOWN", "uid": None, "euid": None,
              "bootstrap_status": "UNKNOWN", "bootstrap_reasons": [],
              "trusted_host_status": "UNKNOWN", "ssh_status": "UNKNOWN",
              "runtime_status": "UNKNOWN", "control_status": "UNKNOWN",
              "device_mode": "UNKNOWN", "timestamp": time.time(),
              "diagnostics": []}
    try:
        output.update(privilege_probe(uid, euid))
    except Exception as exc:
        output["diagnostics"].append("root:" + type(exc).__name__)
    bootstrap, issue = _bounded(lambda: bootstrap_probe(paths),
                                min(1.0, max(0.0, deadline - time.monotonic())))
    if issue:
        output["bootstrap_status"] = "TIMEOUT" if issue == "TIMEOUT" else "DEGRADED"
        output["diagnostics"].append("bootstrap:" + issue)
    elif isinstance(bootstrap, dict):
        output.update(bootstrap)
    pairing, issue = _bounded(pairing_status,
                              min(2.0, max(0.0, deadline - time.monotonic())))
    if issue:
        output["trusted_host_status"] = "TIMEOUT" if issue == "TIMEOUT" else "UNKNOWN"
        output["diagnostics"].append("trust:" + issue)
    else:
        output["trusted_host_status"] = trust_probe(pairing)
        output["device_mode"] = research_device_probe(pairing)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        ssh, issue = None, "TIMEOUT"
    else:
        ssh, issue = _bounded(lambda: ssh_probe(pairing, banner),
                              min(2.0, remaining))
    if issue:
        output["ssh_status"] = "TIMEOUT" if issue == "TIMEOUT" else "FAILED"
        output["diagnostics"].append("ssh:" + issue)
    else:
        output["ssh_status"] = str(ssh)
    if runtime_reader is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            runtime, issue = None, "TIMEOUT"
        else:
            runtime, issue = _bounded(runtime_reader, min(1.5, remaining))
        if issue:
            if issue == "TIMEOUT":
                output["runtime_status"] = output["control_status"] = "TIMEOUT"
            output["diagnostics"].append("runtime:" + issue)
        else:
            output.update(runtime_probe(runtime))
    output["duration_ms"] = int((time.monotonic() - started) * 1000)
    return output
