"""Bounded smoke and UAT evidence; unperformed tests stay SKIP."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import uuid
import zipfile

try:
    from .research_toolkit import RESULTS
except ImportError:
    from research_toolkit import RESULTS


SMOKE_NAMES = (
    "Preflight", "Source Integrity", "Package Database", "Dependency Graph",
    "Architecture", "Code Signature", "Entitlements", "Daemons",
    "Injection Framework", "GUI Applications", "CLI Tools", "Frida",
    "Networking", "SSH", "Package Manager", "Persistence", "0-Sky Integration")
UAT_NAMES = (
    "Open Security Research Apps", "Open Security Research Tweaks",
    "Install compatible application", "Install compatible tweak",
    "Encounter incompatible package", "Missing dependency",
    "Repair corrupted component", "Update component", "Frida integration",
    "Host integration through Bridge", "Reboot/respring recovery", "Offline behavior")
SAFE_COMMANDS = {
    "ssh": "-V", "ldid": "-h", "otool": "--version",
    "llvm-objdump": "--version", "nm": "--version", "llvm-nm": "--version",
    "strings": "--version", "llvm-strings": "--version", "file": "--version",
    "plutil": "-help", "sqlite3": "--version", "tcpdump": "--version",
    "curl": "--version", "git": "--version", "dpkg": "--version",
    "apt-get": "--version", "sh": "-c", "grep": "--version", "sed": "--version"}


def _case(identifier: str, name: str, expected: str, observed: str,
          result: str, evidence: list[str] | None = None,
          remediation: str | None = None, started: float | None = None) -> dict:
    if result not in RESULTS:
        raise ValueError("invalid test result")
    return {"id": identifier, "name": name, "result": result,
            "expected": expected, "observed": observed[:512],
            "evidence": (evidence or [])[:16],
            "duration_ms": round((time.monotonic() - started) * 1000, 1) if started else 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": remediation}


class DeviceProbes:
    """Only fixed, read-only commands; no shell interpolation from catalog data."""
    def __init__(self, rootless: Path = Path("/var/jb")) -> None:
        self.rootless = rootless

    @staticmethod
    def command(argv: list[str], timeout: int = 10) -> dict:
        try:
            completed = subprocess.run(argv, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, check=False)
            return {"status": completed.returncode,
                    "output": (completed.stdout + b"\n" + completed.stderr).decode(
                        "utf-8", "replace")[:512]}
        except (OSError, subprocess.TimeoutExpired) as error:
            return {"status": None, "output": type(error).__name__}

    def package_database(self) -> dict:
        path = self.rootless / "usr/bin/dpkg"
        apt = self.rootless / "usr/bin/apt-get"
        if not path.is_file() or not apt.is_file():
            return {"status": None, "output": "dpkg or apt-get is absent",
                    "apt_check_status": None}
        audit = self.command([str(path), "--audit"], timeout=20)
        check = self.command([str(apt), "check"], timeout=30)
        audit["apt_check_status"] = check["status"]
        return audit

    def command_version(self, executable: str) -> dict:
        path = Path(executable)
        name = path.name
        if name not in SAFE_COMMANDS or not path.is_file() or not os.access(path, os.X_OK):
            return {"status": None, "output": "command is absent or outside reviewed probes"}
        if name == "sh":
            return self.command([str(path), "-c", "exit 0"])
        return self.command([str(path), SAFE_COMMANDS[name]])

    @staticmethod
    def local_bridge() -> bool:
        try:
            with socket.create_connection(("127.0.0.1", 48654), timeout=2):
                return True
        except OSError:
            return False


def run_smoke(snapshot: dict, probes: DeviceProbes | None = None) -> dict:
    probes = probes or DeviceProbes()
    rows = {row["id"]: row for row in snapshot.get("components", [])}
    environment = snapshot.get("environment", {})
    results = []
    component_results: dict[str, dict] = {}

    def record(index: int, expected: str, observed: str, result: str,
               evidence: list[str] | None = None, remediation: str | None = None,
               started: float | None = None) -> None:
        results.append(_case(f"SMOKE-{index:02d}", SMOKE_NAMES[index-1], expected,
                             observed, result, evidence, remediation, started))

    started = time.monotonic()
    preflight = environment.get("bootstrap") == "rootless" and environment.get("architecture") in ("arm64", "arm64e")
    architecture_verified = environment.get("architecture_verified") is True
    record(1, "authorized rootless arm64 SRD environment",
           json.dumps({key: environment.get(key) for key in
                       ("ios_version", "device_model", "architecture", "architecture_verified",
                        "bootstrap", "host_connected")}, sort_keys=True),
           "BLOCKED" if not preflight else "PASS" if architecture_verified else "DEGRADED",
           remediation=None if preflight and architecture_verified else
           "Verify the CPU slice and SRD bootstrap on this device", started=started)
    source_bad = [row["id"] for row in rows.values() if row["facets"]["installation"] == "INSTALLED"
                  and row["facets"]["source"] != "PASS"]
    record(2, "every installed toolkit artifact has reviewed provenance",
           ", ".join(source_bad[:12]) if source_bad else "all reviewed",
           "DEGRADED" if source_bad else "PASS", source_bad[:16],
           "Verify artifact hashes or mark user-managed sources explicitly" if source_bad else None)
    started = time.monotonic()
    database = probes.package_database()
    audit_lines = [line for line in database["output"].splitlines() if line.strip()]
    virtual_only = (len(audit_lines) > 2 and
        audit_lines[:2] == [
            "The following packages are missing the md5sums control file in the",
            "database, they need to be reinstalled:"] and
        all(re.fullmatch(r"\s+(?:cy\+[^\s]+|gsc\.[^\s]+|firmware)\s+.*", line)
            for line in audit_lines[2:]))
    apt_healthy = database.get("apt_check_status") == 0
    database_ok = database["status"] == 0 and not audit_lines and apt_healthy
    database_warn = database["status"] == 0 and virtual_only and apt_healthy
    database_result = "PASS" if database_ok else "DEGRADED" if database_warn else "FAIL"
    record(3, "dpkg audit is empty and apt dependency check passes",
           database["output"] if audit_lines else "audit empty; apt check " + str(database.get("apt_check_status")),
           database_result,
           remediation=None if database_ok else "Review virtual package md5sum records" if database_warn
           else "Inspect dpkg --audit and apt-get check before changing packages", started=started)
    blocked = [row["id"] for row in rows.values() if row["facets"]["installation"] == "INSTALLED"
               and row["missing_dependencies"]]
    record(4, "all installed components have required dependencies", ", ".join(blocked) or "resolved",
           "FAIL" if blocked else "PASS", blocked[:16])
    blockers = {"BLOCKED_BY_DEPENDENCY", "BLOCKED_BY_PLATFORM", "BLOCKED_BY_ENTITLEMENT",
                "BLOCKED_BY_ARCHITECTURE", "BROKEN_UPSTREAM", "UNSAFE_TO_ADAPT"}
    incompatible = [row["id"] for row in rows.values() if row["facets"]["installation"] == "INSTALLED"
                    and row["facets"]["compatibility"] in blockers]
    unverified = [row["id"] for row in rows.values() if row["facets"]["installation"] == "INSTALLED"
                  and row["facets"]["compatibility"] not in
                  ({"COMPATIBLE", "COMPATIBLE_WITH_ADAPTER"} | blockers)]
    record(5, "installed components have verified OS, architecture, and bootstrap compatibility",
           ", ".join(incompatible + unverified) or "all verified",
           "FAIL" if incompatible else "DEGRADED" if unverified else "PASS",
           (incompatible + unverified)[:16],
           "Validate each component on this exact OS build" if unverified else None)
    for index, name in ((6, "Code Signature"), (7, "Entitlements")):
        record(index, "effective code-signing and entitlement state verified",
               "no reviewed device-wide probe; application launch evidence is separate", "SKIP",
               remediation="Run the per-component launch and entitlement UAT")
    for index, component in ((8, "frida_server"), (9, "ellekit")):
        row = rows.get(component)
        if not row or row["facets"]["installation"] != "INSTALLED":
            record(index, component + " installed and healthy", "not installed", "SKIP")
        else:
            runtime = row["facets"]["runtime"]
            record(index, component + " runtime health passes", runtime,
                   "PASS" if runtime == "PASS" else "FAIL" if runtime == "FAIL" else "DEGRADED",
                   remediation=None if runtime == "PASS" else "Run the controlled runtime probe")
    gui = [row for row in rows.values() if row["type"] == "APP" and row["facets"]["installation"] == "INSTALLED"]
    failed_gui = [row["id"] for row in gui if row["facets"]["runtime"] == "FAIL"]
    untested_gui = [row["id"] for row in gui if row["facets"]["runtime"] != "PASS"]
    record(10, "installed research apps launch and remain alive",
           ", ".join(untested_gui) if untested_gui else "all validated" if gui else "no apps installed",
           "FAIL" if failed_gui else "DEGRADED" if untested_gui else "PASS" if gui else "SKIP",
           untested_gui,
           "Run explicit GUI launch tests through the controlled UAT" if untested_gui else None)
    cli = [row for row in rows.values() if row["type"] == "CLI" and row["facets"]["installation"] == "INSTALLED"]
    cli_fail = []
    cli_pass = []
    started = time.monotonic()
    for row in cli:
        command = row.get("command")
        if not command:
            cli_fail.append(row["id"] + ":missing command evidence")
            component_results[row["id"]] = {"smoke": "FAIL", "runtime": "FAIL",
                                             "configured": False}
            continue
        probe = probes.command_version(command)
        (cli_pass if probe["status"] == 0 else cli_fail).append(row["id"])
        component_results[row["id"]] = {
            "smoke": "PASS" if probe["status"] == 0 else "FAIL",
            "runtime": "PASS" if probe["status"] == 0 else "FAIL",
            "configured": probe["status"] == 0}
    record(11, "installed CLI utilities execute a bounded version probe",
           f"passed={len(cli_pass)} failed={len(cli_fail)}", "FAIL" if cli_fail else "PASS" if cli else "SKIP",
           cli_fail[:16], started=started)
    server, host = rows.get("frida_server"), rows.get("frida_cli")
    if server and host and server["facets"]["installation"] == host["facets"]["installation"] == "INSTALLED":
        # Read-only process enumeration proves transport, but not attachment or RPC.
        frida_uat = environment.get("frida_uat", {})
        enumeration_pass = (environment.get("host_connected") is True and
                            isinstance(frida_uat, dict) and frida_uat.get("result") == "PASS")
        record(12, "matching host and device Frida versions, process enumeration, and controlled test app RPC",
               "pinned exact-USB process enumeration passed; controlled test app RPC unverified"
               if enumeration_pass else "both components discovered; process enumeration and RPC unverified",
               "DEGRADED",
               ["pinned artifact hash, server process, listener, version match, process enumeration"]
               if enumeration_pass else [],
               remediation="Run Frida UAT on the 0-Sky test app")
    else:
        record(12, "Frida device and host are present", "one or both unavailable", "SKIP")
    started = time.monotonic()
    bridge = probes.local_bridge()
    record(13, "local 0-Sky Bridge listener is reachable", "reachable" if bridge else "unreachable",
           "PASS" if bridge else "FAIL", started=started)
    ssh_uat = environment.get("ssh_uat", {})
    ssh_pass = (environment.get("host_connected") is True and
                isinstance(ssh_uat, dict) and ssh_uat.get("result") == "PASS")
    record(14, "authorized-key SSH round trip and reconnect pass",
           "paired Mac SSH UAT passed via " + str(ssh_uat.get("transport")) if ssh_pass else
           "paired Mac available; SSH round trip unverified" if environment.get("host_connected")
           else "paired Mac unavailable",
           "PASS" if ssh_pass else "DEGRADED" if environment.get("host_connected") else "SKIP",
           ["pinned key, local listener, root shell, file copy, cleanup, reconnect"] if ssh_pass else [],
           remediation=None if ssh_pass else "Run the paired Mac SSH UAT")
    apt = rows.get("apt")
    dpkg = rows.get("dpkg")
    package_manager = bool(apt and dpkg and apt["facets"]["installation"] == "INSTALLED"
                           and dpkg["facets"]["installation"] == "INSTALLED" and
                           (database_ok or database_warn))
    record(15, "apt and dpkg are present and dependency checks pass",
           "healthy" if database_ok else "virtual package metadata warnings" if database_warn
           else "unavailable or damaged",
           "PASS" if package_manager and database_ok else
           "DEGRADED" if package_manager and database_warn else "FAIL")
    record(16, "services and app registrations survive reboot/respring",
           "no reboot was performed by generic smoke tests", "SKIP",
           remediation="Run explicit reboot/respring UAT when safe")
    record(17, "0-Sky Control, Link, and Bridge communicate",
           "local Bridge reachable; Control/Link handshake needs its own UAT",
           "DEGRADED" if bridge else "FAIL")
    counts = {state: sum(row["result"] == state for row in results) for state in RESULTS}
    return {"schema": 1, "tests": results, "counts": counts,
            "component_results": component_results,
            "result": "BLOCKED" if counts["BLOCKED"] else "FAIL" if counts["FAIL"] else
                      "DEGRADED" if counts["DEGRADED"] or counts["SKIP"] else "PASS",
            "timestamp": datetime.now(timezone.utc).isoformat()}


def run_uat(snapshot: dict, smoke: dict, evidence: dict | None = None) -> dict:
    """An automated case without operational evidence is SKIP, never PASS."""
    evidence = evidence or {}
    results = []
    checks = (
        "ui_apps", "ui_tweaks", "app_install", "tweak_install",
        "incompatible_fixture", "missing_dependency_fixture", "repair_fixture",
        "update_fixture", "frida_test_app", "host_bridge", "reboot_respring", "offline")
    for index, key in enumerate(checks, 1):
        record = evidence.get(key) if isinstance(evidence.get(key), dict) else {}
        state = record.get("result", "SKIP")
        if state not in RESULTS:
            state = "FAIL"
        if state == "PASS" and not record.get("evidence"):
            state = "FAIL"
        results.append(_case(f"UAT-{index:03d}", UAT_NAMES[index-1],
                             "documented end-to-end behavior on the authorized SRD",
                             str(record.get("observed", "No end-to-end evidence")), state,
                             record.get("evidence") if isinstance(record.get("evidence"), list) else [],
                             str(record.get("remediation", "Run this case with the controlled fixture"))
                             if state != "PASS" else None))
    counts = {state: sum(row["result"] == state for row in results) for state in RESULTS}
    return {"schema": 1, "tests": results, "counts": counts,
            "result": "BLOCKED" if counts["BLOCKED"] else "FAIL" if counts["FAIL"] else
                      "DEGRADED" if counts["DEGRADED"] or counts["SKIP"] else "PASS",
            "timestamp": datetime.now(timezone.utc).isoformat()}


def write_bundle(root: Path, snapshot: dict, smoke: dict, uat: dict) -> Path:
    """Write a new review directory atomically without credential-bearing logs."""
    if root.is_symlink():
        raise ValueError("evidence root is a symbolic link")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = root / ("0sky-uat-" + uuid.uuid4().hex)
    destination.mkdir(mode=0o700)
    (destination / "logs").mkdir(mode=0o700)
    rows = snapshot.get("components", [])
    by_category = {
        "apps.json": [row for row in rows if row.get("category") == "Apps/Security Research"],
        "tweaks.json": [row for row in rows if row.get("category") == "Tweaks/Security Research"],
        "host-tools.json": [row for row in rows if row.get("scope") == "HOST"],
    }
    overall = ("BLOCKED" if "BLOCKED" in (smoke.get("result"), uat.get("result")) else
               "FAIL" if "FAIL" in (smoke.get("result"), uat.get("result")) else
               "DEGRADED" if "DEGRADED" in (smoke.get("result"), uat.get("result")) else "PASS")
    content = {
        "summary.json": {"toolkit": snapshot.get("counts"), "smoke": smoke.get("counts"),
                         "uat": uat.get("counts"), "overall": overall},
        "environment.json": snapshot.get("environment", {}),
        "sources.json": [{"id": row.get("id"), "upstream": row.get("upstream_project"),
                          "package_repository": row.get("package_repository"),
                          "source_trust": row.get("source_trust"),
                          "package_source_trust": row.get("package_source_trust"),
                          "source": row.get("facets", {}).get("source")}
                         for row in rows],
        "compatibility.json": [{"id": row.get("id"),
                                "status": row.get("facets", {}).get("compatibility"),
                                "reason": row.get("compatibility_reason")} for row in rows],
        "dependencies.json": [{"id": row.get("id"), "missing": row.get("missing_dependencies"),
                               "conflicts": row.get("conflicts")} for row in rows],
        "smoke-tests.json": smoke,
        "uat-results.json": uat,
        "failures.json": [row for row in smoke.get("tests", []) + uat.get("tests", [])
                          if row.get("result") in ("FAIL", "BLOCKED")],
        **by_category,
    }
    for name, payload in content.items():
        path = destination / name
        path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        path.chmod(0o600)
    summary = destination / "summary.md"
    summary.write_text("# 0-Sky Security Research Toolkit UAT\n\n"
                       + f"Overall automated result: **{overall}**\n\n"
                       + "Manual researcher evaluation required.\n", encoding="utf-8")
    summary.chmod(0o600)
    archive = destination / "0sky-uat.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(destination.iterdir()):
            if path.is_file() and path != archive:
                bundle.write(path, path.name)
    archive.chmod(0o600)
    return destination
