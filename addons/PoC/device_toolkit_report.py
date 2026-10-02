#!/usr/bin/env python3
"""Build honest predeployment toolkit evidence for each USB-verified SRD."""
from __future__ import annotations

import json
from pathlib import Path
import re

from research_toolkit import compatibility_for, evaluate, load_catalog
from research_toolkit_runner import run_smoke, run_uat, write_bundle


HERE = Path(__file__).resolve().parent
CLI_NAMES = {"openssh": "ssh", "apt": "apt-get"}


class RecordedProbes:
    """Replay only the bounded read-only probes captured from this exact SRD."""
    def __init__(self, evidence: dict) -> None:
        self.evidence = evidence

    def package_database(self) -> dict:
        return {"status": self.evidence["dpkg_audit_exit"],
                "apt_check_status": self.evidence.get("apt_check_exit"),
                "output": self.evidence.get("dpkg_audit_text", "")}

    def command_version(self, executable: str) -> dict:
        name = Path(executable).name
        entry = self.evidence["cli"].get("apt" if name == "apt-get" else name, {})
        return {"status": 0 if entry.get("status") == "PASS" else entry.get("exit"),
                "output": " ".join(entry.get("version_line", [])) or entry.get("probe", "")}

    def local_bridge(self) -> bool:
        return self.evidence["bridge_listener"] is True


def package_versions(evidence: dict) -> dict[str, str]:
    versions = {}
    for line in evidence["packages"]:
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and parts[1].strip():
            versions[parts[0]] = parts[1].strip()
    return versions


def snapshot_for(evidence: dict, catalog: dict) -> dict:
    packages = package_versions(evidence)
    apps = evidence["registered_apps"]
    observations = {}
    model = evidence["usb_product"]
    for row in catalog["components"]:
        component = row["id"]
        observation = {"source": "UNVERIFIED", "installation": "NOT_INSTALLED",
                       "runtime": "UNTESTED", "smoke": "SKIP", "uat": "SKIP",
                       "configured": False, "installer_ready": False}
        compatibility = compatibility_for(row, ios_version=evidence["os"],
                                          architecture="unknown", root_model="rootless")
        observation["compatibility"] = compatibility["result"]
        observation["compatibility_reason"] = compatibility["reason"]
        found_apps = [apps[bundle] for bundle in row.get("bundle_ids", []) if bundle in apps]
        receipt = next(((name, packages[name]) for name in row.get("package_ids", [])
                        if name in packages), None)
        if row["type"] == "APP":
            if len(found_apps) == 1 and found_apps[0]["identity_executable_valid"]:
                observation.update(installation="INSTALLED",
                                   installed_version=found_apps[0].get("version"))
            elif receipt:
                observation["installation"] = "PARTIAL"
        elif row["scope"] == "HOST":
            tool = evidence["host"].get("tools", {}).get(component, {})
            if tool.get("detected") is True:
                observation.update(installation="INSTALLED",
                                   installed_version=tool.get("version"),
                                   runtime="PASS" if tool.get("probe") == "PASS" else "UNTESTED")
        elif component == "frida_server":
            if evidence["frida_server_file_present"]:
                observation["installation"] = "INSTALLED"
                observation["source"] = ("PASS" if evidence["frida_server_sha256"] ==
                                         row["sha256"] else "BLOCKED")
                version = re.search(r"\d+(?:\.\d+){2}", row.get("artifact_path") or "")
                observation["installed_version"] = version.group(0) if version else None
        elif row["type"] == "CLI":
            command = CLI_NAMES.get(component, component)
            entry = evidence["cli"].get(component if component in evidence["cli"] else command)
            if entry and entry["status"] == "PASS":
                observation.update(installation="INSTALLED",
                                   command="/var/jb/usr/bin/" + command)
            elif receipt:
                observation["installation"] = "PARTIAL"
        elif receipt:
            observation.update(installation="INSTALLED", installed_version=receipt[1])
        observations[component] = observation
    if (observations["frida_server"]["installation"] == "INSTALLED" and
            observations["frida_cli"]["installation"] == "INSTALLED"):
        observations["frida"]["installation"] = "INSTALLED"
    result = evaluate(catalog, observations)
    result["environment"] = {
        "ios_version": evidence["os"], "build": evidence["build"],
        "device_model": model, "usb_identity_suffix": evidence["usb_identity_suffix"],
        "usb_identity_verified": evidence["usb_identity_verified"],
        "architecture": "arm64", "architecture_verified": False,
        "architecture_basis": "installed package ABI; arm64e capability unverified",
        "bootstrap": "rootless" if evidence["bootstrap"] else "unknown",
        "host_connected": evidence["host"].get("pairing_verified") is True and
                          evidence["host"].get("identity_verified") is True and
                          evidence["host"].get("age_seconds", 999) <= 15,
        "bridge_listener": evidence["bridge_listener"],
        "dpkg_audit_lines": evidence["dpkg_audit_lines"],
        "dpkg_audit_text": evidence.get("dpkg_audit_text", ""),
        "apt_check_exit": evidence.get("apt_check_exit"),
        "cli_probes": evidence["cli"],
        "frida_server_sha256": evidence["frida_server_sha256"],
        "registered_apps": evidence["registered_apps"],
        "host_tool_inventory_available": bool(evidence["host"].get("tool_ids")),
        "evidence_scope": "read-only device preflight; Control UI UAT was not run",
    }
    return result


def main() -> None:
    catalog = load_catalog()
    root = HERE / "0sky-uat"
    for path in sorted((HERE / "installer-verification").glob("toolkit-preflight-*.json")):
        observed = json.loads(path.read_text(encoding="utf-8"))
        if observed.get("usb_identity_verified") is not True:
            raise RuntimeError("exact USB identity was not verified: " + path.name)
        snapshot = snapshot_for(observed, catalog)
        smoke = run_smoke(snapshot, RecordedProbes(observed))
        uat = run_uat(snapshot, smoke)
        directory = write_bundle(root / observed["usb_identity_suffix"].lower(),
                                 snapshot, smoke, uat)
        print(json.dumps({"device": observed["usb_identity_suffix"],
                          "smoke": smoke["result"], "smoke_counts": smoke["counts"],
                          "uat": uat["result"], "uat_counts": uat["counts"],
                          "report": str(directory)}, sort_keys=True))


if __name__ == "__main__":
    main()
