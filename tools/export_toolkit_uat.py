#!/usr/bin/env python3
"""Export bounded, sanitized host evidence for two or more exact-device UAT runs."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))
from zero_sky_core.research_toolkit_runner import overall_result  # noqa: E402
from tools.release_sanitize import audit  # noqa: E402

ALLOWED_RESULTS = {"PASS", "PASS_WITH_WARNINGS", "DEGRADED", "FAIL", "BLOCKED", "SKIP"}
RESULT_ORDER = ("BLOCKED", "FAIL", "DEGRADED", "SKIP", "PASS")
IDENTITY = re.compile(r"[a-f0-9]{16}\Z")
FIELDS = ("id", "name", "type", "category", "badge", "lifecycle_stage",
          "installed_version", "available_version", "last_tested", "facets",
          "missing_dependencies", "compatibility_reason", "runtime_reason")
SOURCE_FIELDS = ("id", "name", "upstream_project", "source_git_revision",
                 "source_mirror", "source_mirror_revision", "source_trust",
                 "package_repository", "package_source_trust")
CATEGORIES = {"apps": "Apps/", "tweaks": "Tweaks/",
              "instrumentation": "Research Tools/Instrumentation",
              "command-line": "Research Tools/Command Line",
              "host-tools": "Host Security Tools"}


def load_receipt(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("device UAT receipt is absent or unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("device UAT receipt must be an object")
    device, result, inventory = (value.get(name) for name in ("device", "result", "inventory"))
    if not all(isinstance(item, dict) for item in (device, result, inventory)):
        raise ValueError("device UAT receipt is incomplete")
    if (not IDENTITY.fullmatch(str(device.get("device_reference", ""))) or
            device.get("usb_identity_verified") is not True or
            not isinstance(device.get("product"), str) or
            not isinstance(device.get("build"), str) or
            not isinstance(inventory.get("components"), list) or
            not isinstance(inventory.get("environment"), dict) or
            not isinstance(result.get("smoke"), dict) or
            not isinstance(result.get("uat"), dict)):
        raise ValueError("device UAT identity or suite is incomplete")
    strict = overall_result(result["smoke"], result["uat"])
    if strict != value.get("verified_overall") or strict not in ALLOWED_RESULTS:
        raise ValueError("device UAT overall result differs from the test cases")
    for suite in (result["smoke"], result["uat"]):
        if (not isinstance(suite.get("tests"), list) or
                any(not isinstance(case, dict) or
                    case.get("result") not in ALLOWED_RESULTS or
                    not isinstance(case.get("id"), str)
                    for case in suite["tests"])):
            raise ValueError("device UAT cases are incomplete")
    if any(not isinstance(row, dict) or not isinstance(row.get("id"), str) or
           not isinstance(row.get("category"), str) or
           not isinstance(row.get("facets"), dict) for row in inventory["components"]):
        raise ValueError("device UAT inventory is incomplete")
    ids = [row["id"] for row in inventory["components"]]
    if len(ids) != len(set(ids)):
        raise ValueError("device UAT inventory has duplicate component IDs")
    return value


def public_component(row: dict, reference: str) -> dict:
    return {"device_reference": reference, **{name: row.get(name) for name in FIELDS}}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def export(receipts: list[Path], output: Path) -> dict:
    if len(receipts) < 1 or output.exists() or output.is_symlink():
        raise ValueError("at least one receipt and a new output directory are required")
    values = [load_receipt(path) for path in receipts]
    references = [value["device"]["device_reference"] for value in values]
    if len(references) != len(set(references)):
        raise ValueError("the same device appears more than once")
    devices = []
    categories: dict[str, list[dict]] = {name: [] for name in CATEGORIES}
    sources, compatibility, dependencies, smoke, uat, failures = [], [], [], [], [], []
    for value in values:
        device, result, inventory = value["device"], value["result"], value["inventory"]
        reference = device["device_reference"]
        badges = dict(sorted(Counter(row.get("badge", "UNKNOWN")
                                     for row in inventory["components"]).items()))
        devices.append({"device_reference": reference, "model": device["product"],
                        "ios_version": device.get("version"), "ios_build": device["build"],
                        "collected_at": value.get("collected_at"),
                        "environment": inventory["environment"],
                        "component_count": len(inventory["components"]),
                        "badges": badges, "smoke_counts": result["smoke"].get("counts", {}),
                        "uat_counts": result["uat"].get("counts", {}),
                        "overall": value["verified_overall"],
                        "device_reported_overall": result.get("overall")})
        for row in inventory["components"]:
            component = public_component(row, reference)
            for name, prefix in CATEGORIES.items():
                if row["category"].startswith(prefix):
                    categories[name].append(component)
            sources.append({"device_reference": reference,
                            **{name: row.get(name) for name in SOURCE_FIELDS}})
            compatibility.append({"device_reference": reference, "component": row["id"],
                                  "compatibility": row["facets"].get("compatibility"),
                                  "reason": row.get("compatibility_reason"),
                                  "badge": row.get("badge")})
            dependencies.append({"device_reference": reference, "component": row["id"],
                                 "state": row["facets"].get("dependencies"),
                                 "missing": row.get("missing_dependencies", [])})
        for suite_name, destination in (("smoke", smoke), ("uat", uat)):
            for case in result[suite_name]["tests"]:
                entry = {"device_reference": reference, **case}
                destination.append(entry)
                if case["result"] in {"FAIL", "BLOCKED", "DEGRADED"}:
                    failures.append({"suite": suite_name, **entry})
    overall = next((state for state in RESULT_ORDER if state in
                    {device["overall"] for device in devices}), "BLOCKED")
    summary = {"schema": 1, "overall": overall, "device_count": len(devices),
               "component_observations": sum(device["component_count"] for device in devices),
               "smoke_cases": len(smoke), "uat_cases": len(uat),
               "failed_or_degraded_cases": len(failures),
               "release_accepted": False, "manual_researcher_evaluation_required": True}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".0sky-uat-export-", dir=output.parent) as temporary:
        stage = Path(temporary) / "bundle"
        stage.mkdir(mode=0o700)
        files = {"summary.json": summary, "environment.json": devices,
                 "sources.json": sources, "compatibility.json": compatibility,
                 "dependencies.json": dependencies, "apps.json": categories["apps"],
                 "tweaks.json": categories["tweaks"],
                 "instrumentation.json": categories["instrumentation"],
                 "command-line.json": categories["command-line"],
                 "host-tools.json": categories["host-tools"],
                 "smoke-tests.json": smoke, "uat-results.json": uat,
                 "failures.json": failures}
        for name, payload in files.items():
            write_json(stage / name, payload)
        lines = ["# 0-Sky Security Research Toolkit UAT", "",
                 "Overall automated result: **" + overall + "**", "",
                 "| Device | iOS build | Components | Smoke | UAT | Result |",
                 "| --- | --- | ---: | --- | --- | --- |"]
        for device in devices:
            lines.append("| " + device["model"] + " | " + device["ios_build"] + " | " +
                         str(device["component_count"]) + " | " +
                         str(device["smoke_counts"]) + " | " +
                         str(device["uat_counts"]) + " | " + device["overall"] + " |")
        lines += ["", "Manual researcher evaluation required.", ""]
        (stage / "summary.md").write_text("\n".join(lines), encoding="utf-8")
        (stage / "logs").mkdir()
        (stage / "logs" / "README.md").write_text(
            "No raw device logs are included. Test case evidence is in the JSON files.\n",
            encoding="utf-8")
        findings = audit([stage])
        if findings:
            raise ValueError("UAT bundle contains sensitive data: " +
                             ", ".join(sorted({item["category"] for item in findings})))
        if output.exists() or output.is_symlink():
            raise FileExistsError("UAT output appeared during export")
        os.replace(stage, output)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", action="append", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = export(args.receipt, args.output)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["overall"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
