#!/usr/bin/env python3
"""Run the read-only Doodle API survey on one exact paired USB SRD."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

from repair_device_connection import profiles, usb_identity, worker_namespace


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "compat/ios27/doodle/runtime_probe.py"


def run(instance: str, udid: str) -> dict:
    selected = profiles(instance_name=instance)
    if udid not in selected or asyncio.run(usb_identity(udid))["udid"] != udid:
        raise RuntimeError("exact USB identity and paired worker do not match")
    worker = worker_namespace(selected[udid][1])
    result = worker["ssh"]("/var/jb/usr/bin/python3 -", input_data=PROBE.read_bytes(),
                           timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("Doodle API survey failed: " +
                           result.stderr.decode("utf-8", "replace")[-300:])
    report = json.loads(result.stdout)
    if report.get("schema") != 1 or report.get("component") != "com.nahtedetihw.doodle":
        raise RuntimeError("Doodle API survey returned the wrong component")
    output = ROOT / "artifacts/compatibility/doodle" / ("api-" + udid[-8:].lower() + ".json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return {"device": udid[-8:], "ios": report["ios_version"], "build": report["ios_build"],
            "api_result": report["compatibility"]["result"],
            "legacy_hook_result": report["legacy_hook_compatibility"]["result"],
            "evidence": str(output)}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: doodle_api_uat.py INSTANCE EXACT_UDID")
    print(json.dumps(run(sys.argv[1], sys.argv[2]), sort_keys=True))
