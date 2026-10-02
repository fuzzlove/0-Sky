#!/usr/bin/env python3
"""Produce deterministic v2 compatibility state-machine acceptance evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))

from zero_sky_compat import CompatibilityEngine, Environment  # noqa: E402
from zero_sky_compat.transaction import atomic_json  # noqa: E402
from zero_sky_compat.validation import DataTreeBackend  # noqa: E402


class EntitlementFailureBackend(DataTreeBackend):
    name = "acceptance-entitlement-failure-v1"

    def validate(self, staged, report):
        return {
            "install": {"passed": True, "detail": "staged fixture installed"},
            "dependencies": {"passed": True, "detail": "fixture has no dependencies"},
            "privilege_contract": {"passed": True, "detail": "fixture data destination only"},
            "functional_test": {"passed": False,
                                "detail": "missing required entitlement"},
        }


def summarize(report):
    return {
        "component": report.component,
        "compatibility_state": report.compatibility_state,
        "transaction": report.transaction.get("phase"),
        "issues": sorted({item["code"] for item in report.issues}),
        "adaptations": report.adaptations,
        "evidence": report.evidence,
    }


def run_acceptance():
    environment = Environment(
        ios_version="27.0", build_version="ACCEPTANCE",
        device_model="authorized-srd-fixture", architecture="arm64",
        bootstrap_type="rootless", bootstrap_prefix="/var/jb", uid=0, gid=0,
        capabilities={"var_jb": True, "root": True,
                      "launchctl": False, "system_launchctl": True})
    with tempfile.TemporaryDirectory(prefix="0sky-compat-acceptance-") as folder:
        root = Path(folder)

        unknown_source = root / "unknown-method"
        unknown_source.mkdir()
        (unknown_source / "configuration.json").write_text("{}")
        unknown = CompatibilityEngine(root / "unknown-state", environment).process(
            unknown_source).report

        adapted_source = root / "legacy-rootful"
        (adapted_source / "etc").mkdir(parents=True)
        (adapted_source / "etc/fixture.conf").write_text("enabled=1\n")
        adapted = CompatibilityEngine(root / "adapted-state", environment).process(
            adapted_source, DataTreeBackend(root / "adapted-installed")).report

        blocked_source = root / "entitlement-fixture"
        (blocked_source / "etc").mkdir(parents=True)
        (blocked_source / "etc/fixture.conf").write_text("requires=entitlement\n")
        blocked = CompatibilityEngine(root / "blocked-state", environment).process(
            blocked_source,
            EntitlementFailureBackend(root / "blocked-installed")).report

        if unknown.compatibility_state != "UNKNOWN":
            raise RuntimeError("unknown installation method was not preserved")
        if adapted.compatibility_state != "COMPATIBLE_WITH_ADAPTER":
            raise RuntimeError("reviewed rootless adaptation did not validate")
        if blocked.compatibility_state != "BLOCKED_BY_ENTITLEMENT":
            raise RuntimeError("runtime entitlement failure was not classified specifically")
        return {
            "schema_version": 1,
            "environment": environment.summary(),
            "cases": {
                "unknown_method": summarize(unknown),
                "adaptation_success": summarize(adapted),
                "evidence_blocker": summarize(blocked),
            },
            "result": "PASS",
            "release_admission": "NOT_GRANTED_BY_FIXTURE",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT /
                        "artifacts/compatibility/reports/pipeline-acceptance-v2.json")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    value = run_acceptance()
    atomic_json(args.output, value)
    print(json.dumps({"result": value["result"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
