#!/usr/bin/env python3
"""Reproduce HIGH-confidence manual conversions and prove artifact equality."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))

from zero_sky_compat.archive_adapter import normalize_zip_compression
from zero_sky_compat.deb_adapter import canonicalize_locked_plist


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name("." + path.name + ".tmp")
    pending.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    pending.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--search-root", type=Path, action="append", required=True)
    parser.add_argument("--report", type=Path,
                        default=ROOT / "reports/converter-reproduction.json")
    args = parser.parse_args()
    originals = []
    for root in args.search_root:
        candidate = root.expanduser().resolve() / "TRApp_4.7-3658.tipa"
        if candidate.is_file() and not candidate.is_symlink():
            originals.append(candidate)
    if len(originals) != 1:
        raise FileNotFoundError("exactly one configured TrollRecorder original is required")
    lock = json.loads((ROOT / "compatibility/conversion-locks/doodle-1.1-ios27-filter.json").read_text())
    doodle_source = ROOT / "artifacts/compatibility/doodle/com.nahtedetihw.doodle_1%3a1.1+0sky27.1_iphoneos-arm64.deb"
    known_trapp = ROOT / "addons/PoC/installer-verification/tipa-compression/TRApp_4.7-3658.tipa"
    known_doodle = ROOT / "artifacts/compatibility/doodle/com.nahtedetihw.doodle_1%3a1.1+0sky27.2_iphoneos-arm64.deb"
    with tempfile.TemporaryDirectory(prefix="0sky-reproduction-") as folder:
        temporary = Path(folder)
        trapp = temporary / "TRApp+0sky1.tipa"
        trapp_result = normalize_zip_compression(originals[0], trapp)
        doodle = temporary / "Doodle+0sky27.2.deb"
        doodle_result = canonicalize_locked_plist(
            doodle_source, doodle, package=lock["package"],
            from_version=lock["from_version"], to_version=lock["to_version"],
            plist_path=lock["plist_path"], source_date_epoch=lock["source_date_epoch"])
        rows = [
            {"component": "TrollRecorder", "rule": trapp_result["rule"],
             "reproduced_sha256": digest(trapp), "known_working_sha256": digest(known_trapp),
             "runtime_evidence": "addons/PoC/DEVICE_CONNECTION_REPAIR.md"},
            {"component": "Doodle", "rule": doodle_result["rule"],
             "reproduced_sha256": digest(doodle), "known_working_sha256": digest(known_doodle),
             "runtime_evidence": "artifacts/compatibility/doodle/uat-summary.json"},
        ]
    for row in rows:
        row["artifact_equivalence"] = "PASS" if row["reproduced_sha256"] == row["known_working_sha256"] else "FAIL"
    result = {"schema_version": 1, "result": "PASS" if all(row["artifact_equivalence"] == "PASS" for row in rows) else "FAIL",
              "conversions": rows, "originals_preserved": True,
              "device_mutation": "NONE; equality is evaluated against previously device-tested artifact hashes"}
    atomic(args.report, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
