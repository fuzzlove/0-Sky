"""Load reviewer-pinned device evidence for repository admission.

The scanner never trusts an unreviewed runtime report merely because it exists
on disk. A receipt must be pinned by SHA-256 in reviewed-admission.json.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RECEIPT_NAME = re.compile(r"[0-9a-f]{64}\.json\Z")


def load_reviewed_receipts(root: Path) -> tuple[dict[tuple[str, str], dict], list[str]]:
    base = root / "compat/ios27"
    registry = base / "reviewed-admission.json"
    if not registry.exists() and not registry.is_symlink():
        return {}, []
    if registry.is_symlink() or not registry.is_file() or registry.stat().st_size > 65536:
        return {}, ["REVIEWED_ADMISSION_REGISTRY_INVALID"]
    try:
        reviewed = json.loads(registry.read_text())
    except (OSError, UnicodeError, ValueError):
        return {}, ["REVIEWED_ADMISSION_REGISTRY_INVALID"]
    pins = reviewed.get("receipts") if isinstance(reviewed, dict) else None
    if not isinstance(reviewed, dict) or reviewed.get("schema") != 1 or not isinstance(pins, dict) or len(pins) > 1000:
        return {}, ["REVIEWED_ADMISSION_REGISTRY_INVALID"]
    receipts: dict[tuple[str, str], dict] = {}
    errors: list[str] = []
    for name, expected_hash in sorted(pins.items()):
        if (not isinstance(name, str) or not RECEIPT_NAME.fullmatch(name) or
                not isinstance(expected_hash, str) or not HEX64.fullmatch(expected_hash)):
            errors.append("REVIEWED_ADMISSION_PIN_INVALID")
            continue
        path = base / "admission-evidence" / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            errors.append("REVIEWED_ADMISSION_RECEIPT_MISSING_OR_UNSAFE:" + name)
            continue
        try:
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected_hash:
                errors.append("REVIEWED_ADMISSION_HASH_MISMATCH:" + name)
                continue
            value = json.loads(raw)
        except (OSError, UnicodeError, ValueError):
            errors.append("REVIEWED_ADMISSION_RECEIPT_INVALID:" + name)
            continue
        if (not isinstance(value, dict) or value.get("schema") != 1 or
                not isinstance(value.get("component_id"), str) or
                not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}-[0-9a-f]{12}", value["component_id"]) or
                not isinstance(value.get("artifact_sha256"), str) or
                not HEX64.fullmatch(value["artifact_sha256"]) or
                not isinstance(value.get("environment_hash"), str) or
                not HEX64.fullmatch(value["environment_hash"]) or
                not isinstance(value.get("stages"), dict) or
                any(not isinstance(stage, dict) or stage.get("result") not in
                    {"PASS", "FAIL", "BLOCKED", "UNVERIFIED", "SKIP"}
                    for stage in value["stages"].values()) or
                type(value.get("quarantined")) is not bool):
            errors.append("REVIEWED_ADMISSION_RECEIPT_INVALID:" + name)
            continue
        if name != value["artifact_sha256"] + ".json":
            errors.append("REVIEWED_ADMISSION_ARTIFACT_NAME_MISMATCH:" + name)
            continue
        evidence_dir = base / "admission-evidence" / value["artifact_sha256"]
        evidence_valid = True
        for stage_name, stage in value["stages"].items():
            if stage.get("result") != "PASS":
                continue
            expected_file = stage_name + ".json"
            evidence_hash = stage.get("evidence_sha256")
            if (not re.fullmatch(r"[a-z_]{1,64}", stage_name) or
                    stage.get("evidence_file") != expected_file or
                    not isinstance(evidence_hash, str) or not HEX64.fullmatch(evidence_hash) or
                    evidence_dir.is_symlink()):
                evidence_valid = False
                break
            evidence_path = evidence_dir / expected_file
            if (evidence_path.is_symlink() or not evidence_path.is_file() or
                    evidence_path.stat().st_size > 1024 * 1024):
                evidence_valid = False
                break
            try:
                evidence_raw = evidence_path.read_bytes()
                observed = json.loads(evidence_raw)
            except (OSError, UnicodeError, ValueError):
                evidence_valid = False
                break
            if (hashlib.sha256(evidence_raw).hexdigest() != evidence_hash or
                    not isinstance(observed, dict) or observed.get("schema") != 1 or
                    observed.get("component_id") != value["component_id"] or
                    observed.get("artifact_sha256") != value["artifact_sha256"] or
                    observed.get("environment_hash") != value["environment_hash"] or
                    observed.get("stage") != stage_name or observed.get("result") != "PASS" or
                    not isinstance(observed.get("observations"), list) or
                    not observed["observations"] or
                    any(not isinstance(item, dict) or
                        not isinstance(item.get("expected"), str) or not item["expected"] or
                        not isinstance(item.get("observed"), str) or not item["observed"]
                        for item in observed["observations"])):
                evidence_valid = False
                break
        if not evidence_valid:
            errors.append("REVIEWED_ADMISSION_STAGE_EVIDENCE_INVALID:" + name)
            continue
        key = (value["component_id"], value["artifact_sha256"])
        if key in receipts:
            errors.append("REVIEWED_ADMISSION_DUPLICATE_RECEIPT:" + name)
            continue
        value["reviewed_receipt_sha256"] = expected_hash
        receipts[key] = value
    return receipts, errors
