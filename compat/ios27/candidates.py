"""Hash-pinned selection among different builds of one package identifier."""
from __future__ import annotations

import json
from pathlib import Path
import re

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
COMPONENT_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}-[0-9a-f]{12}\Z")
PACKAGE_ID = re.compile(r"[a-z0-9][a-z0-9+._-]{1,199}\Z")


def load_candidate_pins(root: Path) -> tuple[dict[str, dict], list[str]]:
    path = root / "compat/ios27/reviewed-candidates.json"
    if not path.exists() and not path.is_symlink():
        return {}, []
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        return {}, ["CANDIDATE_REGISTRY_INVALID"]
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, ValueError):
        return {}, ["CANDIDATE_REGISTRY_INVALID"]
    if (not isinstance(value, dict) or value.get("schema") != 1 or
            not isinstance(value.get("candidates"), dict) or
            len(value["candidates"]) > 1000):
        return {}, ["CANDIDATE_REGISTRY_INVALID"]
    pins = {}
    errors = []
    for package, choice in sorted(value["candidates"].items()):
        if (not isinstance(package, str) or not PACKAGE_ID.fullmatch(package) or
                not isinstance(choice, dict) or
                not isinstance(choice.get("component_id"), str) or
                not COMPONENT_ID.fullmatch(choice["component_id"]) or
                not isinstance(choice.get("artifact_sha256"), str) or
                not HEX64.fullmatch(choice["artifact_sha256"])):
            errors.append("CANDIDATE_PIN_INVALID")
            continue
        pins[package] = choice
    return pins, errors
