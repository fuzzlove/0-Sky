"""Resolve a 0-Sky per-device support directory without cross-device fallback."""

from __future__ import annotations

from pathlib import Path
import re


def slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:63]
    if not result:
        raise SystemExit("invalid 0-Sky instance name")
    return result


def resolve(base: Path, instance_name: str | None) -> Path:
    base = base.expanduser().resolve()
    if instance_name:
        selected = base / "instances" / slug(instance_name)
        if not ((selected / "config.json").is_file() or
                (selected / "pairing-state.json").is_file()):
            raise SystemExit(f"0-Sky instance is not installed: {selected}")
        return selected
    # Retain read compatibility with the pre-1.8 single-device layout.
    if (base / "config.json").is_file():
        return base
    instances = sorted({path.parent for path in (base / "instances").glob("*/config.json")} |
                       {path.parent for path in (base / "instances").glob("*/pairing-state.json")})
    if len(instances) == 1:
        return instances[0]
    if not instances:
        raise SystemExit(f"no 0-Sky companion instance found below {base}")
    names = ", ".join(path.name for path in instances)
    raise SystemExit(f"multiple 0-Sky instances exist ({names}); pass --instance-name")
