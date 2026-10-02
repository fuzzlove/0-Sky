#!/usr/bin/env python3
"""Update changed bundled host pairing checksums in the source kit."""
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parents[2]
kit = root / "bridge/0SkyBridge/Resources/Scripts/kit"
manifest = kit / "SHA256SUMS"
lines = manifest.read_text().splitlines()
for name in ("pair.py", "apple_device_transport.py"):
    source = root / "bridge/HostTools" / name
    bundled = kit / "host-mac" / name
    if source.read_bytes() != bundled.read_bytes():
        raise SystemExit(f"Pairing helpers differ: {name}")
    digest = hashlib.sha256(bundled.read_bytes()).hexdigest()
    suffix = f"  ./host-mac/{name}"
    matches = [index for index, line in enumerate(lines) if line.endswith(suffix)]
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one manifest entry: {name}")
    lines[matches[0]] = f"{digest}{suffix}"
manifest.write_text("\n".join(lines) + "\n")
print("BUNDLED_PAIRING_SHA256=PASS")
