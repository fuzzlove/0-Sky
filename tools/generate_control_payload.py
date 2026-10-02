#!/usr/bin/env python3
"""Seal the verified kit's one Control IPA into a Link release manifest."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime/zero_sky_core"))
from control_payload import create_manifest, verify_manifest  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = create_manifest(args.ipa, ROOT / "control/TrollStoreLite/entitlements.plist")
    verify_manifest(args.ipa, manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                           encoding="utf-8")


if __name__ == "__main__":
    main()
