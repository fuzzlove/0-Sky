#!/usr/bin/env python3
"""Activate the project's isolated no-reboot SRD SSH recovery service."""

import argparse
import json
from pathlib import Path

from repair_device_connection import profiles
from stage_srdssh_recovery import recover


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    selected = profiles(instance_name=args.instance)
    if set(selected) != {args.udid}:
        raise RuntimeError("exact worker profile does not match requested device")
    environment = selected[args.udid][1]["EnvironmentVariables"]
    key = Path(environment["CRYPSTORE_DEVICE_KEY"])
    if not key.is_file() or key.stat().st_mode & 0o077:
        raise RuntimeError("configured private key is unavailable or not mode 0600")
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    result = recover(args.udid, key, args.output, args.instance)
    print(json.dumps({"identifier": result.get("identifier"),
                      "remote_port": result.get("remote_port"),
                      "installed": result.get("installed", False),
                      "reused": result.get("reused", False),
                      "route_updated": bool(result.get("route"))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
