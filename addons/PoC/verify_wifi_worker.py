#!/usr/bin/env python3
"""Refresh and verify an enrolled Mac worker over its pinned Wi-Fi SSH route."""
import argparse
import json

from repair_device_connection import profiles, worker_namespace


def verify(udid: str) -> None:
    profile = profiles().get(udid)
    if profile is None:
        raise RuntimeError("No exact-device worker profile")
    namespace = worker_namespace(profile[1])
    live = namespace["refresh_apple_pairing"](allow_pair=False)
    transport = live.get("transport", {}).get("type")
    verified = (live.get("status") == "verified" and
                live.get("device", {}).get("udid") == udid and
                live.get("host", {}).get("identityVerified") and
                transport in ("WIFI_LOCKDOWN", "NATIVE_REMOTEXPC", "USERSPACE_RSD"))
    result = {"device": udid, "apple_wifi_verified": bool(verified),
              "transport": transport, "errorCode": live.get("errorCode")}
    if not verified:
        print(json.dumps(result, indent=2))
        raise SystemExit(1)
    response = namespace["ssh"]("id -u", timeout=20, check=False)
    result["root_ssh_over_fallback"] = response.returncode == 0 and response.stdout.strip() == b"0"
    result["ssh_exit"] = response.returncode
    print(json.dumps(result, indent=2))
    if not result["root_ssh_over_fallback"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    verify(parser.parse_args().udid)
