#!/usr/bin/env python3
"""Configure or verify Wi-Fi fallback for one enrolled, exact-identity SRD."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import time

from apple_device_pairing import MacIdentity, MacPairingCoordinator
from apple_device_transport import AppleDeviceTransportManager
from repair_device_connection import profiles, usb_identity


def context(udid: str) -> tuple[Path, Path]:
    profile = profiles().get(udid)
    if profile is None:
        raise RuntimeError("No enrolled worker for this exact device")
    instance = Path(profile[1]["EnvironmentVariables"]["CRYPSTORE_INSTANCE_DIR"])
    if not instance.is_dir() or instance.is_symlink():
        raise RuntimeError("Enrolled instance is missing or unsafe")
    support = instance.parent.parent
    receipt = instance / "pairing-state.json"
    state = json.loads(receipt.read_text())
    if state.get("device_udid") != udid or state.get("verified") is not True:
        raise RuntimeError("Trusted Mac receipt is not verified for this exact device")
    return support, receipt


def save_wireless(receipt: Path, udid: str, wireless: dict) -> None:
    if receipt.is_symlink():
        raise RuntimeError("Refusing symbolic-link pairing receipt")
    state = json.loads(receipt.read_text())
    if state.get("device_udid") != udid or state.get("verified") is not True:
        raise RuntimeError("Pairing receipt changed during wireless setup")
    state["wireless"] = wireless
    temporary = receipt.with_name(f".{receipt.name}.{os.getpid()}.{time.time_ns()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(state, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, receipt)
    finally:
        temporary.unlink(missing_ok=True)


async def configure(udid: str) -> dict:
    await usb_identity(udid)
    support, receipt = context(udid)
    trusted = await MacPairingCoordinator(support, timeout=90).run(
        udid, allow_pair=False, allow_host_enrollment=False)
    if (trusted.get("status") != "verified" or trusted.get("device", {}).get("udid") != udid or
            not trusted.get("pairing", {}).get("lockdownSessionValidated") or
            not trusted.get("host", {}).get("identityVerified")):
        raise RuntimeError(f"Existing USB trust could not be reverified: {trusted.get('errorCode')}")
    fingerprint = trusted["host"]["publicKeyFingerprint"]
    wireless = await AppleDeviceTransportManager(support).enable_wireless(
        udid, fingerprint, usb_trust_verified=True)
    wireless = dict(wireless)
    wireless["wifiPairingVerified"] = bool(wireless.get("relationship", {}).get("wifiPairingVerified"))
    if wireless.get("status") in ("pending", "ready"):
        save_wireless(receipt, udid, wireless)
    return wireless


async def verify(udid: str, require_usb_absent: bool = True) -> dict:
    support, receipt = context(udid)
    _, fingerprint = MacIdentity(support).ensure()
    wireless = await AppleDeviceTransportManager(support).verify_wireless(
        udid, fingerprint, require_usb_absent=require_usb_absent,
        discovery_timeout=30, poll_interval=1)
    wireless = dict(wireless)
    wireless["wifiPairingVerified"] = bool(wireless.get("relationship", {}).get("wifiPairingVerified"))
    if wireless.get("status") == "ready" and not wireless["wifiPairingVerified"]:
        raise RuntimeError("Wireless transport reported ready without a verified relationship")
    if wireless.get("status") == "ready":
        save_wireless(receipt, udid, wireless)
    return wireless


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--verify", action="store_true",
                        help="verify the configured network link after USB is disconnected")
    parser.add_argument("--allow-usb-present", action="store_true",
                        help="still require an authenticated network transport, but permit attached USB")
    args = parser.parse_args()
    if args.allow_usb_present and not args.verify:
        parser.error("--allow-usb-present requires --verify")
    result = asyncio.run(verify(args.udid, not args.allow_usb_present)
                         if args.verify else configure(args.udid))
    print(json.dumps({"device": args.udid, "status": result.get("status"),
                      "errorCode": result.get("errorCode"),
                      "wifiLockdownEnabled": result.get("wifiLockdownEnabled"),
                      "wifiPairingVerified": result.get("wifiPairingVerified"),
                      "remotePairingReady": result.get("remotePairingReady"),
                      "wirelessRSDVerified": result.get("relationship", {}).get("wirelessRSDVerified"),
                      "requiresCableRemovalVerification":
                          result.get("requiresCableRemovalVerification")}, indent=2))
    if result.get("status") == "failed":
        raise SystemExit(1)
