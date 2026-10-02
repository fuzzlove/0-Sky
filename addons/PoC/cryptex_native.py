#!/usr/bin/env python3
"""Install an authorized SRD research cryptex over the RemoteXPC tunnel."""

import asyncio
import contextlib
import copy
import hashlib
import pathlib
import plistlib
import sys

from device_python import ensure_device_python

ensure_device_python()

from pymobiledevice3.exceptions import DeviceNotFoundError, StreamClosedError
from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.remote.xpc_message import XpcUInt64Type
from pymobiledevice3.restore.tss import TSSRequest
from pymobiledevice3.services.cryptexd import CryptexdService

from remotexpc_flow_control import enable_flow_control_accounting, verify_flow_control_accounting

enable_flow_control_accounting()
print(f"native runner={pathlib.Path(__file__).resolve()} python={sys.executable}", flush=True)
print(f"transport flow-control=all-data-v1 source={verify_flow_control_accounting()}", flush=True)

if sys.argv[1:] == ["--check-transport"]:
    print("TRANSPORT CHECK SUCCESS: no device connection or changes", flush=True)
    raise SystemExit(0)


IDENTIFIER = sys.argv[1]
IMAGE_PATH = pathlib.Path(sys.argv[2])
TRUST_PATH = pathlib.Path(sys.argv[3])
HASH_PATH = pathlib.Path(sys.argv[4])
VERSION = sys.argv[5]
UDID = sys.argv[6]
TEMPLATE_MANIFEST = pathlib.Path(sys.argv[7])
PREFLIGHT_ONLY = "--preflight-only" in sys.argv[8:]

def compatibility_stop(operation):
    import pathlib
    import sys
    for ancestor in pathlib.Path(__file__).resolve().parents:
        runtime = ancestor / "bridge" / "DeviceRuntime"
        if (runtime / "zero_sky_compat").is_dir():
            sys.path.insert(0, str(runtime))
            break
    from zero_sky_compat.integration import block_legacy_mutation
    block_legacy_mutation(operation)


if not PREFLIGHT_ONLY:
    compatibility_stop("native-cryptex-install")

BUILD_MANIFEST = plistlib.loads(TEMPLATE_MANIFEST.read_bytes())
IMAGE = IMAGE_PATH.read_bytes()
TRUST = TRUST_PATH.read_bytes()
HASH_DATA = HASH_PATH.read_bytes()


def der_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def der_ia5(value: str) -> bytes:
    encoded = value.encode("ascii")
    return b"\x16" + der_length(len(encoded)) + encoded


def der_octets(value: bytes) -> bytes:
    return b"\x04" + der_length(len(value)) + value


def der_sequence(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + der_length(len(body)) + body


VOLUME_HASH = (HASH_DATA if b"IM4P" in HASH_DATA[:16]
               else der_sequence(der_ia5("IM4P"), der_ia5("gtgv"),
                                 der_ia5("0"), der_octets(HASH_DATA)))
info_asset = IMAGE_PATH.with_name("ginf")
INFO_PLIST = (info_asset.read_bytes() if info_asset.is_file() else plistlib.dumps(
    {"CFBundleIdentifier": IDENTIFIER, "CFBundleVersion": VERSION,
     "DeveloperModeRequired": True}, fmt=plistlib.FMT_XML, sort_keys=True))
info = plistlib.loads(INFO_PLIST)
if info.get("CFBundleIdentifier") != IDENTIFIER or info.get("CFBundleVersion") != VERSION:
    raise ValueError("Cryptex info plist does not match identifier and version")


def make_build_identity():
    identity = copy.deepcopy(BUILD_MANIFEST["BuildIdentities"][0])
    identity.update(
        {
            "Cryptex1,UseProductClass": True,
            "Cryptex1,ChipID": "0xff10",
            "Cryptex1,ProductClass": "0xf2",
            "Cryptex1,Type": 3,
            "Cryptex1,SubType": 255,
            "Cryptex1,NonceDomain": 3,
            "Cryptex1,Version": "999.999.999.999.999,999",
            "Cryptex1,PreauthorizationVersion": "999.999.999.999.999,999",
        }
    )
    for key, data in (
        ("Cryptex1,CryptexInfoPlist", INFO_PLIST),
        ("Cryptex1,GenericTrustCache", TRUST),
        ("Cryptex1,GenericVolume", VOLUME_HASH),
        ("Cryptex1,GenericDmg", IMAGE),
    ):
        entry = identity["Manifest"].setdefault(key, {"Info": {}})
        entry["Digest"] = hashlib.sha384(data).digest()
        entry.setdefault("Info", {})["Personalize"] = True
    return identity


async def main():
    async with NativeRemotedTunnel(serial=UDID) as rsd:
        if str(rsd.udid) != UDID:
            raise RuntimeError(f"RemoteXPC selected {rsd.udid}, not {UDID}")
        print("native", rsd.udid, rsd.product_type, flush=True)
        service = CryptexdService(rsd)
        # Complete the read-only SRD/TSS preflight before replacing a known-good
        # installed cryptex. A normal device or ticket failure therefore leaves
        # the existing installation untouched.
        identifiers = await service.read_personalization_identifiers()
        research_enabled = identifiers.get("img4_chip_rsch")
        # The legacy indicator is advisory on current iOS 27 builds.  A fresh
        # exact-device domain-3 nonce plus Apple's live TSS ticket is the
        # authorization boundary; no mutation occurs before both succeed.
        nonce = await service.cryptex_nonce(3)
        if not nonce:
            raise RuntimeError("cryptexd returned an empty domain-3 nonce")
        print(
            "ids rsch",
            identifiers.get("img4_chip_rsch"),
            "nonce len",
            len(nonce),
            "trust len",
            len(TRUST),
            "image len",
            len(IMAGE),
            flush=True,
        )

        identity = make_build_identity()
        request = TSSRequest()
        request.add_cryptex1_tags(identity, identifiers, nonce)
        response = await request.send_receive()
        ticket = response.get("Cryptex1,Ticket")
        if not isinstance(ticket, (bytes, bytearray)) or not ticket:
            raise RuntimeError("Apple TSS did not authorize a Cryptex1 ticket")
        print("ticket", len(ticket), "authorization live-tss", flush=True)
        if PREFLIGHT_ONLY:
            print("PREFLIGHT SUCCESS: no device changes made", flush=True)
            return

        with contextlib.suppress(Exception):
            await asyncio.wait_for(service.uninstall(IDENTIFIER), timeout=30)
            print("uninstalled old", IDENTIFIER, flush=True)

        properties = {
            "Cryptex1,UseProductClass": True,
            "MountedCryptex": False,
            "Cryptex1,SubType": XpcUInt64Type(255),
            "Cryptex1,NonceDomain": XpcUInt64Type(3),
            "Cryptex1,Version": identity["Cryptex1,Version"],
            "Cryptex1,PreauthVersion": identity[
                "Cryptex1,PreauthorizationVersion"
            ],
        }
        await asyncio.wait_for(
            service.install(
                IMAGE,
                TRUST,
                ticket,
                INFO_PLIST,
                VOLUME_HASH,
                properties,
                image_type_index=10,
                persistence=2,
                nonce_persistence=1,
                auth=0,
            ),
            # iOS 27 can spend more than four minutes finalizing a larger
            # replacement Cryptex even though the RemoteXPC connection is
            # healthy.  Keep the operation bounded, but do not cancel it at
            # the former 240-second threshold while cryptexd is still working.
            timeout=900,
        )
        print("INSTALL SUCCESS", IDENTIFIER, flush=True)


try:
    asyncio.run(main())
except DeviceNotFoundError as error:
    raise SystemExit(
        f"RemoteXPC target {UDID} is unavailable: {error}\n"
        "The selected USB UDID must also be paired and visible in "
        "`python -m pymobiledevice3 remote browse --native`."
    ) from error
except StreamClosedError as error:
    raise SystemExit(
        f"RemoteXPC transfer failed for {IDENTIFIER}: {error}\n"
        "Installation was not confirmed. Check device state before retrying; "
        "the previous cryptex may already have been removed."
    ) from error
