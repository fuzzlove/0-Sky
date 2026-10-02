#!/usr/bin/env python3
"""Read a paired iOS device's RemoteXPC Cryptex1 personalization state."""

import argparse
import asyncio

from device_python import ensure_device_python

ensure_device_python()

from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.services.cryptexd import CryptexdService


async def probe(udid: str, list_installed: bool) -> None:
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid:
            raise RuntimeError(f"Selected {rsd.udid}, expected {udid}")
        service = CryptexdService(rsd)
        identifiers = await service.read_personalization_identifiers()
        nonce = await service.cryptex_nonce(3)
        print(f"UDID: {rsd.udid}")
        print(f"Product: {rsd.product_type}")
        print(f"Research flag: {identifiers.get('img4_chip_rsch')}")
        print(f"Cryptex1 domain-3 nonce bytes: {len(nonce) if nonce else 0}")
        if list_installed:
            for installed in await service.copy_installed():
                print(f"Installed: {installed.identifier} {installed.version}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--list-installed", action="store_true")
    args = parser.parse_args()
    asyncio.run(probe(args.udid, args.list_installed))


if __name__ == "__main__":
    main()
