#!/usr/bin/env python3
"""Uninstall one exact cryptex identifier from one paired RemoteXPC device."""

import argparse
import asyncio

from device_python import ensure_device_python

ensure_device_python()

from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.services.cryptexd import CryptexdService


async def uninstall(udid: str, identifier: str) -> None:
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid:
            raise RuntimeError(f"Selected {rsd.udid}, expected {udid}")
        service = CryptexdService(rsd)
        await service.uninstall(identifier)
        print(f"Uninstalled {identifier} from {udid}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("identifier")
    options = parser.parse_args()
    asyncio.run(uninstall(options.udid, options.identifier))
