#!/usr/bin/env python3
"""Locate an installed app in the paired device's Home Screen layout."""

import argparse
import asyncio
import json

from device_python import ensure_device_python

ensure_device_python()

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.springboard import SpringBoardServicesService


async def check(udid, bundle_id):
    async with await create_using_usbmux(serial=udid) as lockdown:
        async with SpringBoardServicesService(lockdown) as service:
            state = await service.get_icon_state()
    found = []
    def visit(value, path):
        if isinstance(value, dict):
            if value.get('bundleIdentifier') == bundle_id:
                found.append({'position': path, 'bundle_id': bundle_id,
                              'display_name': value.get('displayName')})
            for key, child in value.items():
                if isinstance(child, (list, dict)):
                    visit(child, path + [key])
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + [index])
    visit(state, [])
    print(json.dumps(found, indent=2))
    if not found:
        raise SystemExit('App icon is absent from the current Home Screen layout')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--bundle-id', required=True)
    args = parser.parse_args()
    asyncio.run(check(args.udid, args.bundle_id))


if __name__ == '__main__':
    main()
