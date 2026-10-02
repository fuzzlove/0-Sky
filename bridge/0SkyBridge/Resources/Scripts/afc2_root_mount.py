#!/usr/bin/env python3
"""Mount an explicitly selected SRD's AFC2 root in Finder via loopback WebDAV."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import re
import signal
import sys
from pathlib import Path


ROOT_MARKERS = frozenset({"System", "private", "var", "Applications", "usr"})
UDID_PATTERN = re.compile(r"^[A-Za-z0-9-]{8,80}$")


def validated_udid(value: str) -> str:
    if not UDID_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError("UDID contains unsupported characters")
    return value


def safe_label(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
    return (cleaned or "iPhone")[:64]


def verify_root_listing(entries: list[str]) -> None:
    missing = sorted(ROOT_MARKERS.difference(entries))
    if missing:
        raise RuntimeError(
            "com.apple.afc2 did not expose the device root; missing markers: "
            + ", ".join(missing)
        )


def parent_is_alive(pid: int) -> bool:
    if pid <= 1:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


async def wait_for_parent_exit(pid: int) -> None:
    while parent_is_alive(pid):
        await asyncio.sleep(1)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--udid", required=True, type=validated_udid)
    result.add_argument("--label", default="iPhone")
    result.add_argument("--parent-pid", type=int, default=0)
    result.add_argument("--read-write", action="store_true")
    result.add_argument("--no-reveal", action="store_true", help=argparse.SUPPRESS)
    return result


async def run(args: argparse.Namespace) -> None:
    # Imports stay inside the operation so --help and source-level tests work
    # even before the pinned 0-Sky host environment is installed.
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.afc import AfcService
    from pymobiledevice3.services.webdav import serve_afc_webdav
    from pymobiledevice3.services.webdav_mount import (
        mount_webdav_volume,
        reveal_in_file_manager,
        unmount_webdav_volume,
    )

    lockdown = await create_using_usbmux(serial=args.udid, autopair=False)
    afc = AfcService(lockdown=lockdown, service_name="com.apple.afc2")
    server = None
    mounted = None
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def request_stop() -> None:
        stop_event.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signum, request_stop)

    try:
        async with afc:
            verify_root_listing(await afc.listdir("/"))
            server = await serve_afc_webdav(
                afc,
                path="/",
                host="127.0.0.1",
                port=0,
                readonly=not args.read_write,
            )
            mounted = await mount_webdav_volume(
                server.url,
                label=f"0-Sky-{safe_label(args.label)}-Root",
            )
            if mounted is None:
                raise RuntimeError("macOS could not mount the local WebDAV volume")
            mode = "read-write" if args.read_write else "read-only"
            print(f"ROOT_MOUNT_READY={mounted.reveal_target}", flush=True)
            print(f"ROOT_MOUNT_MODE={mode}", flush=True)
            if not args.no_reveal:
                await reveal_in_file_manager(mounted.reveal_target)

            waiters = [asyncio.create_task(stop_event.wait()), asyncio.create_task(afc.wait_terminated())]
            if args.parent_pid > 1:
                waiters.append(asyncio.create_task(wait_for_parent_exit(args.parent_pid)))
            done, pending = await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
    finally:
        if mounted is not None:
            await unmount_webdav_volume(mounted)
            with contextlib.suppress(OSError):
                Path(mounted.reveal_target).rmdir()
        if server is not None:
            await server.stop()
        with contextlib.suppress(Exception):
            await lockdown.close()
        print("ROOT_MOUNT_STOPPED=1", flush=True)


def main() -> int:
    args = parser().parse_args()
    args.label = safe_label(args.label)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f"ROOT_MOUNT_ERROR={error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
