#!/usr/bin/env python3
"""Restore /var/jb to the existing active Preboot Procursus on one paired SRD."""

import argparse
import asyncio
import json
from pathlib import Path
import re
import sys
import uuid

from repair_device_connection import HOST_TOOLS, profiles, usb_identity


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance-name", required=True)
    args = parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _, worker = profiles(instance_name=args.instance_name)[args.udid]
    env = worker["EnvironmentVariables"]
    if env.get("CRYPSTORE_DEVICE_HOST") != "127.0.0.1":
        raise RuntimeError("Preboot link repair requires the exact-device USB tunnel")
    sys.path.insert(0, str(HOST_TOOLS))
    import pair
    base = pair.ssh_base(
        "127.0.0.1", env["CRYPSTORE_DEVICE_PORT"], Path(env["CRYPSTORE_DEVICE_KEY"]),
        known_hosts=Path(env["CRYPSTORE_DEVICE_KNOWN_HOSTS"]),
        host_alias=env["CRYPSTORE_DEVICE_HOST_ALIAS"],
    )
    active = pair.ssh(base, "cat /private/preboot/active", timeout=15).stdout.decode().strip()
    if not re.fullmatch(r"[A-F0-9]{64,128}", active):
        raise RuntimeError("Invalid active Preboot identifier")
    target = f"/private/preboot/{active}/procursus"
    backup = "/var/jb.before-0sky-" + uuid.uuid4().hex
    script = r'''test "$(id -u)" = 0 || exit 72
TARGET='__TARGET__'
test -r "$TARGET/.srd_procursus_bootstrap" || exit 73
test -e "$TARGET/usr/bin/python3" || exit 73
test -x "$TARGET/usr/bin/dpkg" || exit 73
test -x "$TARGET/usr/bin/apt-get" || exit 73
if [ -L /var/jb ]; then
  test "$(readlink /var/jb)" = "$TARGET" || { echo 'different /var/jb link' >&2; exit 74; }
  echo 'link=already-correct'
elif [ -d /var/jb ]; then
  test ! -e '__BACKUP__' || exit 74
  mv /var/jb '__BACKUP__' || exit 75
  ln -s "$TARGET" /var/jb || { mv '__BACKUP__' /var/jb; exit 75; }
  echo 'link=restored'
  echo 'preserved=__BACKUP__'
else
  echo 'unexpected /var/jb type' >&2; exit 76
fi
test -x /var/jb/usr/bin/python3 || exit 77
AUDIT=$(/var/jb/usr/bin/dpkg --audit 2>&1) || exit 77
test -z "$AUDIT" || { echo "$AUDIT" >&2; exit 77; }
/var/jb/usr/bin/apt-get check >/dev/null || exit 77
echo 'procursus=healthy'
'''.replace("__BACKUP__", backup).replace("__TARGET__", target)
    result = pair.ssh(base, script, timeout=180)
    print(json.dumps({"udid": args.udid, "instance": args.instance_name,
                      "result": result.stdout.decode("utf-8", "replace").strip()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
