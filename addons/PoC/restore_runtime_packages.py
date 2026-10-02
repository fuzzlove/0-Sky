#!/usr/bin/env python3
"""Install the bundled rootless Python and ElleKit packages on one paired USB SRD."""
import argparse
import asyncio
import hashlib
import json
import pathlib
import shlex
import time
import uuid

from repair_device_connection import atomic_write, profiles, usb_identity, worker_namespace
from restore_srd_bootstrap import DEFAULT_SRDSH_KIT

PACKAGES = (
    "offline-python/libgdbm6_1.23_iphoneos-arm64.deb",
    "offline-python/libpython3.9_3.9.9-1_iphoneos-arm64.deb",
    "offline-python/python3.9_3.9.9-1_iphoneos-arm64.deb",
    "offline-python/python3_3.9.9-1_iphoneos-arm64.deb",
    "packages/ellekit_1.2_iphoneos-arm64.deb",
    "packages/srd-runtime-manager_2.4.10_iphoneos-arm64.deb",
    "packages/preferenceloader_2.4.3-1+debug_iphoneos-arm64.deb",
)
CATVNC_PACKAGE = "packages/CatVNC-0.0.2-ios27-srd-backup.deb"
UPLOAD = """import hashlib,os,sys
destination,digest=sys.argv[1:]
payload=sys.stdin.buffer.read()
if hashlib.sha256(payload).hexdigest()!=digest:raise SystemExit('Package transport digest mismatch')
fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as stream:stream.write(payload)
"""
VERIFY = """import hashlib,pathlib,sys
destination,digest=sys.argv[1:]
if hashlib.sha256(pathlib.Path(destination).read_bytes()).hexdigest()!=digest:
 raise SystemExit('Uploaded package digest mismatch')
"""
CLEANUP = """import pathlib,sys
folder=pathlib.Path(sys.argv[1])
if folder.parent!=pathlib.Path('/var/mobile/tmp') or not folder.name.startswith('0sky-runtime-packages-'):
 raise SystemExit('Unexpected package staging path')
for item in folder.iterdir():
 if not item.is_file() or item.is_symlink() or item.suffix!='.deb':raise SystemExit('Unexpected package staging entry')
 item.unlink()
folder.rmdir()
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance-name", required=True)
    parser.add_argument("--kit", type=pathlib.Path,
                        default=DEFAULT_SRDSH_KIT.parent)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--catvnc-only", action="store_true",
                        help="Install only the bundled CatVNC package and its preference entry")
    args = parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _, profile = profiles(instance_name=args.instance_name)[args.udid]
    if profile["EnvironmentVariables"].get("CRYPSTORE_DEVICE_HOST") != "127.0.0.1":
        parser.error("Selected profile is not bound to the USB SSH tunnel")
    ssh = worker_namespace(profile)["ssh"]
    folder = "/var/mobile/tmp/0sky-runtime-packages-" + uuid.uuid4().hex
    ssh("mkdir -m 700 " + shlex.quote(folder), timeout=15)
    remote_paths = []
    try:
        selected = (CATVNC_PACKAGE,) if args.catvnc_only else PACKAGES
        manifest = (args.kit / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        expected = {name.removeprefix("./"): value for row in manifest
                    if len(parts := row.split()) == 2
                    for value, name in (parts,)}
        for relative in selected:
            source = args.kit / relative
            if not source.is_file() or source.is_symlink():
                raise RuntimeError(f"Missing package: {source}")
            raw = source.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if expected.get(relative) != digest:
                raise RuntimeError(f"Kit manifest mismatch for {relative}")
            remote = folder + "/" + source.name
            command = "/var/jb/usr/bin/python3 -c " + shlex.quote(UPLOAD)
            ssh(command + " " + shlex.quote(remote) + " " + digest,
                input_data=raw, timeout=90)
            check = "/var/jb/usr/bin/python3 -c " + shlex.quote(VERIFY)
            ssh(check + " " + shlex.quote(remote) + " " + digest, timeout=30)
            remote_paths.append(remote)
            print(f"Verified {source.name}: {digest}", flush=True)
        command = "/var/jb/usr/bin/apt-get install -y --no-remove " + " ".join(
            shlex.quote(path) for path in remote_paths)
        result = ssh(command, timeout=900, check=False)
        report = {
            "udid": args.udid,
            "instance_name": args.instance_name,
            "checked_at": int(time.time()),
            "packages": [pathlib.Path(path).name for path in remote_paths],
            "exit_code": result.returncode,
            "stdout": result.stdout.decode("utf-8", "replace")[-20000:],
            "stderr": result.stderr.decode("utf-8", "replace")[-10000:],
        }
        atomic_write(args.output, (json.dumps(report, indent=2) + "\n").encode())
        print(json.dumps(report, indent=2), flush=True)
        if result.returncode:
            raise SystemExit(result.returncode)
    finally:
        command = "/var/jb/usr/bin/python3 -c " + shlex.quote(CLEANUP)
        ssh(command + " " + shlex.quote(folder), timeout=30, check=False)


if __name__ == "__main__":
    main()
