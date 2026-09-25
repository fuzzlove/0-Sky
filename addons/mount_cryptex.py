#!/usr/bin/env python3
import argparse
import subprocess
import sys
import getpass
import os

def mount_cryptex(dmg_path, mount_point=None, password=None, readonly=False):
    """Mount a DMG Cryptex file using hdiutil.

    Parameters
    ----------
    dmg_path: str
        Path to the DMG file to mount.
    mount_point: str, optional
        Desired mount point. If omitted, macOS chooses automatically.
    password: str
        Password for the encrypted DMG.
    readonly: bool, default False
        If True, mount the image read‑only.
    """
    if not os.path.exists(dmg_path):
        raise FileNotFoundError(f"{dmg_path} not found")

    # Base command: hdiutil attach <image> -nobrowse
    cmd = ["hdiutil", "attach", dmg_path, "-nobrowse"]
    if readonly:
        cmd.append("-readonly")
    if mount_point:
        cmd.extend(["-mountpoint", mount_point])
    # Password from stdin
    cmd.append("-stdinpass")

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    out, err = proc.communicate(password + "\n")
    if proc.returncode != 0:
        raise RuntimeError(f"hdiutil attach failed: {err.strip()}")
    return out.strip()

def main():
    parser = argparse.ArgumentParser(description="Mount a DMG Cryptex file")
    parser.add_argument("dmg", help="Path to the DMG Cryptex file")
    parser.add_argument("-m", "--mountpoint", help="Mount point (optional)", default=None)
    parser.add_argument("-p", "--password", help="Password for DMG (prompt if omitted)", default=None)
    parser.add_argument("-r", "--readonly", help="Mount read‑only", action="store_true")
    args = parser.parse_args()

    dmg_path = os.path.abspath(args.dmg)
    password = args.password
    if password is None:
        password = getpass.getpass(prompt="Enter DMG password: ")

    try:
        output = mount_cryptex(dmg_path, args.mountpoint, password, readonly=args.readonly)
        print(f"Mounted DMG successfully:\n{output}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
