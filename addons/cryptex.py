#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
import tempfile
import shutil

def create_cryptex_dmg(input_path, output_path, password, volume_name=None):
    """Create an encrypted DMG (cryptex) containing the input file or directory.

    Parameters
    ----------
    input_path: str
        Path to the .app, .deb, .ipa file or a directory to package.
    output_path: str
        Destination path for the resulting DMG file.
    password: str
        Encryption password; will be supplied to ``hdiutil`` via stdin.
    volume_name: str, optional
        Name of the volume that appears when the DMG is mounted. If omitted,
        defaults to the base name of the input path.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"{input_path} not found")
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if not volume_name:
        volume_name = os.path.splitext(os.path.basename(input_path))[0]

    # Use a temporary directory as the source for the DMG
    with tempfile.TemporaryDirectory() as tmpdir:
        # If the input is a directory, copy its contents recursively.
        if os.path.isdir(input_path):
            dest_dir = os.path.join(tmpdir, os.path.basename(input_path))
            shutil.copytree(input_path, dest_dir)
        else:
            # For a file, just copy it into the temporary folder.
            shutil.copy2(input_path, tmpdir)

        # Build the hdiutil command for creating an encrypted, compressed DMG.
        cmd = [
            "hdiutil", "create",
            "-srcfolder", tmpdir,
            "-volname", volume_name,
            "-fs", "APFS",
            "-format", "UDBZ",          # Compressed (bzip2) DMG
            "-encryption", "AES-256",
            "-stdinpass",
            output_path
        ]
        # Run the command, feeding the password via stdin.
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = proc.communicate(password + "\n")
        if proc.returncode != 0:
            raise RuntimeError(f"hdiutil failed: {err.strip()}")
        return out.strip()

def main():
    parser = argparse.ArgumentParser(
        description="Convert .app, .deb, or .ipa into an encrypted Cryptex DMG"
    )
    parser.add_argument("input", help="Path to .app, .deb, .ipa file or directory")
    parser.add_argument("-o", "--output", help="Output DMG path (default: <input>.dmg)", default=None)
    parser.add_argument("-p", "--password", help="Password for DMG encryption (prompt if omitted)", default=None)
    parser.add_argument("-n", "--name", help="Volume name inside DMG", default=None)
    args = parser.parse_args()

    input_path = os.path.abspath(args.input)
    output_path = args.output or f"{input_path}.dmg"
    output_path = os.path.abspath(output_path)

    password = args.password
    if password is None:
        import getpass
        password = getpass.getpass(prompt="Enter encryption password: ")

    try:
        create_cryptex_dmg(input_path, output_path, password, volume_name=args.name)
        print(f"Created encrypted DMG at: {output_path}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
