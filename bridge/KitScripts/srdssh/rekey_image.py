#!/usr/bin/env python3
"""Build a Dropbear SRD research Cryptex for a caller-owned SSH key."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys


def stage(number: int, total: int, title: str, detail: str = "") -> None:
    suffix = f" — {detail}" if detail else ""
    print(f"[0-Sky SRDssh] [{number}/{total}] {title}{suffix}", flush=True)


def run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    print("[0-Sky SRDssh]     + " + Path(command[0]).name, flush=True)
    return subprocess.run(
        command, check=True, text=True, timeout=300,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


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


def unwrap_last_octet_string(data: bytes) -> bytes:
    def read_length(offset: int) -> tuple[int, int]:
        first = data[offset]
        offset += 1
        if first < 128:
            return first, offset
        count = first & 0x7F
        return int.from_bytes(data[offset:offset + count], "big"), offset + count

    if not data or data[0] != 0x30:
        raise RuntimeError("cryptexctl returned a malformed trust cache")
    length, offset = read_length(1)
    end = offset + length
    answer: bytes | None = None
    while offset < end:
        tag = data[offset]
        item_length, value_offset = read_length(offset + 1)
        value = data[value_offset:value_offset + item_length]
        if tag == 0x04:
            answer = value
        offset = value_offset + item_length
    if answer is None:
        raise RuntimeError("cryptexctl trust cache has no octet-string payload")
    return answer


def public_key_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    if "\n" in text or not re.fullmatch(
            r"(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa) [A-Za-z0-9+/=]+(?: [^\r\n]+)?",
            text):
        raise RuntimeError("the selected SSH public key has an unsupported format")
    # SSH ignores the comment; remove caller names and hostnames from images.
    key_type, encoded_key = text.split(maxsplit=2)[:2]
    return f"{key_type} {encoded_key} 0-sky-authorized-key\n"


def build(kit: Path, public_key: Path, output: Path) -> dict[str, str]:
    total = 7
    cryptexctl = Path("/System/Library/SecurityResearch/usr/bin/cryptexctl")
    seal_tool = Path(
        "/System/Library/Filesystems/apfs.fs/Contents/Resources/apfs_prepare_cryptex"
    )
    if not cryptexctl.is_file() or not seal_tool.is_file():
        raise RuntimeError("Apple SRD cryptex and APFS sealing tools are required")
    payload = kit / "payload-root"
    if not (payload / "usr/bin/dropbear").is_file():
        raise RuntimeError("bundled Dropbear payload root is incomplete")
    shell = payload / "usr/bin/sh"
    if not shell.is_symlink() or shell.readlink() != Path("toybox"):
        raise RuntimeError(
            "bundled Dropbear payload is missing the confined usr/bin/sh -> toybox link"
        )

    output = output.expanduser().resolve()
    work = output.with_name(output.name + ".building")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    root = work / "root"
    mounted: Path | None = None
    attached_device: str | None = None
    try:
        stage(1, total, "Preparing the minimal SRDssh payload",
              "Dropbear + Toybox + Procursus boot link")
        shutil.copytree(payload, root, symlinks=True)
        (root / "etc/srdsh_authorized_key").write_text(
            public_key_text(public_key), encoding="utf-8")
        for binary in ("cryptex-run", "dropbear", "dropbearkey", "toybox"):
            run(["codesign", "--verify", "--strict", str(root / "usr/bin" / binary)])

        stage(2, total, "Generating the executable trust cache",
              "only signed arm64e payloads are admitted")
        trust_der = work / "srdsh.trustcache"
        trust_command = [str(cryptexctl), "generate-trust-cache", "-o",
                         str(trust_der), "-t", "loadable"]
        procursus_trust = kit / "procursus.trustcache"
        if procursus_trust.is_file():
            trust_command.extend(["-b", str(procursus_trust)])
        trust_command.append(str(root))
        run(trust_command)
        payload_octets = unwrap_last_octet_string(trust_der.read_bytes())
        trust = work / "srdsh.gtcd"
        trust.write_bytes(der_sequence(
            der_ia5("IM4P"), der_ia5("gtcd"), der_ia5("1"), der_octets(payload_octets)))

        stage(3, total, "Creating the APFS research image", "64 MiB isolated volume")
        rw = work / "srdsh-apfs-rw.dmg"
        run(["hdiutil", "create", "-size", "64m", "-fs", "APFS",
             "-volname", "srdsh", "-layout", "NONE", str(rw)])
        mounted = work / "mnt"
        mounted.mkdir()
        attached = run(["hdiutil", "attach", "-plist", "-nobrowse",
                        "-mountpoint", str(mounted), str(rw)], capture=True)
        plist = plistlib.loads(attached.stdout.encode())
        entities = plist.get("system-entities", [])
        attached_device = next(
            (item.get("dev-entry") for item in entities if item.get("mount-point")), None)
        if not attached_device:
            raise RuntimeError("hdiutil did not return an attached APFS device")
        run(["ditto", str(root), str(mounted)])
        run(["hdiutil", "detach", attached_device])
        attached_device = None
        mounted = None

        stage(4, total, "Sealing the APFS volume", "measuring immutable contents")
        sealed = work / "srdsh-apfs-sealed.dmg"
        shutil.copy2(rw, sealed)
        attach = run(["hdiutil", "attach", "-nomount", str(sealed)], capture=True)
        devices = re.findall(r"(/dev/disk\d+s\d+)", attach.stdout)
        if not devices:
            devices = re.findall(r"(/dev/disk\d+)", attach.stdout)
        if not devices:
            raise RuntimeError("could not locate the APFS sealing device")
        catalyst = devices[-1]
        attached_device = re.sub(r"s\d+$", "", catalyst)
        volume_hash = work / "srdsh-apfs-sealed.hash"
        run([str(seal_tool), "-p", "-M", str(volume_hash), catalyst])
        run(["hdiutil", "detach", attached_device])
        attached_device = None

        stage(5, total, "Compressing the personalized Cryptex image", "UDZO transport")
        final_image = work / "srdsh-apfs-sealed-udzo.dmg"
        run(["hdiutil", "convert", str(sealed), "-format", "UDZO",
             "-o", str(final_image)])

        stage(6, total, "Writing reproducibility metadata", "SHA-256 manifest")
        if output.exists():
            shutil.rmtree(output)
        output.mkdir(parents=True)
        results = {
            "image": final_image,
            "trust_cache": trust,
            "volume_hash": volume_hash,
            "public_key": public_key,
        }
        names = {
            "image": "srdsh-apfs-sealed-udzo.dmg",
            "trust_cache": "srdsh.gtcd",
            "volume_hash": "srdsh-apfs-sealed.hash",
            "public_key": "srdsh-authorized-key.pub",
        }
        metadata: dict[str, str] = {"schema": "1"}
        lines: list[str] = []
        for key, source in results.items():
            target = output / names[key]
            if key == "public_key":
                target.write_text(public_key_text(source), encoding="utf-8")
            else:
                shutil.copy2(source, target)
            value = sha256(target)
            metadata[f"{key}_sha256"] = value
            lines.append(f"{value}  {target.name}\n")
        (output / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
        (output / "BUILD.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        stage(7, total, "Personalized SRDssh image ready",
              f"{final_image.stat().st_size:,} bytes")
        return {key: str(output / names[key]) for key in names}
    finally:
        if attached_device:
            subprocess.run(["hdiutil", "detach", attached_device],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif mounted and mounted.exists():
            subprocess.run(["hdiutil", "detach", str(mounted)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if work.exists():
            shutil.rmtree(work)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.kit.resolve(), args.public_key.expanduser().resolve(), args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
