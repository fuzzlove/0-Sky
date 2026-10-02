#!/usr/bin/env python3
"""Reversibly remove one exact-UDID 0-Sky Mac companion.

The default is a dry run. --apply stops only verified per-device LaunchAgents
and moves their plists and non-evidence host state into a private rollback
directory. Apple pairing, the SRD, bootstrap and research evidence are never
modified. An absent instance is already uninstalled and safe to install again.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import time


PREFIX = "com.liquidskysecurity.crypstore-"
ROLES = ("usbmux", "worker", "device-bridge", "bluetooth")
UDID_RE = re.compile(r"^[A-Za-z0-9-]{20,80}$")
INSTANCE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


class RemovalError(RuntimeError):
    pass


@dataclass(frozen=True)
class RemovalPlan:
    instance: str
    udid: str
    support: Path
    agents: Path
    state: tuple[Path, ...]
    services: tuple[Path, ...]


def _safe_path(path: Path, root: Path) -> None:
    if root.is_symlink() or path.is_symlink():
        raise RemovalError(f"unsafe symbolic link: {path.name}")
    if root.resolve() not in path.resolve(strict=False).parents:
        raise RemovalError(f"path escapes its owner directory: {path.name}")


def _plist_device(path: Path, udid: str) -> bool:
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        raise RemovalError(f"invalid LaunchAgent plist: {path.name}") from error
    if value.get("Label") != path.stem:
        raise RemovalError(f"LaunchAgent label mismatch: {path.name}")
    env = value.get("EnvironmentVariables", {})
    if isinstance(env, dict) and env.get("CRYPSTORE_DEVICE_UDID") == udid:
        return True
    argv = value.get("ProgramArguments", [])
    return (isinstance(argv, list) and all(isinstance(arg, str) for arg in argv)
            and any(argv[index:index + 2] == ["-u", udid]
                    for index in range(len(argv) - 1))
            and Path(argv[0]).name == "iproxy")


def plan(instance: str, udid: str, support: Path, agents: Path) -> RemovalPlan:
    if not INSTANCE_RE.fullmatch(instance) or not UDID_RE.fullmatch(udid):
        raise RemovalError("an exact instance name and device UDID are required")
    support = support.expanduser().resolve()
    agents = agents.expanduser().resolve()
    directory = support / "instances" / instance
    _safe_path(directory, support)
    config = directory / "config.json"
    if directory.exists():
        _safe_path(config, support)
        if not config.is_file():
            raise RemovalError("installed instance has no valid config.json")
        try:
            data = json.loads(config.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise RemovalError("installed instance config is unreadable") from error
        if data.get("udid") != udid or data.get("instance", instance) != instance:
            raise RemovalError("installed instance belongs to another device")

    digest = hashlib.sha256(udid.encode()).hexdigest()[:24]
    candidates = (
        directory,
        support / "bridge-profiles" / f"{instance}.json",
        support / "state" / instance,
        support / "trusted-devices" / f"{digest}.json",
        support / "trusted-device-capabilities" / f"{digest}.json",
    )
    for path in candidates:
        _safe_path(path, support)
    service_paths: list[Path] = []
    if agents.exists():
        for path in agents.glob(f"{PREFIX}*.plist"):
            _safe_path(path, agents)
            if not path.is_file():
                raise RemovalError(f"unsafe LaunchAgent: {path.name}")
            is_current = any(path.stem == f"{PREFIX}{role}.{instance}" for role in ROLES)
            if is_current:
                if not _plist_device(path, udid):
                    raise RemovalError(f"instance LaunchAgent belongs to another device: {path.name}")
                service_paths.append(path)
            elif path.stem.startswith(f"{PREFIX}usbmux.") and _plist_device(path, udid):
                # A profile can inherit the exact-UDID USB forward from an
                # older instance. Leave every other device's forward alone.
                service_paths.append(path)
    existing = tuple(path for path in candidates if path.exists())
    if existing and not directory.exists():
        raise RemovalError("orphaned device state requires review before removal")
    return RemovalPlan(instance, udid, support, agents, existing,
                       tuple(sorted(service_paths)))


def _launchctl(argv: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(["/bin/launchctl", *argv], capture_output=True,
                              text=True, timeout=15, check=False)
    except subprocess.TimeoutExpired as error:
        raise RemovalError("launchctl operation timed out; no state was removed") from error


def _stop(label: str) -> bool:
    target = f"gui/{os.getuid()}/{label}"
    if _launchctl(["print", target]).returncode != 0:
        return False
    stopped = _launchctl(["bootout", target])
    if stopped.returncode != 0 and _launchctl(["print", target]).returncode == 0:
        raise RemovalError(f"service is still loaded: {label}")
    return True


def _backup_id(instance: str) -> str:
    return f"{instance}.{time.strftime('%Y%m%d-%H%M%S')}.{time.time_ns()}"


def apply_removal(item: RemovalPlan) -> str:
    if not item.state and not item.services:
        return "ALREADY_REMOVED"
    backups = item.support / "uninstall-backups"
    backups.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(backups, 0o700)
    backup_id = _backup_id(item.instance)
    backup = backups / backup_id
    backup.mkdir(mode=0o700)
    moved: list[tuple[Path, Path]] = []
    stopped: list[Path] = []
    try:
        # Stop first. A failed stop never strands a deleted profile while its
        # privileged worker is still running.
        for service in item.services:
            if _stop(service.stem):
                stopped.append(service)
        metadata = {"schema": 1, "instance": item.instance, "udid": item.udid,
                    "state": [str(path.relative_to(item.support)) for path in item.state],
                    "services": [path.name for path in item.services]}
        encoded = json.dumps(metadata, indent=2, sort_keys=True) + "\n"
        ledger = backup / "manifest.json"
        ledger.write_text(encoded, encoding="utf-8")
        os.chmod(ledger, 0o600)
        for path in item.services:
            destination = backup / "launchagents" / path.name
            destination.parent.mkdir(mode=0o700, exist_ok=True)
            path.replace(destination)
            moved.append((destination, path))
        for path in item.state:
            destination = backup / "state" / path.relative_to(item.support)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.replace(destination)
            moved.append((destination, path))
    except Exception:
        for source, original in reversed(moved):
            original.parent.mkdir(parents=True, exist_ok=True)
            source.replace(original)
        for service in stopped:
            _launchctl(["bootstrap", f"gui/{os.getuid()}", str(service)])
        raise
    return backup_id


def restore(instance: str, udid: str, support: Path, agents: Path, backup_id: str) -> None:
    if not re.fullmatch(r"[a-z0-9-]{1,63}\.[0-9]{8}-[0-9]{6}\.[0-9]+", backup_id):
        raise RemovalError("invalid rollback identifier")
    backup = support / "uninstall-backups" / backup_id
    _safe_path(backup, support)
    try:
        ledger = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RemovalError("rollback manifest is missing or invalid") from error
    if ledger.get("instance") != instance or ledger.get("udid") != udid:
        raise RemovalError("rollback belongs to another instance or device")
    paths: list[tuple[Path, Path]] = []
    for relative in ledger.get("state", []):
        if not isinstance(relative, str) or ".." in Path(relative).parts:
            raise RemovalError("unsafe rollback state path")
        target = support / relative
        _safe_path(target, support)
        paths.append((backup / "state" / relative, target))
    for name in ledger.get("services", []):
        if not isinstance(name, str) or Path(name).name != name:
            raise RemovalError("unsafe rollback service name")
        paths.append((backup / "launchagents" / name, agents / name))
    if any(not source.exists() or target.exists() or source.is_symlink()
           for source, target in paths):
        raise RemovalError("rollback is incomplete or an installation already occupies its paths")
    moved: list[tuple[Path, Path]] = []
    started: list[str] = []
    try:
        for source, target in paths:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source.replace(target)
            moved.append((target, source))
        for name in ledger.get("services", []):
            result = _launchctl(["bootstrap", f"gui/{os.getuid()}", str(agents / name)])
            if result.returncode != 0:
                # bootstrap may have partially loaded a job before failing.
                _stop(Path(name).stem)
                raise RemovalError(f"restored service did not start: {name}")
            started.append(Path(name).stem)
    except Exception:
        for label in reversed(started):
            _stop(label)
        for target, source in reversed(moved):
            source.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.replace(source)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance-name", required=True)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--support", type=Path,
                        default=Path.home() / "Library/Application Support/0-Sky")
    parser.add_argument("--agents", type=Path, default=Path.home() / "Library/LaunchAgents")
    parser.add_argument("--apply", action="store_true", help="perform the planned host-only removal or restore")
    parser.add_argument("--restore-backup", metavar="BACKUP_ID")
    args = parser.parse_args()
    try:
        if args.restore_backup:
            if not args.apply:
                print("RESTORE=DRY_RUN")
                return 0
            restore(args.instance_name, args.udid, args.support, args.agents, args.restore_backup)
            print("RESTORE=PASS")
            return 0
        selected = plan(args.instance_name, args.udid, args.support, args.agents)
        print(f"DEVICE_UDID={selected.udid}")
        print(f"INSTANCE={selected.instance}")
        print(f"STATE_ITEMS={len(selected.state)}")
        print(f"EXACT_DEVICE_SERVICES={len(selected.services)}")
        if not args.apply:
            print("ACTION=DRY_RUN")
            return 0
        outcome = apply_removal(selected)
        print(f"ACTION={outcome}")
        print("DEVICE_MODIFIED=NO")
        print("APPLE_PAIRING_MODIFIED=NO")
        return 0
    except RemovalError as error:
        print(f"UNINSTALL_FAIL={error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
