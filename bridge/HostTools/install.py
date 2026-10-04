#!/usr/bin/env python3
"""Install or resume the exact-device 0-Sky Mac companion from a verified kit.

This host installer supports macOS arm64 and x86_64. iOS/iPadOS 17 or later
is selected by exact UDID and probed for its actual capabilities by pair.py;
no future OS version is assumed to have the same private services. It never
removes Apple pairing or a working device bootstrap.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import time


PREFIX = "com.liquidskysecurity.crypstore"
UDID_RE = re.compile(r"^[A-Za-z0-9-]{20,80}$")
INSTANCE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
STAGED_DIRS = ("automation", "packages", "apps", "runtime-generation",
               "host-mac", "srdssh", "offline-python", "payloads",
               "appregistrard", "filza", "frida")


class InstallError(RuntimeError):
    pass


def run(argv: list[str | Path], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run([str(value) for value in argv], capture_output=True,
                              text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        raise InstallError(f"bounded operation timed out: {Path(str(argv[0])).name}") from error


def require_success(result: subprocess.CompletedProcess[str], stage: str) -> None:
    if result.returncode != 0:
        # Child output may contain identifiers or credentials; do not print it.
        raise InstallError(f"{stage} exited {result.returncode}; inspect the private instance logs")


def private_transcript(directory: Path, stage: str,
                       result: subprocess.CompletedProcess[str]) -> Path:
    """Persist child output owner-only instead of discarding the root cause."""
    if not re.fullmatch(r"[a-z0-9-]{1,40}", stage):
        raise InstallError("invalid private transcript stage")
    logs = directory / "logs"
    if logs.is_symlink() or not logs.is_dir():
        raise InstallError("private instance log directory is missing or unsafe")
    target = logs / f"{stage}-last.log"
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise InstallError("private pairing transcript path is unsafe")
    payload = (f"EXIT_STATUS={result.returncode}\nSTDOUT:\n{result.stdout}"
               f"\nSTDERR:\n{result.stderr}\n").encode("utf-8", "replace")
    temporary = logs / f".{stage}.{os.getpid()}.{time.time_ns()}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        os.chmod(target, 0o600)
        return target
    finally:
        if temporary.exists():
            temporary.unlink()


def pairing_failure_detail(result: subprocess.CompletedProcess[str], udid: str) -> str:
    """Return a bounded, redacted user action while raw output stays private."""
    lines = [line.strip() for line in (result.stderr + "\n" + result.stdout).splitlines()
             if line.strip()]
    failure = next((line for line in reversed(lines)
                    if "[0-Sky Link pairing] FAILED:" in line), "")
    detail = failure.split("FAILED:", 1)[-1].strip() if failure else ""
    detail = detail.replace(udid, "<selected-device>")
    detail = detail.replace(str(Path.home()), "~")
    detail = re.sub(r"SHA256:[A-Za-z0-9+/=]{20,}", "SHA256:<redacted>", detail)
    detail = re.sub(r"(?i)(token|password|secret)=\S+", r"\1=<redacted>", detail)
    if len(detail) > 800:
        detail = detail[:797] + "..."
    combined = " ".join(lines).lower()
    if "multiple_devices" in combined:
        action = "Disconnect other Apple devices, leave only the selected SRD on USB, and press Resume."
    elif "usb_not_connected" in combined:
        action = "Connect the selected SRD directly by USB, unlock it, and press Resume."
    elif "device_locked" in combined:
        action = "Unlock the selected SRD, keep its screen on, and press Resume."
    elif "trust_required" in combined or "trust_denied" in combined:
        action = "Unlock the selected SRD, approve Trust This Computer, then press Resume."
    elif "permission denied" in combined:
        action = "The SRD rejected this Mac's SSH key. Use Repair Pinned Host Key with the exact device connected by USB."
    elif ("usable host key" in combined or "connection refused" in combined
          or "root-bridge-ready" in combined):
        action = "The SRD SSH service is not ready. Complete Prepare SRD/Runtime Manager for this exact device, then press Resume."
    elif "timed out" in combined or "timeout" in combined:
        action = "Keep the selected SRD unlocked on USB and press Resume; if it repeats, export Diagnostics."
    else:
        action = "Keep the exact SRD unlocked on USB, export Diagnostics, and press Resume after correcting the reported condition."
    return f"{detail + '. ' if detail else ''}{action}"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_kit(kit: Path) -> str:
    manifest = kit / "SHA256SUMS"
    if not manifest.is_file() or manifest.is_symlink():
        raise InstallError("verified kit manifest is missing")
    checked = 0
    root = kit.resolve(strict=True)
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        parts = raw.split(None, 1)
        if len(parts) != 2 or not re.fullmatch(r"[a-f0-9]{64}", parts[0]):
            raise InstallError("kit manifest has a malformed entry")
        relative = parts[1].strip().lstrip("*").removeprefix("./")
        item = kit / relative
        link = os.readlink(item) if item.is_symlink() else None
        if (not item.is_file() or root not in item.resolve().parents
                or (link is not None and (Path(link).is_absolute() or ".." in Path(link).parts))
                or sha256(item) != parts[0]):
            raise InstallError(f"kit integrity check failed: {relative}")
        checked += 1
    if checked < 10:
        raise InstallError("kit manifest is incomplete")
    return sha256(manifest)


def host_architecture() -> str:
    arch = platform.machine().lower()
    if arch not in {"arm64", "x86_64"}:
        raise InstallError(f"unsupported Mac architecture: {arch}")
    return arch


def verify_helper_architecture(path: Path, arch: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise InstallError(f"host helper is missing: {path.name}")
    result = run(["/usr/bin/lipo", "-archs", path], timeout=10)
    if result.returncode != 0 or arch not in result.stdout.split():
        raise InstallError(f"host helper lacks {arch} slice: {path.name}")
    require_success(run(["/usr/bin/codesign", "--verify", "--strict", path], 10),
                    f"host helper signature {path.name}")


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def _manifest_files(kit: Path) -> list[str]:
    return [raw.split(None, 1)[1].strip().lstrip("*").removeprefix("./")
            for raw in (kit / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
            if raw.strip()]


def _stage_directory(kit: Path, destination: Path, name: str,
                     entries: list[str]) -> None:
    """Copy one manifest-selected directory without following source links."""
    destination.mkdir(mode=0o700)
    for relative in entries:
        source = kit / relative
        target = destination / Path(relative).relative_to(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        else:
            shutil.copy2(source, target, follow_symlinks=False)


def _write_private_bytes(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def _refresh_staged_directories(kit: Path, directory: Path, config_path: Path,
                                old_config: dict, new_config: dict,
                                manifest_files: list[str]) -> Path:
    """Replace only immutable kit assets, retaining a local atomic rollback.

    Pairing records, generated keys, logs, the managed Python environment and
    every other per-device state file remain in place. Existing kit assets and
    the prior config are moved to an owner-only checkpoint before the new
    assets become visible. Any failure restores the exact previous state.
    """
    old_digest = str(old_config.get("source_manifest_sha256") or "unknown")
    new_digest = str(new_config["source_manifest_sha256"])
    old_label = (old_digest[:12] if re.fullmatch(r"[a-f0-9]{64}", old_digest)
                 else "legacy-" + hashlib.sha256(old_digest.encode()).hexdigest()[:12])
    new_label = (new_digest[:12] if re.fullmatch(r"[a-f0-9]{64}", new_digest)
                 else "invalid-" + hashlib.sha256(new_digest.encode()).hexdigest()[:12])
    staging = directory / f".kit-refresh.{os.getpid()}.{time.time_ns()}.tmp"
    backups = directory / "kit-refresh-backups"
    if backups.exists() and (backups.is_symlink() or not backups.is_dir()):
        raise InstallError("kit refresh backup directory is unsafe")
    backups.mkdir(mode=0o700, exist_ok=True)
    os.chmod(backups, 0o700)
    checkpoint = backups / (
        f"{old_label}-to-{new_label}."
        f"{time.strftime('%Y%m%d-%H%M%S')}.{time.time_ns()}"
    )
    checkpoint.mkdir(mode=0o700)
    staging.mkdir(mode=0o700)
    replaced: list[tuple[Path, Path | None]] = []
    completion = directory / ".install-complete"
    completion_backup = checkpoint / ".install-complete"
    try:
        _write_private_bytes(
            checkpoint / "config.json",
            json.dumps(old_config, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        )
        atomic_json(checkpoint / "refresh.json", {
            "schema": 1,
            "instance": new_config["instance"],
            "udid": new_config["udid"],
            "old_source_manifest_sha256": old_digest,
            "new_source_manifest_sha256": new_digest,
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "preserved_state": ["logs", "venv", "pairing material", "generated keys"],
        })
        for name in STAGED_DIRS:
            entries = [relative for relative in manifest_files
                       if relative.startswith(name + "/")]
            if not entries:
                continue
            target = directory / name
            if target.exists() and (target.is_symlink() or not target.is_dir()):
                raise InstallError(f"existing staged directory is unsafe: {name}")
            _stage_directory(kit, staging / name, name, entries)

        # Move the previous revision out of the way before installing each
        # fully staged replacement. Path.rename/os.replace stays atomic on the
        # per-user Application Support volume.
        for name in STAGED_DIRS:
            incoming = staging / name
            if not incoming.exists():
                continue
            target = directory / name
            previous: Path | None = None
            if target.exists():
                previous = checkpoint / name
                os.replace(target, previous)
            try:
                os.replace(incoming, target)
            except Exception:
                if previous is not None and previous.exists() and not target.exists():
                    os.replace(previous, target)
                raise
            replaced.append((target, previous))
        if completion.exists():
            if completion.is_symlink() or not completion.is_file():
                raise InstallError("existing install completion marker is unsafe")
            os.replace(completion, completion_backup)
        atomic_json(config_path, new_config)
        return checkpoint
    except Exception:
        for target, previous in reversed(replaced):
            if target.exists():
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            if previous is not None and previous.exists():
                os.replace(previous, target)
        if completion_backup.exists() and not completion.exists():
            os.replace(completion_backup, completion)
        _write_private_bytes(
            config_path,
            json.dumps(old_config, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        )
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def stage_instance(kit: Path, directory: Path, config: dict,
                   refresh_staged_assets: bool = False) -> Path | None:
    if directory.is_symlink():
        raise InstallError("instance directory is a symbolic link")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    existing = directory / "config.json"
    old_config: dict | None = None
    revision_changed = False
    if existing.exists():
        if existing.is_symlink() or not existing.is_file():
            raise InstallError("existing profile is unsafe")
        try:
            value = json.loads(existing.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise InstallError("existing profile is unparseable; use host-profile repair") from error
        for key in ("udid", "instance", "ssh_host", "ssh_port",
                    "ssh_remote_port", "ssh_key"):
            if key in value and str(value[key]) != str(config[key]):
                raise InstallError(f"existing profile {key} belongs to another endpoint")
        old_config = value
        revision_changed = value.get("source_manifest_sha256") not in (
            None, config["source_manifest_sha256"])
        if revision_changed and not refresh_staged_assets:
            raise InstallError(
                "instance uses another kit revision; run Setup, Resume, or Repair "
                "from the current 0-Sky Bridge app to create a rollback checkpoint "
                "and refresh only the staged kit assets"
            )
        config = {**value, **config}
    manifest_files = _manifest_files(kit)
    if revision_changed:
        assert old_config is not None
        return _refresh_staged_directories(
            kit, directory, existing, old_config, config, manifest_files
        )
    for name in STAGED_DIRS:
        entries = [relative for relative in manifest_files if relative.startswith(name + "/")]
        target = directory / name
        if not entries:
            continue
        if target.exists():
            if target.is_symlink() or not target.is_dir():
                raise InstallError(f"existing staged directory is unsafe: {name}")
            continue
        temporary = directory / f".{name}.{os.getpid()}.tmp"
        if temporary.exists():
            raise InstallError(f"interrupted staging requires review: {name}")
        _stage_directory(kit, temporary, name, entries)
        os.replace(temporary, target)
    (directory / "logs").mkdir(mode=0o700, exist_ok=True)
    atomic_json(existing, config)
    return None


def select_python() -> Path:
    candidates = [Path(sys.executable), Path("/opt/homebrew/bin/python3.12"),
                  Path("/usr/local/bin/python3.12"),
                  Path("/Library/Frameworks/Python.framework/Versions/3.12/bin/python3")]
    for candidate in candidates:
        if candidate.is_file():
            result = run([candidate, "-c", "import sys; print(sys.version_info[:2] == (3, 12))"], 10)
            if result.returncode == 0 and result.stdout.strip() == "True":
                return candidate
    raise InstallError("Python 3.12 is required on this Mac")


def ensure_runtime(directory: Path, skip_dependencies: bool) -> Path:
    python = directory / "venv/bin/python3"
    if python.is_file():
        check = run([python, "-c", "import pymobiledevice3,Crypto,zstandard"], 15)
        if check.returncode == 0:
            return python
        raise InstallError("existing instance Python runtime is incomplete; repair it separately")
    if skip_dependencies:
        raise InstallError("--skip-dependencies requires a valid instance Python runtime")
    base = select_python()
    require_success(run([base, "-m", "venv", directory / "venv"], 120), "Python runtime creation")
    lock = directory / "host-mac/requirements-lock.txt"
    wheels = directory / "host-mac/wheelhouse"
    if not lock.is_file() or not wheels.is_dir():
        raise InstallError("offline Python dependency set is incomplete")
    require_success(run([python, "-m", "pip", "install", "--no-index", "--find-links", wheels,
                         "--requirement", lock], 600), "offline Python dependencies")
    require_success(run([python, "-c", "import pymobiledevice3,Crypto,zstandard"], 15),
                    "Python runtime validation")
    return python


def device_alias(udid: str) -> str:
    return "0sky-device-" + hashlib.sha256(udid.encode()).hexdigest()[:24]


def bluetooth_port(udid: str) -> int:
    return 36000 + (int(hashlib.sha256(udid.encode()).hexdigest()[:8], 16) % 20000)


def supported_ios_major(version: str) -> int:
    """Gate the documented floor; probe features instead of guessing a ceiling."""
    match = re.fullmatch(r"([0-9]+)(?:\.[0-9]+){0,2}(?:[a-zA-Z0-9.-]*)?", version)
    if not match or int(match.group(1)) < 17:
        raise InstallError("an iOS/iPadOS 17 or later SRD is required")
    return int(match.group(1))


def bluetooth_token(directory: Path, udid: str, host: str, port: int, key: Path) -> Path:
    from pair import ssh, ssh_base
    pin = directory / "device-known-hosts"
    base = ssh_base(host, str(port), key, known_hosts=pin, host_alias=device_alias(udid))
    result = ssh(base, "cat /var/jb/etc/trollstorelite-srd-bridge.token", timeout=20)
    token = result.stdout.decode("ascii", "ignore").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise InstallError("device Bluetooth token is unavailable")
    target = directory / "bluetooth/token"
    target.parent.mkdir(mode=0o700, exist_ok=True)
    if target.exists() and (target.is_symlink() or not target.is_file()):
        raise InstallError("existing Bluetooth token path is unsafe")
    if not target.exists() or target.read_text(encoding="ascii").strip() != token:
        temporary = target.with_name(f".token.{os.getpid()}.{time.time_ns()}")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(token + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    os.chmod(target, 0o600)
    return target


def agent(label: str, program: list[str], environment: dict[str, str], logs: Path) -> bytes:
    return plistlib.dumps({"Label": label, "ProgramArguments": program,
                           "EnvironmentVariables": environment, "RunAtLoad": True,
                           "KeepAlive": True, "ProcessType": "Interactive",
                           "ThrottleInterval": 5,
                           "StandardOutPath": str(logs / f"{label}.stdout.log"),
                           "StandardErrorPath": str(logs / f"{label}.stderr.log")},
                          fmt=plistlib.FMT_XML, sort_keys=False)


def install_agent(label: str, payload: bytes, agents: Path) -> None:
    agents.mkdir(parents=True, exist_ok=True)
    path = agents / f"{label}.plist"
    if path.exists() and (path.is_symlink() or path.read_bytes() != payload):
        raise InstallError(f"existing LaunchAgent differs: {label}")
    if not path.exists():
        temporary = agents / f".{label}.{os.getpid()}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    target = f"gui/{os.getuid()}/{label}"
    status = run(["/bin/launchctl", "print", target], 10)
    if status.returncode == 0 and "state = running" in status.stdout:
        return
    if status.returncode == 0:
        require_success(run(["/bin/launchctl", "kickstart", "-k", target], 15),
                        f"starting {label}")
    else:
        require_success(run(["/bin/launchctl", "bootstrap", f"gui/{os.getuid()}", path], 15),
                        f"loading {label}")


def exact_forward_exists(udid: str, port: int, remote_port: int) -> bool:
    from pair import exact_iproxy_present
    return exact_iproxy_present(udid, str(port), str(remote_port))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--ssh-key", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--remote-port", type=int, default=22)
    parser.add_argument("--instance-name")
    parser.add_argument("--support", type=Path,
                        default=Path.home() / "Library/Application Support/0-Sky")
    parser.add_argument("--stage-only", action="store_true")
    parser.add_argument(
        "--refresh-staged-assets", action="store_true",
        help=("when the exact-device profile belongs to an older verified kit, "
              "checkpoint and replace only immutable staged assets; pairing, keys, "
              "logs, and the managed Python environment are preserved"),
    )
    parser.add_argument("--skip-dependencies", action="store_true")
    parser.add_argument("--no-launchagents", action="store_true")
    parser.add_argument("--verify-pairing-only", action="store_true")
    args = parser.parse_args()
    try:
        if sys.platform != "darwin":
            raise InstallError("the host companion requires macOS")
        arch = host_architecture()
        if (not UDID_RE.fullmatch(args.udid) or not 1024 <= args.port <= 65535
                or not 1 <= args.remote_port <= 65535):
            raise InstallError("an exact device UDID and valid SSH ports are required")
        instance = args.instance_name or args.udid.lower()
        if not INSTANCE_RE.fullmatch(instance):
            raise InstallError("instance name must be a stable lowercase label")
        if args.host != "127.0.0.1":
            raise InstallError("initial enrollment requires the exact-UDID USB loopback route")
        key = args.ssh_key.expanduser().resolve()
        if not key.is_file() or key.is_symlink() or key.stat().st_mode & 0o077:
            raise InstallError("SSH key is missing or has unsafe permissions")
        kit = Path(__file__).resolve().parent.parent
        manifest_digest = verify_kit(kit)
        verify_helper_architecture(kit / "host-mac/zero-sky-bluetooth-tunnel", arch)
        verify_helper_architecture(kit / "automation/CrypStoreAutomation/device_bridge_supervisor", arch)
        support = args.support.expanduser().resolve()
        directory = support / "instances" / instance
        config = {"schema": 2, "instance": instance, "udid": args.udid,
                  "ssh_host": args.host, "ssh_port": str(args.port),
                  "ssh_remote_port": str(args.remote_port),
                  "ssh_key": str(key), "ssh_known_hosts": str(directory / "device-known-hosts"),
                  "ssh_host_alias": device_alias(args.udid),
                  "bluetooth_port": bluetooth_port(args.udid),
                  "source_manifest_sha256": manifest_digest}
        checkpoint = stage_instance(
            kit, directory, config,
            refresh_staged_assets=args.refresh_staged_assets,
        )
        if checkpoint is not None:
            print(
                "KIT_REFRESH=PASS; old staged assets preserved in owner-only "
                f"checkpoint {checkpoint}; pairing, keys, logs, and Python runtime preserved"
            )
        verify_helper_architecture(directory / "host-mac/zero-sky-bluetooth-tunnel", arch)
        verify_helper_architecture(
            directory / "automation/CrypStoreAutomation/device_bridge_supervisor", arch)
        if args.stage_only:
            print("INSTALL_STAGE=READY; services and device unchanged")
            return 0
        python = ensure_runtime(directory, args.skip_dependencies)
        pair = kit / "host-mac/pair.py"
        pair_argv = [python, pair, "--udid", args.udid, "--ssh-key", key,
                     "--host", args.host, "--port", str(args.port),
                     "--remote-port", str(args.remote_port),
                     "--instance-name", instance, "--support", support,
                     "--pymobile-python", python]
        pair_argv.append("--verify-only" if args.verify_pairing_only else "--confirm-host-enrollment")
        pair_argv.append("--skip-wireless")
        print("PAIRING=START; unlock the selected SRD and approve its Trust prompt if shown")
        pairing_result = run(pair_argv, 360)
        pairing_log = private_transcript(directory, "pairing", pairing_result)
        if pairing_result.returncode != 0:
            raise InstallError(
                f"existing Apple and 0-Sky pairing exited {pairing_result.returncode}. "
                f"{pairing_failure_detail(pairing_result, args.udid)} "
                f"Detailed private log: {pairing_log}"
            )
        receipt = directory / "pairing-state.json"
        try:
            paired = json.loads(receipt.read_text(encoding="utf-8"))
            if paired.get("device_udid") != args.udid:
                raise InstallError("pairing receipt belongs to another device")
            ios_major = supported_ios_major(str(paired["product_version"]))
        except (OSError, ValueError, KeyError) as error:
            raise InstallError("paired device OS version could not be verified") from error
        if args.verify_pairing_only:
            print(f"PAIRING=PASS IOS_MAJOR={ios_major}; host services unchanged")
            return 0
        token = bluetooth_token(directory, args.udid, args.host, args.port, key)
        fingerprint = run(["/usr/bin/ssh-keygen", "-lf", key, "-E", "sha256"], 10)
        parts = fingerprint.stdout.split()
        if fingerprint.returncode != 0 or len(parts) < 2 or not parts[1].startswith("SHA256:"):
            raise InstallError("Mac SSH key fingerprint is unavailable")
        env = {"CRYPSTORE_INSTANCE_DIR": str(directory), "CRYPSTORE_DEVICE_HOST": args.host,
               "CRYPSTORE_DEVICE_PORT": str(args.port), "CRYPSTORE_DEVICE_USER": "root",
               "CRYPSTORE_DEVICE_REMOTE_PORT": str(args.remote_port),
               "CRYPSTORE_DEVICE_KEY": str(key), "CRYPSTORE_DEVICE_UDID": args.udid,
               "CRYPSTORE_DEVICE_KNOWN_HOSTS": str(directory / "device-known-hosts"),
               "CRYPSTORE_DEVICE_HOST_ALIAS": device_alias(args.udid),
               "CRYPSTORE_HOST_KEY_FINGERPRINT": parts[1],
               # A recovery SSH Cryptex may intentionally listen on a
               # device-only port.  CoreDevice port 22 can then be a different
               # SSH service with a different authorized-key set, so it is not
               # a valid failover route for this enrolled profile.
               "CRYPSTORE_WIRELESS_SSH": "1" if args.remote_port == 22 else "0",
               "SRD_PYTHON": str(python),
               "CRYPSTORE_BLUETOOTH_PORT": str(bluetooth_port(args.udid)),
               "CRYPSTORE_BLUETOOTH_STATE": str(directory / "bluetooth/state.json")}
        helper = directory / "host-mac/zero-sky-bluetooth-tunnel"
        bridge = directory / "automation/CrypStoreAutomation/device_bridge_supervisor.sh"
        worker = directory / "automation/CrypStoreAutomation/crypstore_worker.py"
        definitions = {
            f"{PREFIX}-worker.{instance}": [str(python), str(worker), "--interval", "2"],
            f"{PREFIX}-bluetooth.{instance}": [str(helper), "--token-file", str(token),
                                               "--listen-port", str(bluetooth_port(args.udid)),
                                               "--state-file", str(directory / "bluetooth/state.json")],
            f"{PREFIX}-device-bridge.{instance}": [str(bridge)],
        }
        if not exact_forward_exists(args.udid, args.port, args.remote_port):
            listener = run(["/usr/sbin/lsof", "-nP", f"-iTCP:{args.port}", "-sTCP:LISTEN"], 10)
            if listener.returncode == 0 and listener.stdout.strip():
                raise InstallError("SSH port is occupied by another listener; choose another port")
            iproxy = shutil.which("iproxy")
            if not iproxy:
                raise InstallError("iproxy is required for USB SSH")
            definitions[f"{PREFIX}-usbmux.{instance}"] = [iproxy, "-s", "127.0.0.1",
                                                            "-u", args.udid,
                                                            f"{args.port}:{args.remote_port}"]
        generated = directory / "launchagents"
        generated.mkdir(mode=0o700, exist_ok=True)
        payloads = {label: agent(label, program, env, directory / "logs")
                    for label, program in definitions.items()}
        for label, payload in payloads.items():
            path = generated / f"{label}.plist"
            path.write_bytes(payload)
            require_success(run(["/usr/bin/plutil", "-lint", path], 10), "LaunchAgent validation")
        if args.no_launchagents:
            print("INSTALL_STAGE=READY; LaunchAgents rendered but unchanged")
            return 0
        agents = Path.home() / "Library/LaunchAgents"
        for label, payload in payloads.items():
            install_agent(label, payload, agents)
        # The worker may need its first two-second poll to publish a heartbeat.
        deadline = time.monotonic() + 30
        while True:
            verification = run([*pair_argv[:-2], "--verify-only", "--require-worker",
                                "--skip-wireless"], 60)
            if verification.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise InstallError("paired worker heartbeat did not verify")
            time.sleep(1)
        (directory / ".install-complete").write_text(manifest_digest + "\n", encoding="ascii")
        device_hash = hashlib.sha256(args.udid.encode()).hexdigest()[:12]
        print(f"INSTALL=PASS DEVICE_HASH={device_hash} INSTANCE={instance} HOST_ARCH={arch} IOS_MAJOR={ios_major}")
        return 0
    except (InstallError, OSError, ValueError, RuntimeError) as error:
        print(f"INSTALL=FAIL REASON={error if isinstance(error, InstallError) else type(error).__name__}",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
