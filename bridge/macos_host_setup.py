#!/usr/bin/env python3
"""Check or install the macOS side of the authorized-SRD workflow.

The macOS companion consists of three per-device LaunchAgents:

* a USB-only ``iproxy`` forward bound to the exact device UDID;
* the 0-Sky Control request worker; and
* the authenticated device-bridge supervisor.

By default this program is read-only. Use ``--fix-missing`` for host
dependencies without a connected device, or ``--setup`` to also install/repair
the per-device companion. Homebrew itself is installed only with the explicit
``--install-homebrew`` opt-in. Nothing here installs to an iPhone or iPad or
bypasses Apple's SRD, pairing, Cryptex, nonce, or TSS checks.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import plistlib
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

from zero_sky_user_config import (
    UserConfigError,
    config_path as user_config_path,
    defaults as user_config_defaults,
    load as load_user_config,
    public as public_user_config,
    write as write_user_config,
)


ROOT = Path(__file__).resolve().parent
DEFAULT_KIT = next((candidate for candidate in (
    ROOT / "exploitdev/srdsh-work/components/zero-sky/kit",
    ROOT / "0SkyBridge/Resources/Scripts/kit",
    ROOT / "kit",
) if (candidate / "SHA256SUMS").is_file()), ROOT / "kit")
KIT = Path(os.environ.get("ZERO_SKY_KIT", DEFAULT_KIT)).expanduser().resolve()
ZERO_SKY = KIT.parent
INSTALLER = KIT / "host-mac/install.py"
PAIRING_COORDINATOR = KIT / "host-mac/apple_device_pairing.py"
REQUIREMENTS = KIT / "host-mac/requirements.txt"
REQUIREMENTS_LOCK = KIT / "host-mac/requirements-lock.txt"
FRIDA_REQUIREMENTS_LOCK = KIT / "host-mac/frida-requirements-lock.txt"
FRIDA_WHEELHOUSE_HASHES = KIT / "host-mac/frida-wheelhouse.sha256"
WHEELHOUSE = KIT / "host-mac/wheelhouse"
FRIDA_VERSION = "17.18.0"
FRIDA_TOOLS_VERSION = "14.10.4"
FRIDA_COMMANDS = (
    "frida", "frida-apk", "frida-compile", "frida-create", "frida-discover",
    "frida-join", "frida-kill", "frida-ls", "frida-ls-devices", "frida-pm",
    "frida-ps", "frida-pull", "frida-push", "frida-rm", "frida-trace",
)
INITIAL_CONFIG = user_config_defaults(ROOT)
DEFAULT_SUPPORT = Path(INITIAL_CONFIG["paths"]["support"])
DEFAULT_IDENTITY = Path(INITIAL_CONFIG["paths"]["ssh_identity"])
LABEL_PREFIX = "com.liquidskysecurity.crypstore"
UDID_RE = re.compile(r"^[A-Za-z0-9-]{20,80}$")
MIN_FREE_GIB = 4.0

BREW_FORMULAS = {
    # Keep the versioned interpreter explicit.  Apple's /usr/bin/python3 is
    # only a bootstrap convenience and is not the runtime used by 0-Sky.
    "python3.12": "python@3.12",
    "dpkg": "dpkg",
    "iproxy": "libusbmuxd",
    "zstd": "zstd",
    "dpkg-deb": "dpkg",
    "ldid": "ldid",
    "autoreconf": "autoconf",
    "automake": "automake",
    "pkg-config": "pkgconf",
}

COMMANDS = (
    "python3", "python3.12", "shasum", "ssh", "ssh-keygen", "iproxy", "nc", "lsof",
    "tar", "zstd", "make", "xcrun", "clang", "codesign", "lipo",
    "hdiutil", "plutil", "launchctl", "ditto", "dpkg", "dpkg-deb", "ldid",
    "autoreconf", "automake", "pkg-config",
)

APPLE_TOOLS = (
    Path("/System/Library/SecurityResearch/usr/bin/cryptexctl"),
    Path(
        "/System/Library/Filesystems/apfs.fs/Contents/Resources/"
        "apfs_prepare_cryptex"
    ),
)


@dataclass
class Check:
    status: str
    name: str
    detail: str
    fix: str = ""


def log(message: str) -> None:
    print(f"[SRDssh macOS] {message}", flush=True)


def run(argv: list[str | Path], *, check: bool = True,
        capture: bool = False, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    command = [str(item) for item in argv]
    # The argv can contain an exact device ID, a home path or an SSH identity.
    # Report the stage without copying those values into normal setup logs.
    log("running " + Path(command[0]).name)
    return subprocess.run(
        command, check=check, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env, timeout=3600,
    )


def wanted_packages() -> dict[str, str]:
    wanted: dict[str, str] = {}
    for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "==" in line:
            name, version = line.split("==", 1)
            wanted[name.lower()] = version
    return wanted


def python_probe(python: Path) -> tuple[bool, dict[str, str | None]]:
    if not python.is_file():
        return False, {}
    probe = r'''import importlib.metadata,json,sys
wanted=json.loads(sys.argv[1]); found={}
for name in wanted:
 try: found[name]=importlib.metadata.version(name)
 except importlib.metadata.PackageNotFoundError: found[name]=None
try:
 import pymobiledevice3,zstandard,Crypto,pydantic_core._pydantic_core
 imports=True
except Exception: imports=False
print(json.dumps(found,sort_keys=True));raise SystemExit(0 if imports else 2)'''
    result = subprocess.run(
        [str(python), "-c", probe, json.dumps(wanted_packages())],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    try:
        found = json.loads(result.stdout)
    except Exception:
        found = {}
    return result.returncode == 0 and found == wanted_packages(), found


def verify_sha256_manifest(manifest: Path, root: Path) -> tuple[bool, str]:
    """Verify a small, path-confined artifact manifest without invoking a shell."""
    if manifest.is_symlink() or not manifest.is_file():
        return False, f"missing: {manifest}"
    checked = 0
    try:
        root = root.resolve(strict=True)
        for number, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
            if not raw:
                continue
            digest, relative = raw.split("  ", 1)
            path = root / relative
            resolved = path.resolve(strict=True)
            if (not re.fullmatch(r"[0-9a-f]{64}", digest)
                    or root not in resolved.parents or path.is_symlink()
                    or not path.is_file()):
                return False, f"unsafe entry on line {number}"
            observed = hashlib.sha256(path.read_bytes()).hexdigest()
            if observed != digest:
                return False, f"digest mismatch: {relative}"
            checked += 1
    except (OSError, ValueError) as error:
        return False, str(error)
    return (checked > 0, f"{checked} pinned files")


def frida_probe(support: Path) -> tuple[bool, str]:
    root = support / "tools/frida-current"
    python = root / "bin/python"
    cli = root / "bin/frida"
    process_list = root / "bin/frida-ps"
    if not all(path.is_file() and os.access(path, os.X_OK)
               for path in (python, cli, process_list)):
        return False, f"managed executables unavailable below {root}"
    probe = subprocess.run(
        [str(python), "-c",
         "import frida,importlib.metadata as m;"
         "print(frida.__version__);print(m.version('frida-tools'))"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=15, check=False,
    )
    versions = probe.stdout.splitlines()
    cli_version = subprocess.run(
        [str(cli), "--version"], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=15, check=False,
    )
    okay = (probe.returncode == 0 and cli_version.returncode == 0
            and versions == [FRIDA_VERSION, FRIDA_TOOLS_VERSION]
            and cli_version.stdout.strip() == FRIDA_VERSION)
    return okay, (f"frida={versions[0] if versions else 'unknown'}, "
                  f"frida-tools={versions[1] if len(versions) > 1 else 'unknown'}, "
                  f"path={root}")


def expose_frida_cli(support: Path, directories: tuple[Path, ...] | None = None) -> int:
    """Expose managed commands in an existing writable Homebrew bin safely."""
    directories = directories or (Path("/opt/homebrew/bin"), Path("/usr/local/bin"))
    destination_root = next((path for path in directories
                             if path.is_dir() and os.access(path, os.W_OK)), None)
    if destination_root is None:
        log("Managed Frida is ready; no writable command directory was available")
        return 0
    managed_root = (support / "tools").resolve()
    current_bin = support / "tools/frida-current/bin"
    created = 0
    for name in FRIDA_COMMANDS:
        source = current_bin / name
        if not source.is_file():
            continue
        destination = destination_root / name
        if destination.is_symlink():
            try:
                owned = managed_root in destination.resolve(strict=False).parents
            except OSError:
                owned = False
            if not owned:
                log(f"Preserving non-0-Sky command link: {destination}")
                continue
            destination.unlink()
        elif destination.exists():
            log(f"Preserving existing command: {destination}")
            continue
        destination.symlink_to(source)
        created += 1
    return created


def python_candidates(requested: Path | None, support: Path) -> list[Path]:
    values: list[Path] = []
    if requested:
        values.append(requested.expanduser())
    if os.environ.get("SRD_PYTHON"):
        values.append(Path(os.environ["SRD_PYTHON"]).expanduser())
    values.extend([
        support / "venv/bin/python3",
        Path("/opt/homebrew/bin/python3.13"),
        Path("/opt/homebrew/bin/python3"),
        Path("/usr/local/bin/python3"),
        Path(sys.executable),
    ])
    # Existing per-device environments remain a compatibility fallback, never
    # the account-wide setup target.
    values.extend(sorted((support / "instances").glob("*/venv/bin/python3")))
    answer: list[Path] = []
    seen: set[str] = set()
    for value in values:
        key = str(value)
        if key not in seen:
            seen.add(key)
            answer.append(value)
    return answer


def select_python(requested: Path | None, support: Path) -> Path | None:
    for candidate in python_candidates(requested, support):
        okay, _ = python_probe(candidate)
        if okay:
            # Keep the venv path rather than resolving the macOS framework
            # symlink and accidentally dropping the pinned environment.
            return candidate.absolute()
    return None


def bootstrap_python() -> Path | None:
    candidates = [
        Path("/Library/Frameworks/Python.framework/Versions/3.12/bin/python3"),
        Path("/opt/homebrew/bin/python3.12"),
        Path("/usr/local/bin/python3.12"),
    ]
    located = shutil.which("python3.12")
    if located:
        candidates.append(Path(located))
    candidates.append(Path(sys.executable))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        result = subprocess.run(
            [str(candidate), "-c", "import sys;raise SystemExit(sys.version_info[:2]!=(3,12))"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return candidate.resolve()
    return None


def xcode_environment(sdk: str) -> tuple[dict[str, str] | None, str]:
    candidates: list[Path | None] = []
    if os.environ.get("DEVELOPER_DIR"):
        candidates.append(Path(os.environ["DEVELOPER_DIR"]))
    candidates.append(None)
    candidates.extend(sorted(Path("/Applications").glob("Xcode*.app/Contents/Developer")))
    for developer in candidates:
        env = dict(os.environ)
        if developer is not None:
            env["DEVELOPER_DIR"] = str(developer)
        result = subprocess.run(
            ["/usr/bin/xcrun", "--sdk", sdk, "--show-sdk-path"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
        )
        if result.returncode == 0 and Path(result.stdout.strip()).is_dir():
            return env, result.stdout.strip()
    return None, ""


def installed_bindings() -> dict[str, str]:
    answer: dict[str, str] = {}
    for path in (Path.home() / "Library/LaunchAgents").glob(
        f"{LABEL_PREFIX}-worker.*.plist"
    ):
        try:
            value = plistlib.loads(path.read_bytes())
            udid = str(value.get("EnvironmentVariables", {}).get("CRYPSTORE_DEVICE_UDID", ""))
            label = str(value.get("Label", ""))
            if UDID_RE.fullmatch(udid) and label.startswith(f"{LABEL_PREFIX}-worker."):
                answer[udid] = label.split("-worker.", 1)[1]
        except Exception:
            continue
    return answer


def visible_usb_device_records(python: Path | None) -> list[dict[str, str]]:
    if python is not None and PAIRING_COORDINATOR.is_file():
        # Run the same replaceable backend used by MacPairingCoordinator.  The
        # selected venv owns pymobiledevice3, while this setup process may be
        # running from the minimal Python shipped with macOS.  JSON is a
        # private structured process boundary, not parsed human CLI output.
        program = r'''import asyncio,dataclasses,importlib.util,json,sys
async def main():
 spec=importlib.util.spec_from_file_location("zero_sky_pairing_backend",sys.argv[1])
 module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module
 spec.loader.exec_module(module)
 devices=await asyncio.wait_for(module.PymobiledeviceBackend().list_devices(),10)
 answer=[{"udid":d.udid,"deviceName":d.name,"productType":d.product_type,
          "productVersion":d.product_version,"buildVersion":d.build_version,
          "connectionType":d.connection_type} for d in devices]
 print(json.dumps(answer))
asyncio.run(main())'''
        try:
            result = subprocess.run(
                [str(python), "-c", program, str(PAIRING_COORDINATOR)], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15,
            )
            devices = json.loads(result.stdout)
            if result.returncode == 0 and isinstance(devices, list):
                return [item for item in devices if isinstance(item, dict) and
                        UDID_RE.fullmatch(str(item.get("udid", "")))]
        except (OSError, subprocess.TimeoutExpired, ValueError, TypeError,
                json.JSONDecodeError):
            pass
    idevice_id = shutil.which("idevice_id")
    if idevice_id:
        try:
            result = subprocess.run(
                [idevice_id, "-l"], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        return [{"udid": line.strip(), "deviceName": "Apple Device",
                 "productType": "Unknown", "productVersion": "Unknown",
                 "buildVersion": "Unknown", "connectionType": "USB"}
                for line in result.stdout.splitlines() if UDID_RE.fullmatch(line.strip())]
    return []


def visible_usb_devices(python: Path | None) -> list[str]:
    return [item["udid"] for item in visible_usb_device_records(python)]


def agent_checks(instance: str, support: Path, udid: str, port: int,
                 identity: Path) -> list[Check]:
    checks: list[Check] = []
    agents = Path.home() / "Library/LaunchAgents"
    domain = f"gui/{os.getuid()}"
    for role in ("usbmux", "worker", "device-bridge"):
        label = f"{LABEL_PREFIX}-{role}.{instance}"
        plist = agents / f"{label}.plist"
        if not plist.is_file():
            checks.append(Check(
                "FAIL", f"LaunchAgent {role}", f"missing: {plist}",
                "rerun this script with --setup",
            ))
            continue
        try:
            value = plistlib.loads(plist.read_bytes())
            environment = value.get("EnvironmentVariables", {})
            arguments = [str(item) for item in value.get("ProgramArguments", [])]
            valid = (
                value.get("Label") == label
                and value.get("RunAtLoad") is True
                and environment.get("CRYPSTORE_DEVICE_UDID") == udid
                and environment.get("CRYPSTORE_DEVICE_PORT") == str(port)
                and environment.get("CRYPSTORE_DEVICE_KEY") == str(identity)
            )
            if role == "usbmux":
                valid = valid and "-u" in arguments and udid in arguments and f"{port}:22" in arguments
            elif role == "worker":
                valid = valid and any(item.endswith("/crypstore_worker.py") for item in arguments)
            else:
                valid = valid and any(item.endswith("/device_bridge_supervisor.sh") for item in arguments)
        except Exception:
            valid = False
        loaded = subprocess.run(
            ["/bin/launchctl", "print", f"{domain}/{label}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
        status = "PASS" if valid and loaded else "FAIL"
        detail = f"definition={'valid' if valid else 'invalid'}, service={'loaded' if loaded else 'not loaded'}"
        checks.append(Check(status, f"LaunchAgent {role}", detail,
                            "rerun this script with --setup" if status == "FAIL" else ""))
    instance_root = support / "instances" / instance
    checks.append(Check(
        "PASS" if (instance_root / "config.json").is_file() else "FAIL",
        "companion configuration", str(instance_root / "config.json"),
        "rerun this script with --setup",
    ))
    checks.append(Check(
        "PASS" if (instance_root / "automation/CrypStoreAutomation/device_bridge_supervisor.sh").is_file() else "FAIL",
        "device bridge helper", str(instance_root / "automation/CrypStoreAutomation/device_bridge_supervisor.sh"),
        "rerun this script with --setup",
    ))
    checks.append(Check(
        "PASS" if (instance_root / "automation/CrypStoreAutomation/crypstore_worker.py").is_file() else "FAIL",
        "0-Sky Control worker helper", str(instance_root / "automation/CrypStoreAutomation/crypstore_worker.py"),
        "rerun this script with --setup",
    ))
    python = instance_root / "venv/bin/python3"
    pair = instance_root / "host-mac/pair.py"
    python_ok, packages = python_probe(python)
    checks.append(Check(
        "PASS" if python_ok else "FAIL", "instance Python environment",
        f"{python}: {packages}", "rerun this script with --setup",
    ))
    if python_ok and pair.is_file():
        proof = subprocess.run([
            str(python), str(pair), "--udid", udid, "--ssh-key", str(identity),
            "--host", "127.0.0.1", "--port", str(port),
            "--instance-name", instance, "--support", str(support),
            "--pymobile-python", str(python), "--verify-only", "--require-worker",
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        checks.append(Check(
            "PASS" if proof.returncode == 0 else "FAIL",
            "paired bridge and worker proof",
            "exact-UDID HMAC marker and fresh worker heartbeat verified"
            if proof.returncode == 0 else proof.stdout.strip()[-1200:],
            "unlock/connect the SRD, then rerun this script with --setup",
        ))
    else:
        checks.append(Check(
            "FAIL", "paired bridge and worker proof", "pairing helper or exact instance Python is missing",
            "rerun this script with --setup",
        ))
    return checks


def host_checks(sdk: str, requested_python: Path | None, support: Path,
                identity: Path, instance: str | None, udid: str | None,
                port: int) -> tuple[list[Check], Path | None]:
    checks: list[Check] = []
    checks.append(Check(
        "PASS" if sys.platform == "darwin" else "FAIL",
        "operating system", f"macOS {platform.mac_ver()[0]} ({platform.machine()})",
        "run SRDssh from macOS",
    ))
    for name in COMMANDS:
        path = find_command(name)
        formula = BREW_FORMULAS.get(name)
        fix = f"brew install {formula}" if formula else "install Xcode or the macOS command-line tools"
        checks.append(Check("PASS" if path else "FAIL", f"command {name}", path or "not found", fix))
    for path in APPLE_TOOLS:
        checks.append(Check(
            "PASS" if path.is_file() else "FAIL", path.name, str(path),
            "install/enable Apple's Security Research Device host tools",
        ))
    xcode_env, sdk_path = xcode_environment(sdk)
    detail = sdk_path
    if xcode_env and xcode_env.get("DEVELOPER_DIR"):
        detail += f" (DEVELOPER_DIR={xcode_env['DEVELOPER_DIR']})"
    checks.append(Check(
        "PASS" if xcode_env else "FAIL", f"Xcode SDK {sdk}", detail or "not found",
        "install full Xcode containing the requested iPhoneOS SDK",
    ))
    free = shutil.disk_usage(ROOT).free
    free_gib = free / (1024 ** 3)
    checks.append(Check(
        "PASS" if free_gib >= MIN_FREE_GIB else "FAIL",
        "workspace free space", f"{free_gib:.1f} GiB available; {MIN_FREE_GIB:.1f} GiB required",
        "free disk space before building or installing Cryptex components",
    ))
    selected = select_python(requested_python, support)
    if selected:
        _, packages = python_probe(selected)
        checks.append(Check("PASS", "pinned Python environment", f"{selected}: {packages}"))
    else:
        checks.append(Check(
            "FAIL", "pinned Python environment", str(wanted_packages()),
            "rerun this script with --setup-python (or --setup)",
        ))
    base_python = bootstrap_python()
    checks.append(Check(
        "PASS" if base_python else "FAIL", "offline Python runtime",
        str(base_python) if base_python else "Python 3.12 not found",
        "brew install python@3.12",
    ))
    wheel_count = len(list(WHEELHOUSE.glob("*.whl"))) if WHEELHOUSE.is_dir() else 0
    checks.append(Check(
        "PASS" if REQUIREMENTS_LOCK.is_file() and wheel_count >= 100 else "FAIL",
        "bundled offline dependencies", f"{wheel_count} wheels",
        "restore the proprietary release bundle",
    ))
    frida_integrity, frida_integrity_detail = verify_sha256_manifest(
        FRIDA_WHEELHOUSE_HASHES, FRIDA_WHEELHOUSE_HASHES.parent)
    checks.append(Check(
        "PASS" if frida_integrity else "FAIL",
        "bundled Frida dependencies", frida_integrity_detail,
        "restore the signed 0-Sky release bundle",
    ))
    frida_ok, frida_detail = frida_probe(support)
    checks.append(Check(
        "PASS" if frida_ok else "FAIL", "managed Frida host", frida_detail,
        "rerun this script with --setup-python or --fix-missing",
    ))
    if identity.is_file():
        mode_ok = identity.stat().st_mode & 0o077 == 0
        checks.append(Check(
            "PASS" if mode_ok else "FAIL", "SRD SSH identity",
            f"{identity} ({oct(identity.stat().st_mode & 0o777)})",
            f"chmod 600 {shlex.quote(str(identity))}",
        ))
    else:
        checks.append(Check(
            "FAIL", "SRD SSH identity", f"missing: {identity}",
            "rerun this script with --setup-python or create an ed25519 key",
        ))
    if instance and udid:
        checks.extend(agent_checks(instance, support, udid, port, identity))
    return checks, selected


def find_command(name: str) -> str | None:
    """Find a command even before a fresh Homebrew install updates PATH."""
    candidates = [
        shutil.which(name),
        f"/opt/homebrew/bin/{name}",
        f"/usr/local/bin/{name}",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def locate_brew() -> Path | None:
    candidate = find_command("brew")
    return Path(candidate) if candidate else None


def install_homebrew() -> Path:
    """Run Homebrew's official interactive installer after explicit opt-in."""
    existing = locate_brew()
    if existing:
        return existing
    curl = Path("/usr/bin/curl")
    bash = Path("/bin/bash")
    if not curl.is_file() or not bash.is_file():
        raise SystemExit("macOS curl and bash are required to install Homebrew")
    with tempfile.TemporaryDirectory(prefix="0sky-homebrew-") as directory:
        installer = Path(directory) / "install.sh"
        log("Downloading the official interactive Homebrew installer over HTTPS")
        run([
            curl, "--fail", "--location", "--show-error", "--silent",
            "--proto", "=https", "--tlsv1.2",
            "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh",
            "--output", installer,
        ])
        installer.chmod(0o700)
        run([bash, installer])
    brew = locate_brew()
    if brew is None:
        raise SystemExit(
            "Homebrew installation did not expose brew in /opt/homebrew or /usr/local"
        )
    return brew


def request_command_line_tools() -> None:
    if find_command("xcrun") and find_command("clang"):
        return
    log("Requesting Apple's Command Line Tools installer")
    result = subprocess.run(
        ["/usr/bin/xcode-select", "--install"], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    detail = result.stdout.strip()
    if detail:
        log(detail)
    raise SystemExit(
        "Finish the Apple Command Line Tools installation, then run the dependency installer again"
    )


def install_tools(*, allow_homebrew_install: bool = False) -> None:
    if sys.platform != "darwin":
        raise SystemExit("Homebrew setup is only supported on macOS")
    missing = {formula for command, formula in BREW_FORMULAS.items() if not find_command(command)}
    if bootstrap_python() is None:
        missing.add("python@3.12")
    if not missing:
        log("Homebrew command dependencies are already present")
        return
    brew = locate_brew()
    if not brew:
        if allow_homebrew_install:
            brew = install_homebrew()
        else:
            raise SystemExit(
                "Homebrew is missing. Double-click 'Install 0-Sky Dependencies.command' "
                "or rerun with --fix-missing --install-homebrew."
            )
    brew_bin = str(brew.parent)
    path_parts = os.environ.get("PATH", "").split(os.pathsep)
    if brew_bin not in path_parts:
        os.environ["PATH"] = os.pathsep.join([brew_bin, *path_parts])
    run([brew, "install", *sorted(missing)])


def setup_frida_host(base_python: Path, support: Path) -> Path:
    """Install the pinned Frida host CLI in an isolated offline environment."""
    integrity_ok, integrity_detail = verify_sha256_manifest(
        FRIDA_WHEELHOUSE_HASHES, FRIDA_WHEELHOUSE_HASHES.parent)
    if not integrity_ok:
        raise SystemExit(f"the bundled Frida dependency set is invalid: {integrity_detail}")
    tools = support / "tools"
    tools.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = tools / f"frida-{FRIDA_VERSION}"
    current = tools / "frida-current"
    existing_ok, _ = frida_probe(support)
    if existing_ok and current.resolve() == target.resolve():
        expose_frida_cli(support)
        log(f"Managed Frida {FRIDA_VERSION} is already ready")
        return target / "bin/frida"

    # This directory is exclusively owned by 0-Sky and contains no device
    # credentials. Build at the final path because venv console-script shebangs
    # embed it; renaming a staged environment would leave broken executables.
    if target.exists():
        if target.is_symlink() or not target.is_dir():
            raise SystemExit(f"refusing unsafe Frida environment path: {target}")
        shutil.rmtree(target)
    run([base_python, "-m", "venv", target])
    python = target / "bin/python"
    try:
        run([
            python, "-m", "pip", "install", "--no-index",
            "--find-links", WHEELHOUSE, "--requirement",
            FRIDA_REQUIREMENTS_LOCK,
        ])
        temporary = tools / f".frida-current.{os.getpid()}"
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(target.name, target_is_directory=True)
        temporary.replace(current)
        okay, detail = frida_probe(support)
        if not okay:
            raise RuntimeError(f"managed Frida validation failed: {detail}")
        expose_frida_cli(support)
    except Exception:
        if current.is_symlink() and current.resolve() == target.resolve():
            current.unlink(missing_ok=True)
        shutil.rmtree(target, ignore_errors=True)
        raise
    target.chmod(0o700)
    return target / "bin/frida"


def setup_python(identity: Path, support: Path) -> Path:
    base_python = bootstrap_python()
    if base_python is None:
        raise SystemExit("Python 3.12 is required (Homebrew: brew install python@3.12)")
    if not REQUIREMENTS_LOCK.is_file() or len(list(WHEELHOUSE.glob("*.whl"))) < 100:
        raise SystemExit("the bundled offline Python dependency set is incomplete")
    venv = support / "venv"
    venv.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    python = venv / "bin/python3"
    if not python_probe(python)[0]:
        if venv.exists():
            raise SystemExit("existing Python environment is incomplete; preserve it for review before repair")
        run([base_python, "-m", "venv", venv])
        run([
            python, "-m", "pip", "install", "--no-index", "--find-links", WHEELHOUSE,
            "--requirement", REQUIREMENTS_LOCK,
        ])
    else:
        log("reusing the pinned Python environment")
    venv.chmod(0o700)
    setup_frida_host(base_python, support)
    identity.parent.mkdir(parents=True, exist_ok=True)
    if not identity.is_file():
        run([
            "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
            "-C", "0-Sky authorized SRD", "-f", identity,
        ])
    identity.chmod(0o600)
    return python


def choose_target(requested: str | None, python: Path | None) -> str | None:
    if requested:
        if not UDID_RE.fullmatch(requested):
            raise SystemExit(f"invalid UDID: {requested}")
        return requested
    devices = visible_usb_device_records(python)
    if len(devices) == 1:
        return devices[0]["udid"]
    if not devices:
        return None
    labels = [f"{item['deviceName']} — {item['productType']} — "
              f"{item['productVersion']} ({item['buildVersion']}) — USB — "
              f"ID {hashlib.sha256(item['udid'].encode()).hexdigest()[:8]}"
              for item in devices]
    # Use the native macOS picker for the normal packaged workflow. The user
    # selects a device description and never looks up or types a UDID.
    apple_choices = "{" + ",".join(json.dumps(label) for label in labels) + "}"
    script = (
        "set choices to " + apple_choices + "\n"
        "set picked to choose from list choices with title \"0-Sky Link\" "
        "with prompt \"Choose the Apple device to pair\"\n"
        "if picked is false then error number -128\n"
        "return item 1 of picked"
    )
    picked = subprocess.run(["/usr/bin/osascript", "-e", script], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if picked.returncode:
        raise SystemExit("device selection was cancelled")
    selected = picked.stdout.strip()
    try:
        return devices[labels.index(selected)]["udid"]
    except ValueError:
        raise SystemExit("the selected USB device is no longer available")


def instance_for(udid: str | None, requested: str | None) -> str | None:
    if requested:
        value = re.sub(r"[^a-z0-9]+", "-", requested.lower()).strip("-")
        if not value:
            raise SystemExit("--instance-name is not usable as a launchd label component")
        return value[:63]
    if udid:
        existing = installed_bindings().get(udid)
        return existing or f"srd-{re.sub(r'[^a-z0-9]', '', udid.lower())[-8:]}"
    return None


def print_checks(checks: list[Check], as_json: bool) -> None:
    if as_json:
        print(json.dumps([asdict(item) for item in checks], indent=2, sort_keys=True))
        return
    for item in checks:
        print(f"[{item.status:4}] {item.name}: {item.detail}")
        if item.fix and item.status == "FAIL":
            print(f"       fix: {item.fix}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="per-user 0-Sky configuration file")
    parser.add_argument("--init-config", action="store_true", help="create or refresh secure configuration for the current user")
    parser.add_argument("--print-config", action="store_true", help="print effective configuration and exit")
    parser.add_argument("--setup", action="store_true",
                        help="install tools/Python and install or repair all three per-device LaunchAgents")
    parser.add_argument("--install-tools", action="store_true",
                        help="install only missing Homebrew command dependencies")
    parser.add_argument("--fix-missing", action="store_true",
                        help="install missing host tools and the pinned offline Python environment; no device required")
    parser.add_argument("--install-homebrew", action="store_true",
                        help="allow the official interactive Homebrew installer when brew is absent")
    parser.add_argument("--setup-python", action="store_true",
                        help="create the exact pinned Python environment and SSH key")
    parser.add_argument("--install-companion", action="store_true",
                        help="install or repair the usbmux, worker, and bridge LaunchAgents")
    parser.add_argument("--requirements-only", action="store_true",
                        help="do not require per-device LaunchAgents in the final check")
    parser.add_argument("--udid", help="exact authorized SRD USB UDID; auto-detected when possible")
    parser.add_argument("--instance-name", help="stable per-device LaunchAgent suffix")
    parser.add_argument("--port", type=int)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--python", type=Path, help="candidate Python interpreter")
    parser.add_argument("--support", type=Path)
    parser.add_argument("--sdk")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    config = load_user_config(ROOT, args.config)
    support = (args.support or Path(config["paths"]["support"])).expanduser().resolve()
    identity = (args.identity or Path(config["paths"]["ssh_identity"])).expanduser().resolve()
    args.port = args.port or int(config["defaults"]["base_port"])
    args.sdk = args.sdk or str(config["defaults"]["sdk"])
    overrides: dict[str, object] = {
        "paths": {
            "support": str(support),
            "state": str(support / "state"),
            "artifacts": str(support / "artifacts"),
            "venv": str(support / "venv"),
            "ssh_identity": str(identity),
        },
        "defaults": {"base_port": args.port, "sdk": args.sdk},
    }
    if args.init_config or args.setup or args.setup_python or args.fix_missing:
        config_file, config = write_user_config(ROOT, args.config, overrides)
    else:
        config_file = user_config_path(args.config)
        config["paths"].update(overrides["paths"])
        config["defaults"].update(overrides["defaults"])
    config_only = not any((args.setup, args.install_tools, args.fix_missing,
                           args.install_homebrew, args.setup_python,
                           args.install_companion, args.udid))
    if args.print_config or (args.init_config and config_only):
        print(json.dumps(public_user_config(config, config_file), indent=2, sort_keys=True))
        return 0

    if not 1 <= args.port <= 65535:
        raise SystemExit("--port must be between 1 and 65535")

    if args.setup or args.install_tools or args.fix_missing:
        request_command_line_tools()
        install_tools(allow_homebrew_install=args.install_homebrew)
    selected = select_python(args.python, support)
    if args.setup or args.setup_python or args.fix_missing:
        selected = setup_python(identity, support)
    # A host-dependency repair is intentionally device-independent. Do not
    # show a device picker merely because multiple SRDs happen to be attached.
    target = None if args.requirements_only else choose_target(args.udid, selected)
    instance = instance_for(target, args.instance_name)

    if args.setup or args.install_companion:
        if target is None:
            raise SystemExit("connect exactly one authorized SRD over USB or pass --udid")
        if selected is None:
            raise SystemExit("pinned Python is missing; run with --setup-python")
        assert instance is not None
        run([
            selected, INSTALLER, "--udid", target,
            "--ssh-key", identity, "--host", "127.0.0.1",
            "--port", str(args.port), "--instance-name", instance,
            "--support", support,
        ])

    checks, selected = host_checks(
        args.sdk, args.python, support, identity,
        None if args.requirements_only else instance,
        None if args.requirements_only else target,
        args.port,
    )
    if target:
        checks.append(Check("PASS", "USB target", target))
    else:
        checks.append(Check("WARN", "USB target", "no single USB target selected"))
    print_checks(checks, args.json)
    failures = sum(item.status == "FAIL" for item in checks)
    if not args.json:
        print(f"\nmacOS host status: {'PASS' if failures == 0 else 'FAIL'} ({failures} failure(s))")
        if failures == 0 and instance:
            print(f"companion instance: {instance}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except UserConfigError as error:
        raise SystemExit(f"invalid per-user configuration: {error}")
