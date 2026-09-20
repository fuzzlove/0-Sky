#!/usr/bin/env python3
"""0-Sky Link multi-SRD bootstrap and Cryptex deployment PoC.

Authorized Apple Security Research Devices only. The workflow uses Developer
Mode, Apple Lockdown/RemoteXPC, cryptexd personalization, exact-UDID USB SSH,
and the paired 0-Sky Mac worker. It does not contain a retail-device bypass.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import inspect
import json
import os
from pathlib import Path
import plistlib
import queue
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Any

from zero_sky_user_config import (
    UserConfigError,
    config_path as user_config_path,
    defaults as user_config_defaults,
    load as load_user_config,
    public as public_user_config,
    write as write_user_config,
)

ROOT = Path(__file__).resolve().parent
# The signed macOS app keeps the controller under Resources/Scripts and the
# immutable payload under Resources/Kit. Source checkouts retain the original
# sibling `kit` layout. Only an explicit typed bridge environment override is
# accepted; the manifest below still validates every consumed kit file.
KIT = Path(os.environ.get("ZERO_SKY_KIT_ROOT", ROOT / "kit")).expanduser().resolve()
REQUIREMENTS = KIT / "host-mac/requirements.txt"
REQUIREMENTS_LOCK = KIT / "host-mac/requirements-lock.txt"
WHEELHOUSE = KIT / "host-mac/wheelhouse"
USER_CONFIG = user_config_defaults(ROOT)
SUPPORT = Path(USER_CONFIG["paths"]["support"])
ARTIFACTS = Path(USER_CONFIG["paths"]["artifacts"])
STATE_ROOT = Path(USER_CONFIG["paths"]["state"])
IDENTITY_DEFAULT = Path(USER_CONFIG["paths"]["ssh_identity"])
UDID_RE = re.compile(r"^[A-Za-z0-9-]{20,80}$")
FILZA_BUNDLE_ID = "com.tigisoftware.Filza"
FILZA_VERSION = "4.0"
RUNTIME_MANAGER_VERSION = "2.4.9"
FILZA_CRYPTEX_ID = "codes.rambo.research.filza.permanent"
FILZA_CRYPTEX_VERSION = "1.0.1789361256"
APPREGISTRARD_ID = "codes.rambo.research.appregistrard"


class PoCError(RuntimeError):
    pass


_ACTIVE_CHILD: subprocess.Popen | None = None
_STOP_REQUESTED = False


def _request_stop(_signum: int, _frame: Any) -> None:
    """Forward Bridge cancellation to the one child owned by this controller."""
    global _STOP_REQUESTED
    _STOP_REQUESTED = True
    child = _ACTIVE_CHILD
    if child is not None and child.poll() is None:
        child.terminate()


signal.signal(signal.SIGTERM, _request_stop)
signal.signal(signal.SIGINT, _request_stop)


def log(message: str) -> None:
    print(f"[0-Sky Link] {message}", flush=True)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def run(argv: list[str | Path], *, check: bool = True, timeout: int | None = None,
        capture: bool = False, input_data: bytes | None = None,
        log_file: Path | None = None) -> subprocess.CompletedProcess:
    command = [str(value) for value in argv]
    executable = Path(command[0]).name
    phase = Path(command[1]).stem if len(command) > 1 and command[1].endswith(".py") else executable
    log(f"native phase: {phase}")
    started = time.monotonic()
    global _ACTIVE_CHILD, _STOP_REQUESTED
    if _STOP_REQUESTED:
        raise PoCError("setup cancelled")
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _ACTIVE_CHILD = process
    output_queue: queue.Queue[tuple[str, bytes | None]] = queue.Queue()

    def drain(name: str, stream: Any) -> None:
        try:
            for block in iter(lambda: stream.read(64 * 1024), b""):
                output_queue.put((name, block))
        finally:
            output_queue.put((name, None))

    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()

    if input_data is not None:
        assert process.stdin is not None
        try:
            process.stdin.write(input_data)
            process.stdin.close()
        except BrokenPipeError:
            pass

    stdout = bytearray()
    stderr = bytearray()
    finished_streams: set[str] = set()
    next_heartbeat = started + 10
    log_handle = None
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_handle = log_file.open("ab")
        log_handle.write(("$ " + " ".join(command) + "\n").encode())
        log_handle.flush()
    try:
        while process.poll() is None or len(finished_streams) < 2:
            if _STOP_REQUESTED and process.poll() is None:
                process.terminate()
            elapsed = time.monotonic() - started
            if timeout is not None and elapsed >= timeout:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                raise subprocess.TimeoutExpired(
                    command, timeout, output=bytes(stdout), stderr=bytes(stderr)
                )
            try:
                stream_name, block = output_queue.get(timeout=0.25)
                if block is None:
                    finished_streams.add(stream_name)
                    continue
                destination = stdout if stream_name == "stdout" else stderr
                destination.extend(block)
                if log_handle:
                    log_handle.write(block)
                    log_handle.flush()
                if not capture:
                    console = sys.stdout.buffer if stream_name == "stdout" else sys.stderr.buffer
                    console.write(block)
                    console.flush()
            except queue.Empty:
                pass
            now = time.monotonic()
            if process.poll() is None and now >= next_heartbeat:
                log(f"native phase still running: {phase} ({int(now - started)}s elapsed)")
                next_heartbeat = now + 10
    finally:
        _ACTIVE_CHILD = None
        if log_handle:
            log_handle.close()
    completed = subprocess.CompletedProcess(
        command, process.returncode, bytes(stdout), bytes(stderr)
    )
    if _STOP_REQUESTED:
        raise PoCError("setup cancelled")
    if check and completed.returncode:
        detail = (completed.stdout + completed.stderr).decode("utf-8", "replace")[-6000:]
        raise PoCError(f"command failed ({completed.returncode}): {' '.join(command)}\n{detail}")
    return completed


def dependencies_ok(python: Path) -> bool:
    probe = run([python, "-c", '''import importlib.metadata as m,sys
assert sys.version_info[:2] == (3,12)
import pymobiledevice3,Crypto,zstandard
assert m.version("pymobiledevice3") == "11.3.1"
assert m.version("pycryptodome") == "3.23.0"
assert m.version("zstandard") == "0.25.0"'''],
                check=False, capture=True, timeout=20)
    return probe.returncode == 0


def select_python(setup: bool) -> Path:
    candidates = [
        Path(os.environ["ZERO_SKY_PYTHON"]) if os.environ.get("ZERO_SKY_PYTHON") else SUPPORT / "venv/bin/python3",
        SUPPORT / "venv/bin/python3",
        Path("/opt/homebrew/bin/python3.13"),
        Path("/opt/homebrew/bin/python3"),
        Path(sys.executable),
    ]
    seen: set[str] = set()
    for candidate in candidates:
        candidate = candidate.expanduser()
        key = str(candidate)
        if key in seen or not candidate.is_file():
            continue
        seen.add(key)
        if dependencies_ok(candidate):
            # Preserve the venv entry point. Resolving its symlink on the
            # python.org macOS build produces the base-framework executable,
            # which then loses the bundled site-packages in child stages.
            return candidate.absolute()
    if not setup:
        raise PoCError(
            "pinned Python dependencies are missing. Run `./0-sky --setup --check` "
            "once while the Mac has package access."
        )
    venv = Path(USER_CONFIG["paths"]["venv"])
    if sys.version_info[:2] != (3, 12):
        raise PoCError("offline setup requires the bundled Python 3.12 runtime target")
    if not REQUIREMENTS_LOCK.is_file() or len(list(WHEELHOUSE.glob("*.whl"))) < 100:
        raise PoCError("the bundled offline Python dependency set is incomplete")
    run([sys.executable, "-m", "venv", str(venv)])
    python = venv / "bin/python3"
    run([
        python, "-m", "pip", "install", "--no-index", "--find-links", WHEELHOUSE,
        "--requirement", REQUIREMENTS_LOCK,
    ], timeout=600)
    venv.chmod(0o700)
    if not dependencies_ok(python):
        raise PoCError("the 0-Sky Python environment did not pass its import check")
    return python


def verify_manifest() -> int:
    manifest = KIT / "SHA256SUMS"
    if not manifest.is_file():
        raise PoCError(f"missing integrity manifest: {manifest}")
    count = 0
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        expected, raw = line.split(None, 1)
        relative = raw.strip().lstrip("*").removeprefix("./")
        path = KIT / relative
        # The minimal SRDssh payload deliberately uses one relative `sh ->
        # toybox` applet link. Accept only that exact, non-traversing link;
        # every other manifest entry must remain a regular file.
        approved_link = (
            relative == "srdssh/payload-root/usr/bin/sh"
            and path.is_symlink()
            and os.readlink(path) == "toybox"
        )
        if (not path.is_file()
                or (path.is_symlink() and not approved_link)
                or sha256(path) != expected):
            raise PoCError(f"kit integrity check failed: {relative}")
        count += 1
    if count < 10:
        raise PoCError("kit checksum manifest is unexpectedly small")
    log(f"verified {count} immutable kit files")
    return count


async def usb_inventory() -> list[dict[str, str]]:
    from pymobiledevice3.usbmux import list_devices
    from pymobiledevice3.lockdown import create_using_usbmux
    found: list[dict[str, str]] = []
    devices = list_devices()
    if inspect.isawaitable(devices):
        devices = await devices
    for item in devices:
        if str(item.connection_type).upper() != "USB":
            continue
        udid = str(item.serial)
        info = {"udid": udid, "product_type": "unknown", "product_version": "unknown"}
        client = None
        try:
            client = create_using_usbmux(serial=udid, autopair=False)
            if inspect.isawaitable(client):
                client = await client
            info.update(product_type=str(client.product_type),
                        product_version=str(client.product_version))
        except Exception as error:
            info["lockdown_error"] = f"{type(error).__name__}: {error}"
        finally:
            if client is not None:
                result = client.close()
                if asyncio.iscoroutine(result):
                    await result
        found.append(info)
    return found


def launchagent_bindings() -> dict[str, dict[str, str]]:
    answer: dict[str, dict[str, str]] = {}
    for path in (Path.home() / "Library/LaunchAgents").glob(
        "com.liquidskysecurity.crypstore-worker.*.plist"
    ):
        try:
            value = plistlib.loads(path.read_bytes())
            env = value.get("EnvironmentVariables", {})
            udid = str(env.get("CRYPSTORE_DEVICE_UDID", ""))
            if UDID_RE.fullmatch(udid):
                answer[udid] = {
                    "instance": str(value["Label"]).split(".crypstore-worker.", 1)[1],
                    "port": str(env.get("CRYPSTORE_DEVICE_PORT", "")),
                }
        except Exception:
            continue
    return answer


def tcp_free(port: int) -> bool:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def slug_for(device: dict[str, str], existing: dict[str, str] | None) -> str:
    if existing and existing.get("instance"):
        return existing["instance"]
    family = "ipad" if device.get("product_type", "").lower().startswith("ipad") else "iphone"
    suffix = re.sub(r"[^a-z0-9]", "", device["udid"].lower())[-8:]
    return f"{family}-srd-{suffix}"


def assign_targets(devices: list[dict[str, str]], requested: list[str],
                   base_port: int) -> list[dict[str, Any]]:
    by_udid = {item["udid"]: item for item in devices}
    selected = requested or sorted(by_udid)
    missing = [value for value in selected if value not in by_udid]
    if missing:
        raise PoCError("requested USB device(s) not visible: " + ", ".join(missing))
    bindings = launchagent_bindings()
    used: set[int] = set()
    targets: list[dict[str, Any]] = []
    next_port = base_port
    for udid in selected:
        item = dict(by_udid[udid])
        existing = bindings.get(udid)
        port = int(existing["port"]) if existing and existing.get("port", "").isdigit() else 0
        if not port:
            while next_port in used or not tcp_free(next_port):
                next_port += 1
            port, next_port = next_port, next_port + 1
        used.add(port)
        item.update(port=port, instance=slug_for(item, existing))
        targets.append(item)
    return targets


def ssh_base(target: dict[str, Any], identity: Path) -> list[str]:
    candidates = (
        SUPPORT / "instances" / target["instance"] / "device-known-hosts",
        STATE_ROOT / target["instance"] / "srdssh" / "device-known-hosts",
    )
    known_hosts = next((path for path in candidates if path.is_file()), None)
    if (
        known_hosts is None or known_hosts.is_symlink()
        or known_hosts.stat().st_mode & 0o077
    ):
        raise PoCError("an exact-device private SSH host-key pin is required")
    alias = "0sky-device-" + hashlib.sha256(target["udid"].encode()).hexdigest()[:24]
    return [
        "/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", f'UserKnownHostsFile="{known_hosts}"',
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"HostKeyAlias={alias}",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-i", str(identity),
        "-p", str(target["port"]), "root@127.0.0.1",
    ]


def remote(target: dict[str, Any], identity: Path, command: str, *,
           check: bool = True, capture: bool = False, input_data: bytes | None = None,
           timeout: int = 120, log_file: Path | None = None) -> subprocess.CompletedProcess:
    return run(ssh_base(target, identity) + [command], check=check, capture=capture,
               input_data=input_data, timeout=timeout, log_file=log_file)


def bridge_status(target: dict[str, Any], identity: Path) -> dict:
    script = r'''import json,pathlib,urllib.request
try:
 token=pathlib.Path("/var/jb/etc/trollstorelite-srd-bridge.token").read_text().strip()
 request=urllib.request.Request("http://127.0.0.1:48654/v1/status",headers={"X-TrollStore-Bridge-Token":token})
 print(urllib.request.urlopen(request,timeout=10).read().decode())
except Exception as e: print(json.dumps({"error":type(e).__name__}))'''
    result = remote(target, identity,
                    "/var/jb/usr/bin/python3 -c " + shlex.quote(script),
                    check=False, capture=True, timeout=20)
    try:
        return json.loads(result.stdout)
    except Exception:
        return {"error": (result.stdout + result.stderr).decode("utf-8", "replace")}


def package_version(target: dict[str, Any], identity: Path, package: str) -> str:
    command = "/var/jb/usr/bin/dpkg-query -W -f='${Version}' " + shlex.quote(package)
    result = remote(target, identity, command, check=False, capture=True, timeout=20)
    return result.stdout.decode().strip() if result.returncode == 0 else ""


def device_system_version(target: dict[str, Any], identity: Path) -> dict[str, str]:
    result = remote(
        target, identity, "cat /System/Library/CoreServices/SystemVersion.plist",
        capture=True, timeout=20,
    )
    try:
        value = plistlib.loads(result.stdout)
    except Exception as error:
        raise PoCError("device SystemVersion.plist is unreadable") from error
    return {
        "version": str(value.get("ProductVersion", "")),
        "build": str(value.get("ProductBuildVersion", "")),
    }


def appregistrard_status(target: dict[str, Any], identity: Path) -> list[dict[str, Any]]:
    program = r'''import glob,hashlib,json,pathlib,subprocess
try: commands=subprocess.check_output(["/bin/ps","-axo","command="],text=True).splitlines()
except Exception: commands=[]
answer=[]
for raw in glob.glob("/private/var/run/com.apple.security.cryptexd/mnt/codes.rambo.research.appregistrard.*"):
 root=pathlib.Path(raw); daemon=root/"usr/bin/appregistrard"; installd=root/"usr/libexec/srdinstalld"
 if not daemon.is_file() or not installd.is_file(): continue
 answer.append({"mount":raw,"srdinstalld_sha256":hashlib.sha256(installd.read_bytes()).hexdigest(),
 "daemon_running":any(str(daemon)+" daemon" in c for c in commands),
 "srdinstalld_running":any(str(installd) in c for c in commands)})
print(json.dumps(answer))'''
    result = remote(
        target, identity, "/var/jb/usr/bin/python3 -c " + shlex.quote(program),
        check=False, capture=True, timeout=30,
    )
    try:
        value = json.loads(result.stdout)
        return value if isinstance(value, list) else []
    except Exception:
        return []


def ensure_appregistrard_support(python: Path, target: dict[str, Any],
                                 identity: Path, run_dir: Path) -> bool:
    """Install only the appregistrard build matching the target OS build.

    srdinstalld is derived from Apple's exact stock executable and is therefore
    never shared across OS builds. The iOS 26 image uses appregistrard's MCM
    copy backend; iOS 27 keeps the stable InstallCoordination backend.
    """
    system = device_system_version(target, identity)
    build_dir = KIT / "appregistrard" / system["build"]
    provenance_path = build_dir / "PROVENANCE.json"
    if not provenance_path.is_file():
        log(
            f"{target['instance']}: no exact appregistrard/srdinstalld image "
            f"for iOS {system['version']} ({system['build']}); preserving the "
            "bounded direct-registration fallback"
        )
        return False
    provenance = json.loads(provenance_path.read_text())
    # The provenance records stock installd separately. The active executable
    # is patched, so compare against its exact packaged hash as well.
    packaged_hash = str(provenance.get("srdinstalld_sha256", ""))
    if not packaged_hash:
        packaged_hash = str(provenance.get("files", {}).get("srdinstalld", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", packaged_hash):
        raise PoCError(
            f"invalid patched srdinstalld provenance for {system['build']}"
        )
    healthy = [
        item for item in appregistrard_status(target, identity)
        if item.get("daemon_running") is True
        and item.get("srdinstalld_running") is True
        and item.get("srdinstalld_sha256") == packaged_hash
    ]
    if healthy:
        log(
            f"{target['instance']}: preserving exact-build MCM registrar for "
            f"{system['build']}"
        )
        return True

    installer = KIT / "srdssh/install_cryptex_native.py"
    command = [
        python, installer, APPREGISTRARD_ID,
        build_dir / "appregistrard-apfs-sealed-udzo.dmg",
        build_dir / "appregistrard.gtcd",
        build_dir / "appregistrard-apfs-sealed.hash",
        str(provenance["version"]), target["udid"],
        build_dir / "BuildManifest.plist", "--timeout", "240",
    ]
    run(command, timeout=900, log_file=run_dir / "appregistrard-install.log")
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        healthy = [
            item for item in appregistrard_status(target, identity)
            if item.get("daemon_running") is True
            and item.get("srdinstalld_running") is True
            and item.get("srdinstalld_sha256") == packaged_hash
        ]
        if healthy:
            log(
                f"{target['instance']}: exact-build appregistrard and "
                "srdinstalld are active"
            )
            return True
        time.sleep(3)
    raise PoCError(
        f"appregistrard Cryptex mounted but exact {system['build']} daemon pair "
        "did not become active"
    )


def app_info(target: dict[str, Any], identity: Path, bundle: str) -> dict:
    program = r'''import json,pathlib,plistlib,subprocess,sys
prefix=sys.argv[1]+" : "; answer={}
try: rows=subprocess.check_output(["/var/jb/usr/bin/uicache","-l"],text=True).splitlines()
except Exception: rows=[]
paths=[r[len(prefix):].strip() for r in rows if r.startswith(prefix)]
if len(paths)==1:
 p=pathlib.Path(paths[0])
 try:
  i=plistlib.loads((p/"Info.plist").read_bytes()); answer={"path":str(p),"version":str(i.get("CFBundleShortVersionString","")),"build":str(i.get("CFBundleVersion","")),"distribution":str(i.get("ZeroSkyDistributionName",""))}
 except Exception: pass
print(json.dumps(answer))'''
    result = remote(target, identity,
        "/var/jb/usr/bin/python3 -c " + shlex.quote(program) + " " + shlex.quote(bundle),
        check=False, capture=True, timeout=30)
    try:
        return json.loads(result.stdout)
    except Exception:
        return {}


def repair_mounted_app_registrations(target: dict[str, Any], identity: Path,
                                     run_dir: Path) -> dict[str, str]:
    """Restore LaunchServices entries lost when persistent Cryptexes remount.

    Research app Cryptexes survive a reboot, but their Home Screen registration
    does not always survive with them. Only the three reviewed bundle IDs are
    eligible here; unrelated apps in other mounted Cryptexes are never added.
    """
    program = r'''import json,pathlib,plistlib,subprocess
root=pathlib.Path("/private/var/run/com.apple.security.cryptexd/mnt")
allowed={
 "com.liquidsky.CrypStore":"codes.rambo.research.crypstore.",
 "codes.liquidsky.research.zerosky":"codes.rambo.research.crypstore.",
 "com.tigisoftware.Filza":"codes.rambo.research.filza.permanent.",
}
found={}
for app in root.glob("*/Applications/*.app"):
 try:
  info=plistlib.loads((app/"Info.plist").read_bytes())
  bundle=str(info.get("CFBundleIdentifier", ""))
  executable=str(info.get("CFBundleExecutable", ""))
  mount_name=app.parent.parent.name
  if bundle not in allowed or not mount_name.startswith(allowed[bundle]): continue
  if not executable or not (app/executable).is_file(): continue
  old=found.get(bundle)
  if old is None or app.parent.parent.stat().st_mtime > pathlib.Path(old).parent.parent.stat().st_mtime:
   found[bundle]=str(app)
 except Exception: pass
try:
 rows=subprocess.check_output(["/var/jb/usr/bin/uicache","-l"],text=True).splitlines()
except Exception:
 rows=[]
registered={}
for row in rows:
 if " : " in row:
  bundle,path=row.split(" : ",1); registered[bundle]=path.strip()
answer={}
for bundle,path in sorted(found.items()):
 existing=registered.get(bundle,"")
 valid_existing=False
 if existing:
  try:
   ep=pathlib.Path(existing); ei=plistlib.loads((ep/"Info.plist").read_bytes())
   ex=str(ei.get("CFBundleExecutable",""))
   metadata_ok=(ei.get("CFBundleIdentifier")==bundle and ex and "/" not in ex and (ep/ex).is_file())
   mcm=existing.startswith(("/private/var/containers/Bundle/Application/","/var/containers/Bundle/Application/"))
   cryptex=(existing.startswith(str(root)+"/") and ep.parent.parent.name.startswith(allowed[bundle]))
   valid_existing=metadata_ok and (mcm or cryptex)
  except Exception: pass
 if not valid_existing:
  done=subprocess.run(["/var/jb/usr/bin/uicache","-p",path],text=True,capture_output=True)
  if done.returncode:
   raise SystemExit("uicache failed for "+bundle+": "+done.stderr.strip())
 answer[bundle]=existing if valid_existing else path
print(json.dumps(answer,sort_keys=True))'''
    result = remote(
        target,
        identity,
        "/var/jb/usr/bin/python3 -c " + shlex.quote(program),
        capture=True,
        timeout=180,
        log_file=run_dir / "app-registration-repair.log",
    )
    try:
        repaired = json.loads(result.stdout)
    except Exception as error:
        raise PoCError("mounted app registration repair returned invalid data") from error
    if repaired:
        log(
            f"{target['instance']}: verified Home Screen registration for "
            + ", ".join(sorted(repaired))
        )
    return repaired


def ensure_bootstrap_bridge(target: dict[str, Any], identity: Path,
                            run_dir: Path) -> None:
    manager = KIT / f"packages/srd-runtime-manager_{RUNTIME_MANAGER_VERSION}_iphoneos-arm64.deb"
    remote_path = "/var/jb/var/tmp/0-sky-runtime-manager.deb"
    remote(target, identity, "mkdir -p /var/jb/var/tmp /var/jb/usr/local/libexec",
           log_file=run_dir / "bootstrap-bridge.log")
    python_ready = remote(
        target, identity, "/var/jb/usr/bin/python3 -c 'import sys; assert sys.version_info[:2] == (3, 9)'",
        check=False, capture=True, timeout=20,
    ).returncode == 0
    if not python_ready:
        # The reviewed bootstrap_1900 archive intentionally carries only the
        # package-management base. Keep the Python runtime needed by the
        # manager fully offline and immutable so a fresh SRD does not depend
        # on repository availability during enrollment.
        offline = KIT / "offline-python"
        packages = [
            "libgdbm6_1.23_iphoneos-arm64.deb",
            "libpython3.9_3.9.9-1_iphoneos-arm64.deb",
            "python3.9_3.9.9-1_iphoneos-arm64.deb",
            "python3_3.9.9-1_iphoneos-arm64.deb",
        ]
        for name in packages:
            source = offline / name
            if not source.is_file():
                raise PoCError(f"missing immutable offline Python dependency: {source}")
            destination = "/var/jb/var/tmp/" + name
            remote(target, identity, "cat > " + shlex.quote(destination),
                   input_data=source.read_bytes(),
                   log_file=run_dir / "bootstrap-bridge.log")
        paths = " ".join(
            shlex.quote("/var/jb/var/tmp/" + name) for name in packages)
        remote(
            target, identity,
            f"/var/jb/usr/bin/dpkg --unpack {paths} && "
            "/var/jb/usr/bin/dpkg --configure --pending && "
            "/var/jb/usr/bin/python3 -c 'import sys; assert sys.version_info[:2] == (3, 9)'",
            timeout=600, log_file=run_dir / "bootstrap-bridge.log",
        )
    marker = remote(
        target, identity,
        "grep -Fq repair_reviewed_app_registrations "
        "/var/jb/usr/local/libexec/srd-runtime-manager.py",
        check=False, capture=True, timeout=20,
    )
    upgrade = (
        package_version(target, identity,
                        "com.liquidskysecurity.srd-runtime-manager")
        != RUNTIME_MANAGER_VERSION or marker.returncode != 0
    )
    if upgrade:
        remote(target, identity, "cat > " + shlex.quote(remote_path),
               input_data=manager.read_bytes(), log_file=run_dir / "bootstrap-bridge.log")
        command = (
            f"/var/jb/usr/bin/apt-get install -y --no-remove {shlex.quote(remote_path)} || "
            f"(/var/jb/usr/bin/dpkg --unpack {shlex.quote(remote_path)} && "
            "/var/jb/usr/bin/sh /var/jb/var/lib/dpkg/info/"
            "com.liquidskysecurity.srd-runtime-manager.postinst configure && "
            "/var/jb/usr/bin/dpkg --configure --pending)"
        )
        remote(target, identity, command, timeout=600,
               log_file=run_dir / "bootstrap-bridge.log")
        # The manager is KeepAlive-backed by the persistent runtime Cryptex.
        # Terminate only the old daemon instance so launchd loads the upgraded
        # Python source immediately; unrelated Python services are untouched.
        restart = r'''import os,pathlib,subprocess,time
ps=next((p for p in ("/var/jb/usr/bin/ps","/bin/ps") if pathlib.Path(p).is_file()),"")
try: rows=subprocess.check_output([ps,"-axo","pid=,command="],text=True).splitlines()
except Exception: rows=[]
for row in rows:
 try: pid_text,command=row.strip().split(None,1)
 except ValueError: continue
 if command.startswith("/var/jb/usr/bin/python3 /var/jb/usr/local/libexec/srd-runtime-manager.py daemon"):
  try: os.kill(int(pid_text),15); print("restarted-manager-pid="+pid_text)
  except OSError: pass
time.sleep(3)'''
        remote(target, identity,
               "/var/jb/usr/bin/python3 -c " + shlex.quote(restart),
               timeout=30, log_file=run_dir / "bootstrap-bridge.log")
    bridge = KIT / "automation/CrypStoreAutomation/trollstorelite-srd-bridge.py"
    remote(target, identity,
           "cat > /var/jb/usr/local/libexec/trollstorelite-srd-bridge.py",
           input_data=bridge.read_bytes(), log_file=run_dir / "bootstrap-bridge.log")
    token_program = r'''import os,pathlib,secrets
p=pathlib.Path("/var/jb/etc/trollstorelite-srd-bridge.token");p.parent.mkdir(parents=True,exist_ok=True)
try: valid=len(p.read_text().strip())>=16
except Exception: valid=False
if not valid: p.write_text(secrets.token_hex(32)+"\n")
os.chmod(p,0o640);os.chown(p,0,501);print("bridge-token-ready")'''
    remote(target, identity,
           "/var/jb/usr/bin/python3 -c " + shlex.quote(token_program),
           log_file=run_dir / "bootstrap-bridge.log")


def setup_companion(python: Path, target: dict[str, Any], identity: Path,
                    run_dir: Path, repair_pairing: bool) -> None:
    ensure_bootstrap_bridge(target, identity, run_dir)
    command = [
        python, KIT / "host-mac/install.py", "--udid", target["udid"],
        "--ssh-key", identity, "--host", "127.0.0.1", "--port", str(target["port"]),
        "--instance-name", target["instance"], "--support", SUPPORT,
    ]
    if not repair_pairing:
        # Normal install may show Apple's Lockdown Trust UI if required. The
        # exact-UDID marker still fails closed until that succeeds.
        pass
    run(command, timeout=1800, log_file=run_dir / "host-companion.log")


def stage_companion_assets(python: Path, target: dict[str, Any],
                           identity: Path, run_dir: Path) -> None:
    """Stage the verified per-device recovery tree before SSH exists."""
    support = SUPPORT / "instances" / target["instance"]
    if (support / ".install-complete").is_file():
        return
    run([
        python, KIT / "host-mac/install.py", "--udid", target["udid"],
        "--ssh-key", identity, "--host", "127.0.0.1",
        "--port", str(target["port"]), "--instance-name", target["instance"],
        "--support", SUPPORT, "--stage-only",
    ], timeout=600, log_file=run_dir / "stage-companion.log")


def ensure_first_runtime(python: Path, target: dict[str, Any],
                         identity: Path, run_dir: Path) -> None:
    """Establish the first Python-trusted runtime on fresh Procursus."""
    if remote(
        target, identity,
        "/var/jb/usr/bin/python3 -c 'import sys; assert sys.version_info[:2] == (3, 9)'",
        check=False, capture=True, timeout=20,
    ).returncode == 0:
        return
    token_command = r'''T=
for C in /private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.srdssh.*/usr/bin/toybox; do
 [ -x "$C" ] && T="$C" && break
done
[ -n "$T" ] || exit 74
"$T" mkdir -p /var/jb/etc /var/jb/var/tmp/0sky-first-runtime
if [ ! -s /var/jb/etc/trollstorelite-srd-bridge.token ]; then
 "$T" head -c 32 /dev/urandom | "$T" xxd -p -c 64 > /var/jb/etc/trollstorelite-srd-bridge.token
fi
"$T" chmod 0640 /var/jb/etc/trollstorelite-srd-bridge.token
"$T" chown 0:501 /var/jb/etc/trollstorelite-srd-bridge.token
test "$("$T" wc -c < /var/jb/etc/trollstorelite-srd-bridge.token)" -eq 65'''
    remote(target, identity, token_command,
           log_file=run_dir / "first-runtime.log")
    package_paths = [
        KIT / "offline-python/libgdbm6_1.23_iphoneos-arm64.deb",
        KIT / "offline-python/libpython3.9_3.9.9-1_iphoneos-arm64.deb",
        KIT / "offline-python/python3.9_3.9.9-1_iphoneos-arm64.deb",
        KIT / "offline-python/python3_3.9.9-1_iphoneos-arm64.deb",
        KIT / "packages/ellekit_1.2_iphoneos-arm64.deb",
        KIT / "packages/wget_1.24.5_iphoneos-arm64.deb",
        KIT / f"packages/srd-runtime-manager_{RUNTIME_MANAGER_VERSION}_iphoneos-arm64.deb",
        KIT / "packages/preferenceloader_2.4.3-1+debug_iphoneos-arm64.deb",
        KIT / "packages/CatVNC-0.0.2-ios27-srd-backup.deb",
    ]
    remote_paths: list[str] = []
    for package in package_paths:
        if not package.is_file() or package.is_symlink():
            raise PoCError(f"verified first-runtime package is unavailable: {package}")
        destination = "/var/jb/var/tmp/0sky-first-runtime/" + package.name
        remote(target, identity, "cat > " + shlex.quote(destination),
               input_data=package.read_bytes(), timeout=180,
               log_file=run_dir / "first-runtime.log")
        remote_paths.append(destination)
    remote(
        target, identity,
        "/var/jb/usr/bin/dpkg --unpack "
        + " ".join(shlex.quote(path) for path in remote_paths),
        check=False, timeout=600, log_file=run_dir / "first-runtime.log",
    )
    instance = SUPPORT / "instances" / target["instance"]
    builder = instance / "automation/tools/srd-runtime-manager/build_poc.py"
    build_output = instance / "automation/artifacts/srd-runtime-poc/build"
    run([python, builder, "--output", build_output], timeout=600,
        log_file=run_dir / "first-runtime-build.log")
    known_hosts = STATE_ROOT / target["instance"] / "srdssh/device-known-hosts"
    sync = instance / "automation/tools/srd-runtime-manager/sync_runtime_cryptex.py"
    alias = "0sky-device-" + hashlib.sha256(target["udid"].encode()).hexdigest()[:24]
    run([
        python, sync, "--host", "127.0.0.1", "--port", str(target["port"]),
        "--key", identity, "--udid", target["udid"],
        "--known-hosts", known_hosts, "--host-alias", alias,
        "--frida-root", KIT / "frida/17.18.0-ios",
    ], timeout=1800, log_file=run_dir / "first-runtime-sync.log")
    remote(target, identity, "/var/jb/usr/bin/dpkg --configure --pending",
           timeout=600, log_file=run_dir / "first-runtime.log")
    proof = remote(
        target, identity,
        "/var/jb/usr/bin/python3 -c 'import sys; assert sys.version_info[:2] == (3, 9)'",
        check=False, capture=True, timeout=20,
    )
    if proof.returncode:
        raise PoCError("first runtime mounted but the pinned device Python proof failed")


def ensure_frida_runtime(python: Path, target: dict[str, Any],
                         identity: Path, run_dir: Path) -> None:
    """Seal, materialize, start, and prove the project-pinned Frida runtime."""
    version = remote(
        target, identity, "/var/jb/usr/sbin/frida-server --version",
        check=False, capture=True, timeout=20,
    )
    if version.returncode != 0 or version.stdout.decode().strip() != "17.18.0":
        instance = SUPPORT / "instances" / target["instance"]
        sync = instance / "automation/tools/srd-runtime-manager/sync_runtime_cryptex.py"
        known_hosts = instance / "device-known-hosts"
        alias = "0sky-device-" + hashlib.sha256(target["udid"].encode()).hexdigest()[:24]
        run([
            python, sync, "--host", "127.0.0.1", "--port", str(target["port"]),
            "--key", identity, "--udid", target["udid"],
            "--known-hosts", known_hosts, "--host-alias", alias,
            "--frida-root", KIT / "frida/17.18.0-ios",
        ], timeout=1800, log_file=run_dir / "frida-runtime-sync.log")

        # The research Cryptex is mounted as a discrete filesystem on iOS 27,
        # not unioned into /var/jb. Materialize only the three verified,
        # trust-cached files into the Procursus prefix so tooling has a stable
        # path across randomized Cryptex mount names.
        materialize = r'''M=
for P in /private/var/run/com.apple.security.cryptexd/mnt/codes.openai.research.ellekitloader.*/usr/sbin/frida-server; do
 test -x "$P" || continue
 test "$("$P" --version 2>/dev/null)" = "17.18.0" || continue
 M=${P%/usr/sbin/frida-server}
done
test -n "$M" || exit 2
mkdir -p /var/jb/usr/sbin /var/jb/usr/lib/frida-1.0 /var/jb/Library/LaunchDaemons /var/jb/var/log || exit 3
cp "$M/usr/sbin/frida-server" /var/jb/usr/sbin/frida-server || exit 4
cp "$M/usr/lib/frida-1.0/frida-agent.dylib" /var/jb/usr/lib/frida-1.0/frida-agent.dylib || exit 5
cp "$M/Library/LaunchDaemons/re.frida.server.plist" /var/jb/Library/LaunchDaemons/re.frida.server.plist || exit 6
chmod 755 /var/jb/usr/sbin/frida-server || exit 7
chmod 644 /var/jb/usr/lib/frida-1.0/frida-agent.dylib /var/jb/Library/LaunchDaemons/re.frida.server.plist || exit 8'''
        remote(target, identity, materialize, timeout=120,
               log_file=run_dir / "frida-materialize.log")

    # Starting this project-owned research service is reversible Tier 1 work.
    # `command=` is required: Toybox truncates `comm=` to the mount prefix.
    start = r'''G=/var/jb/usr/bin/grep; test -x "$G" || G=/usr/bin/grep
if ! ps ax -o command= 2>/dev/null | "$G" -q '[f]rida-server$'; then
 /var/jb/usr/sbin/frida-server >/var/jb/var/log/frida-server.log 2>&1 </dev/null &
 sleep 2
fi
ps ax -o command= 2>/dev/null | "$G" -q '[f]rida-server$' '''
    remote(target, identity, start, timeout=30,
           log_file=run_dir / "frida-start.log")
    proof = remote(
        target, identity, "/var/jb/usr/sbin/frida-server --version",
        check=False, capture=True, timeout=20,
    )
    if proof.returncode or proof.stdout.decode().strip() != "17.18.0":
        raise PoCError("Frida device/server did not converge to required version 17.18.0")


def direct_components_current(target: dict[str, Any], identity: Path) -> bool:
    return (
        package_version(target, identity, "com.catvnc.server") == "0.0.2"
        and app_info(target, identity, "com.liquidsky.CrypStore").get("version") == "3.4.4"
        and app_info(target, identity, "codes.liquidsky.research.zerosky").get("version") == "1.9.0"
    )


def bootstrap_components(python: Path, target: dict[str, Any], identity: Path,
                         run_dir: Path) -> None:
    command = [
        python, KIT / "host-mac/bootstrap_device.py", "--support", SUPPORT,
        "--instance-name", target["instance"], "--catvnc", "--commissary",
        "--zero-sky-ipa", KIT / "payloads/0-Sky-Link-1.9.0-universal.ipa",
    ]
    run(command, timeout=3600, log_file=run_dir / "components.log")


def filza_current(target: dict[str, Any], identity: Path) -> dict[str, Any]:
    """Return metadata for reviewed Filza in either durable registration."""
    info = app_info(target, identity, FILZA_BUNDLE_ID)
    path = str(info.get("path", ""))
    expected_mount = (
        "/private/var/run/com.apple.security.cryptexd/mnt/"
        + FILZA_CRYPTEX_ID
        + "."
    )
    mcm_prefix = "/private/var/containers/Bundle/Application/"
    if (
        info.get("version") != FILZA_VERSION
        or not (path.startswith(expected_mount) or path.startswith(mcm_prefix))
    ):
        return {}
    probe = remote(
        target,
        identity,
        "test -f " + shlex.quote(path + "/Info.plist")
        + " && test -x " + shlex.quote(path + "/Filza"),
        check=False,
        capture=True,
        timeout=20,
    )
    return info if probe.returncode == 0 else {}


def install_filza(python: Path, target: dict[str, Any], identity: Path,
                  run_dir: Path) -> dict[str, Any]:
    """Install and register the last post-reboot-validated Filza 4.0 DMG."""
    filza = KIT / "filza"
    command = [
        python,
        filza / "install_cryptex_native.py",
        FILZA_CRYPTEX_ID,
        filza / "Filza-4.0-permanent.dmg",
        filza / "Filza-4.0-permanent.trustcache.im4p",
        filza / "Filza-4.0-permanent.volume-hash",
        FILZA_CRYPTEX_VERSION,
        target["udid"],
        filza / "BuildManifest.plist",
    ]
    run(command, timeout=960, log_file=run_dir / "filza-install.log")

    register = r'''import pathlib,subprocess
root=pathlib.Path("/private/var/run/com.apple.security.cryptexd/mnt")
prefix="codes.rambo.research.filza.permanent."
candidates=[]
for mount in root.glob(prefix+"*"):
 app=mount/"Applications/FilzaFixed.6907.app"
 if (app/"Info.plist").is_file() and (app/"Filza").is_file():
  candidates.append(app)
if not candidates: raise SystemExit("mounted Filza payload not found after Cryptex install")
app=max(candidates,key=lambda p:p.parent.parent.stat().st_mtime)
subprocess.run(["/var/jb/usr/bin/uicache","-p",str(app)],check=True)
print(app)'''
    remote(
        target,
        identity,
        "/var/jb/usr/bin/python3 -c " + shlex.quote(register),
        timeout=120,
        log_file=run_dir / "filza-registration.log",
    )
    info = filza_current(target, identity)
    if not info:
        raise PoCError(
            "Filza Cryptex installed but the exact mounted Filza 4.0 app did not "
            "pass LaunchServices and executable verification"
        )
    return info


def pair_remotexpc(python: Path, run_dir: Path) -> None:
    log("RemoteXPC pairing fallback selected. On the SRD open Settings > Developer > Paired Macs, select this Mac, and enter the displayed code.")
    run([python, "-m", "pymobiledevice3", "remote", "pair-host",
         "--name", "0-Sky SRD Research Mac", "--timeout", "180"],
        timeout=210, log_file=run_dir / "remote-pairing.log")


def enforcement_report(error: BaseException) -> str:
    text = str(error).lower()
    if any(marker in text for marker in ("pair", "lockdown", "trust", "remotexpc", "tunnel")):
        component = "Lockdown/remotepairingd/RemoteXPC"
        mechanism = "Developer Mode, exact-UDID USB trust, and Paired Macs authorization"
        required = "Unlock target, accept Trust, and approve this Mac under Settings > Developer > Paired Macs"
    elif any(marker in text for marker in ("permission", "denied", "tss", "nonce", "cryptex")):
        component = "cryptexd/TSS/AMFI"
        mechanism = "Research nonce, ticket personalization, and trust-cache validation"
        required = "Authorized SRD research personalization; no retail-device bypass"
    else:
        component = "0-Sky host orchestration or device package/runtime layer"
        mechanism = "Fail-closed exact-UDID stage validation"
        required = "Review the preserved per-stage log and repair the supported dependency"
    return (f"ENFORCING_COMPONENT={component}\nENFORCEMENT_MECHANISM={mechanism}\n"
            "FIRST_FAILING_TRANSITION=See last completed stage in the run report\n"
            f"REQUIRED_AUTHORIZATION_OR_ENTITLEMENT={required}\n"
            "SUPPORTED_RESEARCH_PATH=Lockdown + RemoteXPC Cryptex personalization + exact-UDID root SSH + paired Mac worker\n"
            "UNSUPPORTED_BYPASS_REQUIRED=NO")


def begin_stage(report: dict[str, Any], name: str) -> None:
    report["stages"].append(name)
    log(f"stage started: {name}")


def process_target(python: Path, target: dict[str, Any], args: argparse.Namespace,
                   root_run: Path) -> dict:
    run_dir = root_run / target["instance"]
    run_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"target": target, "started_at": dt.datetime.now(dt.timezone.utc).isoformat(), "stages": []}
    state = STATE_ROOT / target["instance"] / "srdssh"
    bootstrap = [
        python, KIT / "srdssh/bootstrap.py", "--kit", KIT / "srdssh",
        "--udid", target["udid"], "--identity", args.identity,
        "--port", str(target["port"]), "--state", state,
    ]
    if args.check:
        bootstrap.append("--check")
    if args.no_reboot:
        bootstrap.append("--no-reboot")
    if args.force_dropbear:
        bootstrap.append("--force-srdssh")
    if args.ticket_cache is not None:
        bootstrap += ["--ticket-cache", args.ticket_cache]
    if args.require_cached_ticket:
        bootstrap.append("--require-cached-ticket")
    try:
        if not args.check:
            begin_stage(report, "stage-verified-companion-assets")
            stage_companion_assets(python, target, args.identity, run_dir)
        begin_stage(report, "dropbear-procursus")
        first = run(bootstrap, check=False, capture=True, timeout=1800,
                    log_file=run_dir / "dropbear-procursus.log")
        if first.returncode and args.pair_remotexpc:
            pair_remotexpc(python, run_dir)
            first = run(bootstrap, check=False, capture=True, timeout=1800,
                        log_file=run_dir / "dropbear-procursus-retry.log")
        if first.returncode:
            detail = (first.stdout + first.stderr).decode("utf-8", "replace")
            raise PoCError("Dropbear/Procursus stage failed after supported transport fallbacks:\n" + detail[-6000:])
        if args.check:
            report.update(passed=True, check_only=True)
            return report

        # Fresh Procursus intentionally does not contain an AMFI-admitted
        # Python runtime. Build the first verified runtime generation before
        # appregistrard health or paired-worker checks require Python.
        begin_stage(report, "first-python-trusted-runtime")
        ensure_first_runtime(python, target, args.identity, run_dir)
        begin_stage(report, "bootstrap-runtime-manager")
        ensure_bootstrap_bridge(target, args.identity, run_dir)

        # Make iOS 26 and iOS 27 converge on the iPhone's durable MCM app
        # container model before any app is repaired or installed. Each
        # registrar image contains srdinstalld from that exact OS build.
        begin_stage(report, "appregistrard-mcm-runtime")
        registrar_ready = ensure_appregistrard_support(
            python, target, args.identity, run_dir
        )

        begin_stage(report, "paired-mac-companion")
        status = bridge_status(target, args.identity)
        healthy = (status.get("paired") is True and
                   status.get("device_udid") == target["udid"] and
                   status.get("connected") is True)
        installed_support = SUPPORT / "instances" / target["instance"]
        current_manifest = sha256(KIT / "SHA256SUMS")
        try:
            installed_config = json.loads(
                (installed_support / "config.json").read_text()
            )
        except Exception:
            installed_config = {}
        companion_ready = (
            (installed_support / "config.json").is_file()
            and (installed_support / "host-mac/bootstrap_device.py").is_file()
            and (
                installed_support
                / "automation/artifacts/srd-runtime-poc/build"
            ).is_dir()
            and installed_config.get("source_manifest_sha256") == current_manifest
            and (installed_support / ".install-complete").is_file()
            and (installed_support / ".install-complete").read_text().strip()
            == current_manifest
        )
        if not healthy or not companion_ready or args.repair_pairing:
            setup_companion(python, target, args.identity, run_dir, args.repair_pairing)
            # launchd starts the Mac supervisor immediately, but its first
            # exact-UDID SSH round trip and the device-side HTTP listener can
            # take several seconds on a newly bootstrapped device.
            for _ in range(12):
                time.sleep(3)
                status = bridge_status(target, args.identity)
                healthy = (status.get("paired") is True and
                           status.get("device_udid") == target["udid"] and
                           status.get("connected") is True)
                if healthy:
                    break
        if not healthy:
            raise PoCError("paired privileged bridge did not prove the exact device: " + json.dumps(status))

        # Component health does not imply that the persistence manager itself
        # is current. Upgrade it independently so both MCM-backed iPhones and
        # Cryptex-backed iPads run the same reviewed registration repair.
        ensure_bootstrap_bridge(target, args.identity, run_dir)
        time.sleep(3)

        begin_stage(report, "frida-17.18.0-runtime")
        ensure_frida_runtime(python, target, args.identity, run_dir)

        begin_stage(report, "repair-mounted-app-registrations")
        repair_mounted_app_registrations(target, args.identity, run_dir)

        begin_stage(report, "catvnc-commissary-zerosky")
        if args.force_components or not direct_components_current(target, args.identity):
            bootstrap_components(python, target, args.identity, run_dir)
        else:
            log(f"{target['instance']}: latest CatVNC 0.0.2, 0-Sky Control 3.4.4, and 0-Sky Link 1.9.0 already present; preserving them")

        begin_stage(report, "filza-4.0-cryptex")
        filza = filza_current(target, args.identity)
        if args.force_components or args.force_filza or not filza:
            filza = install_filza(python, target, args.identity, run_dir)
        else:
            log(
                f"{target['instance']}: reviewed Filza 4.0 Cryptex already "
                "mounted and registered; preserving it"
            )

        final = {
            "bridge": bridge_status(target, args.identity),
            "appregistrard_mcm_runtime": registrar_ready,
            "appregistrard_status": appregistrard_status(target, args.identity),
            "catvnc": package_version(target, args.identity, "com.catvnc.server"),
            "commissary": app_info(target, args.identity, "com.liquidsky.CrypStore"),
            "zero_sky": app_info(target, args.identity, "codes.liquidsky.research.zerosky"),
            "filza": filza,
            "frida": remote(
                target, args.identity, "/var/jb/usr/sbin/frida-server --version",
                check=False, capture=True, timeout=20,
            ).stdout.decode().strip(),
        }
        mcm_prefix = "/private/var/containers/Bundle/Application/"
        mcm_parity = all(
            str(final[name].get("path", "")).startswith(mcm_prefix)
            for name in ("commissary", "zero_sky", "filza")
        )
        final["mcm_registration_parity"] = mcm_parity
        passed = (final["catvnc"] == "0.0.2" and
                  final["commissary"].get("version") == "3.4.4" and
                  final["zero_sky"].get("version") == "1.9.0" and
                  final["filza"].get("version") == FILZA_VERSION and
                  final["frida"] == "17.18.0" and
                  final["bridge"].get("paired") is True and
                  (not registrar_ready or mcm_parity))
        report.update(final=final, passed=passed)
        if not passed:
            raise PoCError("post-install version/pairing gate failed: " + json.dumps(final))
        return report
    except Exception as error:
        report.update(passed=False, error=f"{type(error).__name__}: {error}",
                      enforcement=enforcement_report(error))
        raise
    finally:
        report["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        (run_dir / "result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, help="per-user configuration file (default: ~/Library/Application Support/0-Sky/user-config.json)")
    p.add_argument("--init-config", action="store_true", help="create or refresh secure configuration for the current macOS user")
    p.add_argument("--print-config", action="store_true", help="print the effective per-user configuration and exit")
    p.add_argument("--support", type=Path, help="override the per-user support directory")
    p.add_argument("--state-root", type=Path, help="override the per-user state directory")
    p.add_argument("--artifacts-root", type=Path, help="override the per-user run-evidence directory")
    p.add_argument("--venv", type=Path, help="override the per-user Python virtual-environment directory")
    p.add_argument("--udid", action="append", default=[], help="target one exact USB UDID; repeat for several")
    p.add_argument("--list", action="store_true", help="list USB targets and exit")
    p.add_argument("--check", action="store_true", help="read-only kit, Lockdown, RemoteXPC, nonce, and TSS checks")
    p.add_argument("--setup", action="store_true", help="create the pinned local Python environment if missing")
    p.add_argument("--identity", type=Path, help="per-user SRD SSH identity")
    p.add_argument("--base-port", type=int, help="first per-device localhost SSH port")
    p.add_argument(
        "--reuse-port",
        action="store_true",
        help=(
            "reuse --base-port for one explicitly selected target; the "
            "SRDssh stage must still prove authenticated UID 0"
        ),
    )
    p.add_argument("--pair-remotexpc", action="store_true", help="offer iOS 27 Paired Macs code flow after a denial")
    p.add_argument("--repair-pairing", action="store_true", help="reissue the exact-UDID bridge pairing marker")
    p.add_argument("--force-dropbear", action="store_true", help="replace even a working Dropbear Cryptex")
    p.add_argument("--force-components", action="store_true", help="reinstall CatVNC, 0-Sky Control, 0-Sky Link, and Filza")
    p.add_argument("--force-filza", action="store_true", help="reinstall only the reviewed Filza 4.0 Cryptex")
    p.add_argument("--no-reboot", action="store_true")
    p.add_argument(
        "--ticket-cache", type=Path,
        help=(
            "optional research-nonces archive for the SRDssh stage; entries "
            "remain gated by live exact-UDID img4_chip_rsch=1 validation"
        ),
    )
    p.add_argument(
        "--require-cached-ticket", action="store_true",
        help="fail the SRDssh stage instead of contacting TSS when no exact cache match exists",
    )
    return p


def configure_user(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    """Resolve configuration after argument parsing, before any host mutation."""
    requested = args.config
    config = load_user_config(ROOT, requested)
    overrides: dict[str, Any] = {"paths": {}, "defaults": {}}
    paths = overrides["paths"]
    if args.support is not None:
        support = args.support.expanduser().resolve()
        paths.update({
            "support": str(support),
            "state": str(args.state_root.expanduser().resolve()) if args.state_root else str(support / "state"),
            "artifacts": str(args.artifacts_root.expanduser().resolve()) if args.artifacts_root else str(support / "artifacts"),
            "venv": str(args.venv.expanduser().resolve()) if args.venv else str(support / "venv"),
        })
    else:
        if args.state_root is not None:
            paths["state"] = str(args.state_root.expanduser().resolve())
        if args.artifacts_root is not None:
            paths["artifacts"] = str(args.artifacts_root.expanduser().resolve())
        if args.venv is not None:
            paths["venv"] = str(args.venv.expanduser().resolve())
    if args.identity is not None:
        paths["ssh_identity"] = str(args.identity.expanduser().resolve())
    if args.base_port is not None:
        overrides["defaults"]["base_port"] = args.base_port
    if paths:
        config["paths"].update(paths)
    if overrides["defaults"]:
        config["defaults"].update(overrides["defaults"])
    if args.init_config or args.setup:
        path, _ = write_user_config(ROOT, requested, overrides)
        # Environment variables are process-scoped overrides and are never
        # silently persisted, but they must still affect this setup run.
        config = load_user_config(ROOT, requested)
    else:
        path = user_config_path(requested)

    global USER_CONFIG, SUPPORT, ARTIFACTS, STATE_ROOT, IDENTITY_DEFAULT
    USER_CONFIG = config
    SUPPORT = Path(config["paths"]["support"])
    ARTIFACTS = Path(config["paths"]["artifacts"])
    STATE_ROOT = Path(config["paths"]["state"])
    IDENTITY_DEFAULT = Path(config["paths"]["ssh_identity"])
    args.identity = IDENTITY_DEFAULT
    args.base_port = int(config["defaults"]["base_port"])
    return path, config


def main() -> int:
    args = parser().parse_args()
    config_file, config = configure_user(args)
    config_only = not any((
        args.setup, args.list, args.check, args.udid, args.repair_pairing,
        args.force_dropbear, args.force_components, args.force_filza,
    ))
    if args.init_config:
        log(f"per-user configuration: {config_file}")
    if args.print_config or (args.init_config and config_only):
        print(json.dumps(public_user_config(config, config_file), indent=2, sort_keys=True))
        return 0
    if sys.platform != "darwin":
        raise PoCError("this PoC requires macOS and Apple SRD host services")
    args.identity = args.identity.expanduser().resolve()
    if args.require_cached_ticket and args.ticket_cache is None:
        raise PoCError("--require-cached-ticket requires --ticket-cache")
    if args.ticket_cache is not None:
        args.ticket_cache = args.ticket_cache.expanduser().resolve()
        if not args.ticket_cache.is_dir():
            raise PoCError(f"ticket cache is not a directory: {args.ticket_cache}")
    if not args.identity.is_file() and not args.check:
        args.identity.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
             "0-Sky authorized SRD", "-f", args.identity])
        args.identity.chmod(0o600)
    if args.identity.is_file() and args.identity.stat().st_mode & 0o077:
        raise PoCError(f"SSH identity permissions must be 0600: {args.identity}")
    python = select_python(args.setup)
    if python.resolve() != Path(sys.executable).resolve():
        os.execv(str(python), [str(python), str(Path(__file__).resolve()), *sys.argv[1:]])
    verify_manifest()
    devices = asyncio.run(usb_inventory())
    if args.list:
        print(json.dumps(devices, indent=2, sort_keys=True))
        return 0
    if not devices:
        raise PoCError("no USB-connected Apple device is visible")
    targets = assign_targets(devices, args.udid, args.base_port)
    if args.reuse_port:
        if len(targets) != 1 or len(args.udid) != 1:
            raise PoCError("--reuse-port requires exactly one explicit --udid")
        # The parent SRDssh workflow already bound this listener to the exact
        # usbmux UDID. Do not allocate a second port merely because it is busy;
        # srdssh/bootstrap.py independently authenticates the caller-owned key
        # and measures uid=0 before this handoff can mutate the target.
        targets[0]["port"] = args.base_port
    root_run = ARTIFACTS / ("run-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    root_run.mkdir(parents=True, exist_ok=False)
    summary = {"schema": 1, "authorized_srd_only": True, "targets": [],
               "kit_manifest_sha256": sha256(KIT / "SHA256SUMS")}
    failures = 0
    for target in targets:
        log(f"target {target['instance']}: {target['udid']} {target['product_type']} iOS {target['product_version']} on localhost:{target['port']}")
        try:
            major = int(str(target["product_version"]).split(".", 1)[0])
            if major < 17:
                raise PoCError("RemoteXPC Cryptex delivery requires iOS 17 or later")
            result = process_target(python, target, args, root_run)
        except Exception as error:
            failures += 1
            result = {"target": target, "passed": False, "error": str(error),
                      "enforcement": enforcement_report(error)}
            print("\n" + result["enforcement"], file=sys.stderr)
        summary["targets"].append(result)
    summary["passed"] = failures == 0
    (root_run / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    log(f"run evidence: {root_run}")
    return 0 if failures == 0 else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PoCError, UserConfigError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(f"[0-Sky Link] FAILED: {error}", file=sys.stderr)
        print(enforcement_report(error), file=sys.stderr)
        raise SystemExit(2)
