#!/var/jb/usr/bin/python3
"""Loopback-only, authenticated broker for fixed TrollStore Lite operations."""
import base64, crypt, hashlib, hmac, json, os, pathlib, plistlib, re, shutil, stat, subprocess, sys, threading, time, uuid, zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# In the installed package zero_sky_core is adjacent to this script.  In the
# source tree it lives beside the existing runtime-manager implementation.
_HERE = pathlib.Path(__file__).resolve().parent
for _candidate in (_HERE, _HERE.parent / "tools/srd-runtime-manager"):
    if (_candidate / "zero_sky_core").is_dir() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from zero_sky_core import CoreRuntime

HOST, PORT = "127.0.0.1", 48654
TOKEN_FILE = "/var/jb/etc/trollstorelite-srd-bridge.token"
HELPER = "/var/jb/usr/local/libexec/trollstorehelper-srd"
APPREGISTRARD = "/var/jb/usr/local/libexec/appregistrard-srd"
LOG = "/var/jb/var/log/trollstorelite-srd-bridge.log"
SPOOL = "/var/jb/var/spool/crypstore/jobs"
WORKER_HEARTBEAT = "/var/jb/var/run/crypstore-worker.json"
PAIRING_FILE = "/var/jb/var/lib/0-sky/pairing.json"
ACCOUNT_PASSWORD_FILE = "/var/jb/etc/0-sky-passwords"
AUTHORIZED_KEYS = ("/var/jb/var/root/.ssh/authorized_keys", "/var/root/.ssh/authorized_keys")
SRDSH_MOUNT_ROOT = "/private/var/run/com.apple.security.cryptexd/mnt"
APPCTL = "/var/jb/usr/local/libexec/crypstore-appctl.py"
RUNTIME_MANAGER = "/var/jb/usr/local/libexec/srd-runtime-manager.py"
RUNTIME_STATE_DIR = "/var/jb/var/lib/srd-runtime"
GERANIUM_BUNDLE_ID = "live.cclerc.geranium"
MAX_BODY, MAX_OUTPUT = 64 * 1024, 1024 * 1024
MAX_DEB_SIZE = 512 * 1024 * 1024
MAX_APP_BUNDLE_FILES = 100_000
MAX_APP_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024
PAIRING_PROTOCOL_VERSION = 1
# 0-Sky Control is registered as a system app by this PoC, so Foundation resolves
# NSDocumentDirectory to /var/mobile/Documents instead of its MCM data
# container.  Keep exports confined to a single, purpose-specific directory
# rather than granting the broker write access to all of /var/mobile/Documents.
EXPORT_ROOTS = (
    "/var/mobile/Documents/Commissary Exports/",
    "/private/var/mobile/Documents/Commissary Exports/",
    # Depending on how LaunchServices registered 0-Sky Control, Foundation can
    # return either its legacy bundle-keyed Documents container or the
    # elevated process temporary directory for NSDocumentDirectory.  Approve
    # only the dedicated Commissary Exports child, never the surrounding tree.
    "/var/mobile/Library/Application Support/Containers/com.liquidsky.CrypStore/Documents/Commissary Exports/",
    "/private/var/mobile/Library/Application Support/Containers/com.liquidsky.CrypStore/Documents/Commissary Exports/",
    "/var/mobile/tmp/Commissary Exports/",
    "/private/var/mobile/tmp/Commissary Exports/",
    "/var/mobile/Containers/Data/Application/",
    "/private/var/mobile/Containers/Data/Application/",
)
LOCK = threading.Lock()
CORE_LOCK = threading.Lock()
_CORE_RUNTIME = None
BUNDLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
ENV = {
    "PATH": "/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin",
    "HOME": "/var/jb/var/root", "TMPDIR": "/var/jb/var/tmp", "LANG": "C.UTF-8",
    "SILEO": "1", "CYDIA": "1", "DEBIAN_FRONTEND": "noninteractive",
    "APT_LISTCHANGES_FRONTEND": "none",
}

PAIRING_USER_MESSAGES = {
    "MAC_NOT_FOUND": "Open 0-Sky on the Mac; discovery will continue automatically",
    "NO_MAC": "Open 0-Sky on the Mac; discovery will continue automatically",
    "BRIDGE_NOT_RUNNING": "Open 0-Sky on the Mac; the per-user bridge starts automatically",
    "USB_NOT_CONNECTED": "Connect this iPhone or iPad to the Mac by USB",
    "NO_USB_DEVICE": "Connect this iPhone or iPad to the Mac by USB",
    "MULTIPLE_DEVICES": "Choose the intended device in the 0-Sky Mac device selector",
    "DEVICE_LOCKED": "Unlock this iPhone or iPad to continue pairing",
    "TRUST_REQUIRED": "Unlock the device, tap Trust in Apple's dialog, and enter the passcode if requested",
    "TRUST_DENIED": "Trust was not granted; reconnect and choose Pair / Verify Trusted Mac to retry",
    "PAIR_REQUEST_FAILED": "Apple pairing could not be requested; reconnect the selected device and retry",
    "PAIRING_FAILED": "Apple pairing could not be completed; reconnect the selected device and retry",
    "PAIR_RECORD_STALE": "The saved relationship is stale; choose Repair Trusted Mac Pairing",
    "PAIR_RECORD_INVALID": "The saved relationship is stale; choose Repair Trusted Mac Pairing",
    "LOCKDOWN_VALIDATION_FAILED": "Apple's trusted session could not be verified; unlock and reconnect the device",
    "DEVICE_IDENTITY_MISMATCH": "The responding device is not the selected device; reconnect the intended device",
    "IDENTITY_MISMATCH": "The responding device is not the selected device; reconnect the intended device",
    "HOST_IDENTITY_MISMATCH": "The discovered Mac identity does not match the enrolled trusted Mac",
    "REMOTE_SERVICE_UNAVAILABLE": "Trusted pairing is available, but Apple remote services are not currently reachable",
    "BACKEND_UNAVAILABLE": "The Mac Apple-device backend is unavailable; open or repair 0-Sky on the Mac",
    "BACKEND_VERSION_MISMATCH": "Update the 0-Sky Mac Bridge and device applications together",
    "PROTOCOL_VERSION_MISMATCH": "0-Sky Link and Mac Bridge must be updated together",
    "HOST_ENROLLMENT_REQUIRED": "Review and confirm the discovered 0-Sky Mac identity",
    "TIMEOUT": "The operation timed out without changing existing trust; reconnect and retry",
    "CANCELLED": "Pairing was cancelled; existing Apple trust was not changed",
    "TRANSPORT_FAILED": "The selected USB transport was interrupted; reconnect the device and retry",
    "VERIFICATION_FAILED": "Trusted Mac verification failed; review Advanced Diagnostics and retry",
}

class RequestError(Exception): pass


def core_runtime():
    global _CORE_RUNTIME
    with CORE_LOCK:
        if _CORE_RUNTIME is None:
            # The runtime manager owns collection.  The bridge shares the same
            # database for bounded reads and must not duplicate sensor work.
            _CORE_RUNTIME = CoreRuntime(telemetry_owner=False)
            _CORE_RUNTIME.start()
        return _CORE_RUNTIME


def journal_change(action, target, previous=None, current=None,
                   reversible=False, transaction_id=None):
    """Journal a completed mutation without making storage failure destructive."""
    try:
        core_runtime().record_change(
            "PACKAGE", action, target, previous, current,
            reversible=reversible, transaction_id=transaction_id)
    except Exception as error:
        try:
            with open(LOG, "a", encoding="utf-8") as stream:
                stream.write(json.dumps({"core_journal_error": repr(error),
                                         "action": action, "target": target}) + "\n")
        except OSError:
            pass

def inside(path, roots, must_exist=False, allow_directory=False):
    if not isinstance(path, str) or not path.startswith(roots):
        raise RequestError("path is outside an approved container")
    resolved = os.path.realpath(path)
    if not resolved.startswith(roots):
        raise RequestError("path escapes an approved container")
    if must_exist and not (os.path.isfile(resolved) or
                           (allow_directory and os.path.isdir(resolved))):
        raise RequestError("input file is missing")
    return path


def set_device_account_password(payload, password_file=ACCOUNT_PASSWORD_FILE):
    """Atomically store a salted SSH password hash for root or mobile.

    The cleartext password is accepted only in the authenticated loopback
    request body. It is never placed in argv, written to a log, or persisted.
    SRDsh Dropbear reads this root-owned override file for new connections and
    falls back to the sealed system account database when no override exists.
    """
    if not isinstance(payload, dict) or set(payload) != {"account", "password"}:
        raise RequestError("invalid account-password request")
    account, password = payload.get("account"), payload.get("password")
    if account not in ("root", "mobile") or not isinstance(password, str):
        raise RequestError("invalid account-password request")
    encoded = password.encode("utf-8")
    if (len(encoded) < 8 or len(encoded) > 128 or
            any(character in password for character in ("\0", "\r", "\n"))):
        raise RequestError("password must be 8-128 UTF-8 bytes without line breaks")

    password_hash = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    if not password_hash or not password_hash.startswith("$6$"):
        raise RuntimeError("unable to create SHA-512 password hash")

    entries = {}
    try:
        info = os.lstat(password_file)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o077 or info.st_size > 4096):
            raise RequestError("existing account-password file failed security checks")
        with open(password_file, "r", encoding="ascii") as stream:
            for line in stream:
                name, separator, value = line.rstrip("\n").partition(":")
                if (separator and name in ("root", "mobile") and
                        value.startswith("$6$") and len(value) <= 512):
                    entries[name] = value
    except FileNotFoundError:
        pass

    entries[account] = password_hash
    content = "".join(f"{name}:{entries[name]}\n"
                      for name in ("root", "mobile") if name in entries).encode("ascii")
    directory = os.path.dirname(password_file)
    os.makedirs(directory, mode=0o755, exist_ok=True)
    temporary = password_file + f".tmp.{os.getpid()}.{threading.get_ident()}"
    descriptor = os.open(temporary,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o600)
        os.replace(temporary, password_file)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return {"status": 0, "stdout": f"{account} SSH password updated", "stderr": ""}

def validate(arguments):
    if (not isinstance(arguments, list) or not arguments or len(arguments) > 8 or
            not all(isinstance(x, str) and "\0" not in x and len(x) <= 4096 for x in arguments)):
        raise RequestError("invalid arguments")
    a = list(arguments); cmd = a[0]
    if cmd == "install":
        if len(a) < 2 or len(a) > 4 or any(x not in ("force", "custom", "installd", "skip-uicache") for x in a[1:-1]):
            raise RequestError("invalid install options")
        # UIDocumentPicker may return an app-container temporary URL, an app
        # group URL, or an iCloud/Mobile Documents URL. All are confined to
        # the mobile user's tree; realpath checking still prevents escapes.
        inside(a[-1], ("/var/mobile/", "/private/var/mobile/"), True)
    elif cmd == "install-deb":
        if len(a) != 2 or not a[-1].lower().endswith(".deb"):
            raise RequestError("invalid Debian package request")
        path = inside(a[-1], ("/var/mobile/", "/private/var/mobile/"), True)
        size = os.path.getsize(os.path.realpath(path))
        if size < 64 or size > MAX_DEB_SIZE:
            raise RequestError("Debian package size is outside the allowed range")
    elif cmd == "install-app-bundle":
        if len(a) != 2 or not a[-1].lower().endswith(".app"):
            raise RequestError("invalid app bundle request")
        path = inside(a[-1], ("/var/mobile/", "/private/var/mobile/"), True,
                      allow_directory=True)
        if not os.path.isdir(os.path.realpath(path)):
            raise RequestError("selected app bundle is not a directory")
    elif cmd == "export-app":
        if len(a) != 3 or not a[1].lower().endswith(".app") or not a[2].lower().endswith(".ipa"):
            raise RequestError("invalid app export request")
        source = inside(a[1], (
            "/var/containers/Bundle/Application/",
            "/private/var/containers/Bundle/Application/",
            "/var/jb/Applications/", "/private/var/jb/Applications/",
            "/var/run/com.apple.security.cryptexd/mnt/",
            "/private/var/run/com.apple.security.cryptexd/mnt/",
        ), True, allow_directory=True)
        if not os.path.isdir(os.path.realpath(source)):
            raise RequestError("selected app bundle is not a directory")
        destination = inside(a[2], EXPORT_ROOTS)
        if os.path.isdir(os.path.realpath(destination)):
            raise RequestError("app export destination is a directory")
    elif cmd == "export-app-deb":
        if len(a) != 3 or not a[1].lower().endswith(".app") or not a[2].lower().endswith(".deb"):
            raise RequestError("invalid app Debian export request")
        source = inside(a[1], (
            "/var/containers/Bundle/Application/",
            "/private/var/containers/Bundle/Application/",
            "/var/jb/Applications/", "/private/var/jb/Applications/",
            "/var/run/com.apple.security.cryptexd/mnt/",
            "/private/var/run/com.apple.security.cryptexd/mnt/",
        ), True, allow_directory=True)
        if not os.path.isdir(os.path.realpath(source)):
            raise RequestError("selected app bundle is not a directory")
        inside(a[2], EXPORT_ROOTS)
    elif cmd == "export-package":
        if len(a) != 3 or not BUNDLE_ID.fullmatch(a[1]) or not a[2].lower().endswith(".deb"):
            raise RequestError("invalid installed-package export request")
        inside(a[2], EXPORT_ROOTS)
    elif cmd == "repair-preferences":
        if len(a) not in (1, 2) or (len(a) == 2 and not BUNDLE_ID.fullmatch(a[1])):
            raise RequestError("invalid preference-repair request")
    elif cmd == "uninstall":
        if len(a) not in (2, 3) or any(x not in ("custom", "installd") for x in a[1:-1]) or not BUNDLE_ID.fullmatch(a[-1]):
            raise RequestError("invalid uninstall request")
    elif cmd == "uninstall-path":
        if len(a) not in (2, 3) or any(x not in ("custom", "installd") for x in a[1:-1]):
            raise RequestError("invalid uninstall-path options")
        inside(a[-1], ("/var/containers/Bundle/Application/", "/private/var/containers/Bundle/Application/"))
    elif cmd == "remove-package":
        if len(a) != 2 or not BUNDLE_ID.fullmatch(a[1]):
            raise RequestError("invalid package removal request")
    elif cmd in ("refresh", "refresh-all", "transfer-apps", "reboot"):
        if len(a) != 1: raise RequestError("unexpected arguments")
    elif cmd == "url-scheme":
        if len(a) != 2 or a[1] not in ("enable", "disable"): raise RequestError("invalid URL scheme state")
    elif cmd == "enable-jit":
        if len(a) != 2 or not BUNDLE_ID.fullmatch(a[1]): raise RequestError("invalid bundle identifier")
    elif cmd == "modify-registration":
        if len(a) != 3 or a[2] not in ("User", "System"): raise RequestError("invalid registration request")
        inside(a[1], ("/var/containers/Bundle/Application/", "/private/var/containers/Bundle/Application/"))
    elif cmd == "check-dev-mode":
        if len(a) != 1: raise RequestError("unexpected arguments")
    else:
        raise RequestError("operation is not approved")
    return a


GERANIUM_PATH_ROOTS = (
    "/var/mobile/Library/Logs/", "/var/mobile/Library/Caches/",
    "/var/mobile/Library/Mail/", "/var/mobile/Library/Preferences/",
    "/var/mobile/Media/PhotoData/", "/var/mobile/Containers/Data/Application/",
    "/var/mobile/Documents/", "/var/log/", "/var/logs/", "/var/tmp/",
    "/var/MobileSoftwareUpdate/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate/",
)
GERANIUM_EXACT_PATHS = {
    "/var/db/com.apple.xpc.launchd/disabled.plist",
    "/var/db/com.apple.xpc.launchd/disabled.migrated",
}


def validate_geranium_path(value):
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise RequestError("Geranium requested an invalid path")
    normalized = os.path.normpath(value)
    canonical = "/var/" + normalized[len("/private/var/"):] if normalized.startswith("/private/var/") else normalized
    approved = canonical in GERANIUM_EXACT_PATHS or any(
        canonical == root.rstrip("/") or canonical.startswith(root)
        for root in GERANIUM_PATH_ROOTS)
    if not approved:
        raise RequestError("Geranium path is outside the approved research scope")
    resolved = os.path.realpath(normalized)
    resolved_canonical = "/var/" + resolved[len("/private/var/"):] if resolved.startswith("/private/var/") else resolved
    resolved_approved = resolved_canonical in GERANIUM_EXACT_PATHS or any(
        resolved_canonical == root.rstrip("/") or resolved_canonical.startswith(root)
        for root in GERANIUM_PATH_ROOTS)
    if not resolved_approved:
        raise RequestError("Geranium path escapes the approved research scope")
    return canonical


def validate_geranium(arguments):
    if (not isinstance(arguments, list) or len(arguments) != 3 or
            not all(isinstance(item, str) and "\0" not in item for item in arguments)):
        raise RequestError("invalid Geranium arguments")
    action, source, destination = arguments
    if action == "writedata":
        if len(source.encode("utf-8")) > 4 * 1024 * 1024:
            raise RequestError("Geranium write payload is too large")
        validate_geranium_path(destination)
    elif action in ("filemove", "filecopy"):
        validate_geranium_path(source)
        validate_geranium_path(destination)
    elif action in ("makedirectory", "removeitem", "permissionset"):
        validate_geranium_path(source)
        if destination:
            raise RequestError("unexpected Geranium destination")
    elif action == "daemonperm":
        if validate_geranium_path(source) not in GERANIUM_EXACT_PATHS:
            raise RequestError("daemon permissions are limited to launchd policy files")
        if destination:
            raise RequestError("unexpected Geranium destination")
    elif action == "rebuildiconcache":
        if source or destination:
            raise RequestError("unexpected icon-cache arguments")
    else:
        raise RequestError("Geranium operation is not approved")
    return list(arguments)


def geranium_helper():
    listing = subprocess.run(["/var/jb/usr/bin/uicache", "-l"], env=ENV,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=30, check=False).stdout.decode("utf-8", "replace")
    prefix = GERANIUM_BUNDLE_ID + " : "
    paths = [line[len(prefix):].strip() for line in listing.splitlines()
             if line.startswith(prefix)]
    if len(paths) != 1:
        raise RequestError("Geranium must have exactly one registered bundle")
    app = os.path.realpath(paths[0])
    if not app.startswith(("/private/var/containers/Bundle/Application/",
                           "/var/containers/Bundle/Application/")):
        raise RequestError("Geranium is outside an app container")
    try:
        with open(os.path.join(app, "Info.plist"), "rb") as handle:
            if plistlib.load(handle).get("CFBundleIdentifier") != GERANIUM_BUNDLE_ID:
                raise RequestError("Geranium bundle identity mismatch")
    except RequestError:
        raise
    except Exception as error:
        raise RequestError(f"Geranium bundle metadata is unavailable: {error}")
    helper = os.path.join(app, "GeraniumRootHelper")
    if not os.access(helper, os.X_OK):
        raise RequestError("Geranium root helper is unavailable")
    return helper


def run_geranium(arguments):
    args = validate_geranium(arguments)
    started = time.monotonic()
    completed = subprocess.run([geranium_helper()] + args, cwd="/var/jb/var/tmp",
        env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=180, check=False)
    result = {"status": completed.returncode,
              "stdout": completed.stdout.decode("utf-8", "replace")[:MAX_OUTPUT],
              "stderr": completed.stderr.decode("utf-8", "replace")[:MAX_OUTPUT]}
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"geranium_action": args[0],
            "status": completed.returncode,
            "duration_ms": int((time.monotonic() - started) * 1000)}) + "\n")
    return result

def token():
    with open(TOKEN_FILE, "r", encoding="ascii") as f: return f.read().strip()


def bridge_ready():
    """Report the active Lite broker boundary, not the optional legacy helper.

    0-Sky Control Lite sends its bounded operations to this root loopback process.
    The iOS 26 iPad runtime intentionally does not require the old standalone
    TrollStore helper, while the iOS 27 iPhone may still have it installed.
    """
    try:
        secret = token()
    except OSError:
        return False
    return (os.geteuid() == 0 and len(secret) >= 64 and
            os.access(APPCTL, os.X_OK) and os.path.isfile(RUNTIME_MANAGER))

def atomic_json(path, value):
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as f:
        json.dump(value, f, separators=(",", ":"))
        f.write("\n")
    os.replace(temporary, path)

def worker_status():
    result = {"connected": False, "age_seconds": None, "message": "Mac companion is not connected"}
    try:
        with open(WORKER_HEARTBEAT, "r", encoding="utf-8") as f:
            heartbeat = json.load(f)
        age = max(0, int(time.time()) - int(heartbeat.get("timestamp", 0)))
        result.update({
            "connected": age <= 15,
            "age_seconds": age,
            "message": "Mac companion is ready" if age <= 15 else "Mac companion heartbeat is stale",
            "stage": heartbeat.get("stage", "Ready"),
            "detail": heartbeat.get("detail", ""),
            "job_id": heartbeat.get("job_id"),
            "device_udid": heartbeat.get("device_udid"),
            "host_key_fingerprint": heartbeat.get("host_key_fingerprint"),
            # Forward only the structured, non-secret pairing evidence that
            # the persistent Mac worker intentionally publishes.  Previous
            # code dropped these fields here, which made first enrollment
            # impossible even though the heartbeat contained them.
            "host_name": heartbeat.get("host_name"),
            "bridge_version": heartbeat.get("bridge_version"),
            "protocol_version": heartbeat.get("protocol_version"),
            "device_backend": heartbeat.get("device_backend", "PymobiledeviceBackend"),
            "mac_identity_fingerprint": heartbeat.get("mac_identity_fingerprint"),
            "apple_pairing_verified": bool(heartbeat.get("apple_pairing_verified")),
            "lockdown_session_validated": bool(heartbeat.get("lockdown_session_validated")),
            "host_identity_verified": bool(heartbeat.get("host_identity_verified")),
            "pairing_error": heartbeat.get("pairing_error"),
            "pairing_state": heartbeat.get("pairing_state"),
            "device_info": heartbeat.get("device_info") if isinstance(
                heartbeat.get("device_info"), dict) else {},
            "research_class": heartbeat.get("research_class", "UNKNOWN"),
            "remote_services": heartbeat.get("remote_services") if isinstance(
                heartbeat.get("remote_services"), dict) else None,
            "last_pairing_verified_at": heartbeat.get("last_pairing_verified_at"),
            "transport_type": heartbeat.get("transport_type", "UNAVAILABLE"),
            "wireless_connected": bool(heartbeat.get("wireless_connected")),
            "trust_state": heartbeat.get("trust_state", "UNKNOWN"),
            "transport_state": heartbeat.get("transport_state", "NONE"),
            "session_state": heartbeat.get("session_state", "DISCONNECTED"),
            "usb_available": bool(heartbeat.get("usb_available")),
            "wifi_available": bool(heartbeat.get("wifi_available")),
            "wifi_lockdown_enabled": bool(heartbeat.get("wifi_lockdown_enabled")),
            "wifi_pairing_verified": bool(heartbeat.get("wifi_pairing_verified")),
            "remote_pairing_ready": bool(heartbeat.get("remote_pairing_ready")),
            "wireless_rsd_verified": bool(heartbeat.get("wireless_rsd_verified")),
            "bluetooth_connected": bool(heartbeat.get("bluetooth_connected")),
            "bluetooth_pairing_verified": bool(
                heartbeat.get("bluetooth_pairing_verified")),
        })
    except Exception as error:
        result["message"] = "Trusted Mac evidence is unavailable; retry or open diagnostics"
        result["pairing_error"] = "PAIRING_EVIDENCE_UNAVAILABLE"
        result["developer_diagnostic"] = type(error).__name__
    return result

def authorized_key_paths():
    """Return normal and sealed-SRDssh authorized-key sources.

    The minimal research Cryptex deliberately keeps its actual authorized
    public key inside the signed mount at ``etc/srdsh_authorized_key``.  The
    ordinary root authorized_keys path can therefore be empty even while
    Dropbear correctly accepts the key.  Resolve candidates beneath the
    fixed Cryptex mount root and reject links/escapes rather than weakening
    the first-enrollment identity check.
    """
    result = list(AUTHORIZED_KEYS)
    root = pathlib.Path(SRDSH_MOUNT_ROOT)
    try:
        resolved_root = root.resolve(strict=True)
    except OSError:
        return tuple(result)
    mounts = []
    for pattern in ("com.liquidsky.srdssh.*", "com.jonpalmisc.srdsh.*"):
        mounts.extend(root.glob(pattern))
    for mount in sorted(set(mounts)):
        candidate = mount / "etc/srdsh_authorized_key"
        try:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(resolved_root)
        except (OSError, ValueError):
            continue
        result.append(str(resolved))
    return tuple(dict.fromkeys(result))

def pairing_host_id(value):
    """Return the non-secret stable identifier for one enrolled Mac."""
    host_key = value.get("host_key_fingerprint")
    mac_identity = value.get("mac_identity_fingerprint")
    if not isinstance(host_key, str) or not isinstance(mac_identity, str):
        return None
    return hashlib.sha256((host_key + "\0" + mac_identity).encode()).hexdigest()[:32]


def pairing_status():
    """Verify the host/device binding without exposing either credential."""
    result = {
        "paired": False, "marker_valid": False, "worker_fresh": False,
        "udid_bound": False, "host_key_bound": False,
        "apple_pairing_verified": False, "lockdown_session_validated": False,
        "host_identity_verified": False,
        "usb_pairing_verified": False, "wifi_pairing_verified": False,
        "bluetooth_pairing_verified": False,
        "wifi_lockdown_state": "NOT_CONFIGURED",
        "remote_pairing_state": "NOT_CONFIGURED",
        "wireless_rsd_state": "NOT_CONFIGURED",
        "message": "Connect by USB and choose Pair / Verify Trusted Mac",
    }
    marker = {}
    registry = {}
    enrolled_hosts = {}
    registry_schema = None
    registry_device_udid = None
    marker_error = None
    try:
        with open(PAIRING_FILE, "r", encoding="utf-8") as handle:
            registry = json.load(handle)
        supplied = registry.pop("hmac_sha256", "")
        canonical = json.dumps(registry, sort_keys=True, separators=(",", ":")).encode()
        expected = hmac.new(token().encode(), canonical, "sha256").hexdigest()
        valid = hmac.compare_digest(str(supplied), expected)
        registry_schema = registry.get("schema")
        registry_device_udid = registry.get("device_udid")
        if valid and registry_schema == 1:
            identifier = pairing_host_id(registry)
            valid = bool(identifier and isinstance(registry_device_udid, str))
            if valid:
                enrolled_hosts = {identifier: registry}
        elif valid and registry_schema == 2:
            candidates = registry.get("hosts")
            valid = isinstance(registry_device_udid, str) and isinstance(candidates, dict)
            if valid:
                for identifier, value in candidates.items():
                    if (not isinstance(identifier, str) or len(identifier) != 32
                            or not isinstance(value, dict)
                            or value.get("device_udid") != registry_device_udid
                            or pairing_host_id(value) != identifier):
                        valid = False
                        break
                if valid:
                    enrolled_hosts = candidates
        else:
            valid = False
    except Exception as error:
        valid = False
        marker_error = type(error).__name__

    # Worker discovery is independent of enrollment.  This lets an unpaired
    # device display and explicitly approve the Mac application's public-key
    # fingerprint without treating that advertisement as trust.
    worker = worker_status()
    fresh = bool(worker.get("connected"))
    authorized_fingerprints = set()
    for path in authorized_key_paths():
        try:
            for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
                fields = line.strip().split()
                for index, field in enumerate(fields[:-1]):
                    if field.startswith(("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-")):
                        digest = hashlib.sha256(base64.b64decode(fields[index + 1])).digest()
                        authorized_fingerprints.add("SHA256:" +
                            base64.b64encode(digest).decode().rstrip("="))
                        break
        except (OSError, ValueError, IndexError):
            continue
    worker_host_key_authorized = worker.get("host_key_fingerprint") in authorized_fingerprints
    discovery_authenticated = bool(fresh and worker_host_key_authorized and
                                   worker.get("mac_identity_fingerprint"))
    active_host_id = pairing_host_id(worker) if fresh else None
    if active_host_id and active_host_id in enrolled_hosts:
        marker = enrolled_hosts[active_host_id]
    active_host_enrolled = bool(marker)
    active_marker_valid = bool(valid and (not fresh or active_host_enrolled))
    udid_bound = (isinstance(marker.get("device_udid"), str) and
                  marker.get("device_udid") == worker.get("device_udid"))
    host_bound = (isinstance(marker.get("host_key_fingerprint"), str) and
                  marker.get("host_key_fingerprint") == worker.get("host_key_fingerprint"))
    mac_identity_bound = (isinstance(marker.get("mac_identity_fingerprint"), str) and
        marker.get("mac_identity_fingerprint") == worker.get("mac_identity_fingerprint"))
    apple_verified = bool(worker.get("apple_pairing_verified"))
    lockdown_validated = bool(worker.get("lockdown_session_validated"))
    host_identity_verified = bool(worker.get("host_identity_verified") and mac_identity_bound)
    usb_pairing_verified = bool(apple_verified and lockdown_validated and
                                host_identity_verified)
    wifi_pairing_verified = bool(worker.get("wifi_pairing_verified") and
                                 worker.get("wifi_lockdown_enabled"))
    bluetooth_pairing_verified = bool(worker.get("bluetooth_pairing_verified") and
                                      worker.get("bluetooth_connected") and
                                      worker.get("transport_type") == "BLUETOOTH_TUNNEL")
    worker_protocol = worker.get("protocol_version")
    protocol_compatible = worker_protocol == PAIRING_PROTOCOL_VERSION
    # Trusted-Mac state is an Apple-session and host-identity decision.  Do
    # not silently redefine it as "this device broker happens to run as root";
    # pairing, platform/SRD classification, and privileged-runtime readiness
    # are independent postconditions.  Privileged endpoints still require the
    # separate privileged_bridge_ready gate in pairing_denial().
    paired = bool(active_marker_valid and fresh and worker_host_key_authorized and udid_bound and host_bound and
                  apple_verified and lockdown_validated and host_identity_verified and
                  protocol_compatible)
    # ``paired`` deliberately remains a live authorization decision.  A missed
    # worker heartbeat must revoke privileged requests, but it must not erase a
    # previously verified enrollment from the UI.  The marker is written only
    # after Apple Lockdown, exact-UDID SSH, and the Mac identity have all been
    # verified, and is authenticated with the device-local bridge token.  Keep
    # that durable relationship distinct from the live authorization gate.
    marker_complete = bool(valid and enrolled_hosts)
    live_identity_conflict = bool(fresh and not (
        active_host_enrolled and worker_host_key_authorized and udid_bound and host_bound and
        mac_identity_bound and protocol_compatible))
    relationship_verified = bool(marker_complete and not live_identity_conflict)
    privileged_bridge_ready = bool(paired and os.geteuid() == 0)
    pairing_error = worker.get("pairing_error")
    if (fresh and worker_protocol is not None and
            worker_protocol != PAIRING_PROTOCOL_VERSION):
        pairing_error = "PROTOCOL_VERSION_MISMATCH"
    if paired:
        message = "Trusted Mac verified"
    elif pairing_error in PAIRING_USER_MESSAGES:
        message = PAIRING_USER_MESSAGES[pairing_error]
    elif not fresh:
        message = "0-Sky Mac Bridge is not connected"
    elif not discovery_authenticated:
        message = "0-Sky Mac identity could not be authenticated"
    elif not valid:
        message = "Confirm the discovered 0-Sky Mac to begin enrollment"
    elif not active_host_enrolled:
        message = "This Mac is not enrolled; pair it without removing existing trusted Macs"
    elif not udid_bound:
        message = "The Mac worker is targeting a different device"
    elif not host_bound:
        message = "The connected worker uses a different host key"
    elif not apple_verified or not lockdown_validated:
        message = "Apple pairing requires verification"
    elif not host_identity_verified:
        message = "0-Sky Mac identity does not match enrollment"
    else:
        message = "The bridge is not running as root"
    result.update({
        "paired": paired, "live_verified": paired, "trusted_mac_verified": paired,
        "relationship_verified": relationship_verified,
        "verification_recommended": bool(relationship_verified and not paired),
        "privileged_bridge_ready": privileged_bridge_ready,
        "marker_valid": active_marker_valid, "pairing_registry_valid": valid,
        "pairing_registry_schema": registry_schema,
        "paired_host_count": len(enrolled_hosts),
        "active_host_id": active_host_id,
        "active_host_enrolled": active_host_enrolled,
        "worker_fresh": fresh,
        "bridge_installed": True, "bridge_running": fresh,
        "device_backend": worker.get("device_backend"),
        "mac_discovery_authenticated": discovery_authenticated,
        "worker_host_key_authorized": worker_host_key_authorized,
        "udid_bound": udid_bound, "host_key_bound": host_bound,
        "mac_identity_bound": mac_identity_bound,
        "apple_pairing_verified": apple_verified,
        "lockdown_session_validated": lockdown_validated,
        "host_identity_verified": host_identity_verified,
        "trust_state": worker.get("trust_state", "TRUSTED" if relationship_verified else "UNKNOWN"),
        "transport_state": worker.get("transport_state", "NONE"),
        "session_state": worker.get("session_state", "DISCONNECTED"),
        "usb_available": bool(worker.get("usb_available")),
        "wifi_available": bool(worker.get("wifi_available")),
        "usb_pairing_verified": usb_pairing_verified,
        "wifi_pairing_verified": wifi_pairing_verified,
        "bluetooth_pairing_verified": bluetooth_pairing_verified,
        "bluetooth_connected": bool(worker.get("bluetooth_connected")),
        "bluetooth_state": ("VERIFIED" if bluetooth_pairing_verified else
                            "NOT_CONNECTED"),
        "wifi_lockdown_state": ("VERIFIED" if wifi_pairing_verified else
                                "ENABLED" if worker.get("wifi_lockdown_enabled") else
                                "NOT_CONFIGURED"),
        "remote_pairing_state": ("VERIFIED" if worker.get("remote_pairing_ready") else
                                 "NOT_REQUIRED"),
        "wireless_rsd_state": ("VERIFIED" if worker.get("wireless_rsd_verified") else
                               "PENDING" if worker.get("wifi_lockdown_enabled") else
                               "NOT_CONFIGURED"),
        "pairing_state": worker.get("pairing_state"),
        "pairing_error": pairing_error,
        "transport_type": worker.get("transport_type", "UNAVAILABLE"),
        "wireless_connected": bool(worker.get("wireless_connected")),
        "mac_name": worker.get("host_name"),
        "mac_identity_fingerprint": worker.get("mac_identity_fingerprint"),
        "bridge_version": worker.get("bridge_version"),
        "protocol_version": worker.get("protocol_version"),
        "device": worker.get("device_info", {}),
        "remote_services": worker.get("remote_services"),
        "research_class": worker.get("research_class", "UNKNOWN"),
        "last_verified_at": worker.get("last_pairing_verified_at"),
        "device_udid": marker.get("device_udid") or registry_device_udid,
        "instance_name": marker.get("instance_name"),
        "ssh_port": marker.get("ssh_port"),
        "paired_at": marker.get("paired_at"), "message": message,
        "marker_diagnostic": marker_error,
    })
    return result

def pairing_denial():
    status = pairing_status()
    if status["paired"] and status.get("privileged_bridge_ready"):
        return None
    if status["paired"]:
        return {"status": 126, "stdout": "",
                "errorCode": "BRIDGE_NOT_RUNNING",
                "stderr": "Trusted Mac is verified, but the privileged device bridge is unavailable",
                "pairing": status}
    return {"status": 193, "stdout": "", "stderr": status["message"],
            "pairing": status}


def queue_pair_verify():
    """Queue a bounded pairing request for this instance's exact Mac worker."""
    worker = worker_status()
    if not worker.get("connected"):
        return {"status": 190, "stdout": "", "stderr": "0-Sky Mac Bridge is not connected",
                "errorCode": "BRIDGE_NOT_RUNNING"}
    if worker.get("protocol_version") != PAIRING_PROTOCOL_VERSION:
        return {"status": 191, "stdout": "",
                "stderr": "0-Sky Link and Mac Bridge protocol versions are incompatible",
                "errorCode": "PROTOCOL_VERSION_MISMATCH",
                "expectedProtocol": PAIRING_PROTOCOL_VERSION,
                "receivedProtocol": worker.get("protocol_version")}
    # Pairing is a single device/host operation.  App relaunches and retries
    # previously left multiple processing.json files queued, each of which
    # could spend three minutes waiting for USB removal before the current UI
    # job was reached.  Supersede incomplete older pairing jobs explicitly so
    # the newest authenticated request cannot stall behind abandoned work.
    now = int(time.time())
    try:
        entries = os.listdir(SPOOL)[:512]
    except OSError:
        entries = []
    for prior_id in entries:
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", prior_id):
            continue
        prior_root = os.path.join(SPOOL, prior_id)
        if os.path.isfile(os.path.join(prior_root, "result.json")):
            continue
        request_path = os.path.join(prior_root, "request.json")
        if not os.path.isfile(request_path):
            request_path = os.path.join(prior_root, "processing.json")
        try:
            if os.path.getsize(request_path) > MAX_BODY:
                continue
            with open(request_path, "r", encoding="utf-8") as handle:
                prior = json.load(handle)
            if prior.get("operation") != "pair-verify":
                continue
            atomic_json(os.path.join(prior_root, "cancel.json"),
                        {"cancelled_at": now, "reason": "SUPERSEDED"})
            atomic_json(os.path.join(prior_root, "result.json"), {
                "status": 130, "stdout": "", "errorCode": "SUPERSEDED",
                "stderr": "A newer Wi-Fi pairing verification replaced this request",
            })
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    job_id = str(uuid.uuid4())
    root = os.path.join(SPOOL, job_id)
    os.makedirs(root, mode=0o700, exist_ok=False)
    atomic_json(os.path.join(root, "request.json"), {
        "job_id": job_id, "operation": "pair-verify", "created_at": now,
        "protocol_version": PAIRING_PROTOCOL_VERSION,
    })
    return {"status": 0, "stdout": "Waiting for Apple Trust approval", "stderr": "",
            "job_id": job_id, "state": "WAITING_FOR_TRUST"}

def cancel_pair_verify(job_id):
    """Cancel only the selected pairing operation; never alter trust records."""
    if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", job_id):
        return {"status": 22, "stderr": "invalid pairing operation identifier"}
    root = os.path.join(SPOOL, job_id)
    if not os.path.isdir(root):
        return {"status": 2, "stderr": "pairing operation was not found"}
    atomic_json(os.path.join(root, "cancel.json"), {"cancelled_at": int(time.time())})
    return {"status": 0, "stdout": "Pairing cancellation requested",
            "job_id": job_id, "state": "CANCELLED"}

def pairing_result(job_id):
    """Return the authenticated, structured result for exactly one operation.

    The device UI uses this rather than inferring completion from a global
    heartbeat.  This prevents a stale error from a prior health check from
    being mistaken for the result of the user's current request.
    """
    if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", job_id):
        return {"status": 22, "complete": True,
                "errorCode": "INVALID_OPERATION_ID",
                "stderr": "invalid pairing operation identifier"}
    root = os.path.join(SPOOL, job_id)
    if not os.path.isdir(root):
        return {"status": 2, "complete": True,
                "errorCode": "OPERATION_NOT_FOUND",
                "stderr": "pairing operation was not found"}
    result_path = os.path.join(root, "result.json")
    if not os.path.isfile(result_path):
        state = pairing_status().get("pairing_state") or "QUEUED"
        return {"status": 102, "complete": False, "job_id": job_id,
                "state": state}
    try:
        if os.path.getsize(result_path) > MAX_BODY:
            raise ValueError("pairing result exceeds the bounded response size")
        with open(result_path, "r", encoding="utf-8") as handle:
            result = json.load(handle)
        if not isinstance(result, dict):
            raise ValueError("pairing result is not an object")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return {"status": 74, "complete": True,
                "errorCode": "INVALID_OPERATION_RESULT",
                "stderr": f"pairing result could not be read: {type(error).__name__}"}
    # Explicit allowlist: a future worker cannot accidentally expose a pair
    # record or private credential through this device-facing API.
    safe = {key: result.get(key) for key in (
        "status", "stdout", "stderr", "errorCode", "expectedProtocol",
        "receivedProtocol") if key in result}
    try:
        normalized_status = int(result.get("status", 125))
    except (TypeError, ValueError):
        normalized_status = 125
    safe["status"] = normalized_status
    pair = result.get("pairing")
    if isinstance(pair, dict):
        safe["pairing"] = {key: pair.get(key) for key in (
            "status", "operation", "operationId", "errorCode", "userMessage",
            "safeRemediation", "device", "pairing", "host", "transport",
            "capabilities", "researchClass", "events") if key in pair}
    return {"complete": True, "job_id": job_id, "result": safe,
            "status": normalized_status}

def package_app_bundle(source, destination):
    """Create a bounded IPA from one caller-confined ``.app`` directory.

    Modes and safe bundle-internal symbolic links are preserved.  Following a
    symlink while exporting would permit a crafted bundle to read arbitrary
    root-owned files, so links are represented as links in the ZIP instead.
    """
    source = os.path.realpath(source)
    info_path = os.path.join(source, "Info.plist")
    try:
        with open(info_path, "rb") as handle:
            info = plistlib.load(handle)
    except Exception as error:
        raise RequestError(f"app bundle has no valid Info.plist: {error}")
    executable = info.get("CFBundleExecutable")
    if (not isinstance(executable, str) or not executable or
            os.path.basename(executable) != executable or
            not os.path.isfile(os.path.join(source, executable))):
        raise RequestError("app bundle executable is missing")
    bundle_name = os.path.basename(source)
    if not bundle_name.lower().endswith(".app") or "/" in bundle_name:
        raise RequestError("app bundle name is invalid")
    count = 0
    total = 0

    def add_link(archive, path, relative):
        nonlocal count, total
        target = os.readlink(path)
        if os.path.isabs(target):
            raise RequestError("app bundle contains an absolute symbolic link")
        resolved = os.path.realpath(path)
        if resolved != source and not resolved.startswith(source + os.sep):
            raise RequestError("app bundle symbolic link escapes the selected directory")
        payload = target.encode("utf-8")
        count += 1
        total += len(payload)
        if count > MAX_APP_BUNDLE_FILES or total > MAX_APP_BUNDLE_BYTES:
            raise RequestError("app bundle exceeds the import safety limit")
        member = zipfile.ZipInfo(os.path.join("Payload", bundle_name, relative))
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, payload)

    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED,
                         allowZip64=True) as archive:
        for root, directories, files in os.walk(source):
            directories.sort()
            files.sort()
            for name in list(directories):
                path = os.path.join(root, name)
                if os.path.islink(path):
                    relative = os.path.relpath(path, source)
                    add_link(archive, path, relative)
                    directories.remove(name)
            for name in files:
                path = os.path.join(root, name)
                if os.path.islink(path):
                    add_link(archive, path, os.path.relpath(path, source))
                    continue
                resolved = os.path.realpath(path)
                if not resolved.startswith(source + os.sep):
                    raise RequestError("app bundle file escapes the selected directory")
                count += 1
                total += os.path.getsize(path)
                if count > MAX_APP_BUNDLE_FILES or total > MAX_APP_BUNDLE_BYTES:
                    raise RequestError("app bundle exceeds the import safety limit")
                relative = os.path.relpath(path, source)
                archive.write(path, os.path.join("Payload", bundle_name, relative))


def export_app(args):
    """Atomically export one installed application into 0-Sky Control's sandbox."""
    source = os.path.realpath(args[1])
    destination = args[2]
    parent = os.path.dirname(destination)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    temporary = destination + ".new." + str(uuid.uuid4())
    try:
        package_app_bundle(source, temporary)
        os.chown(temporary, 501, 501)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        return {"status": 0, "stdout": destination, "stderr": ""}
    except Exception:
        try: os.unlink(temporary)
        except OSError: pass
        raise


def _publish_export(temporary, destination):
    os.chown(temporary, 501, 501)
    os.chmod(temporary, 0o600)
    os.replace(temporary, destination)
    return {"status": 0, "stdout": destination, "stderr": ""}


def _debian_value(value, fallback):
    value = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return value or fallback


def export_app_deb(args):
    """Wrap an installed app as a rootless, 0-Sky Control-importable Debian package."""
    source = os.path.realpath(args[1])
    destination = args[2]
    with open(os.path.join(source, "Info.plist"), "rb") as handle:
        info = plistlib.load(handle)
    bundle_id = info.get("CFBundleIdentifier")
    executable = info.get("CFBundleExecutable")
    if (not isinstance(bundle_id, str) or not BUNDLE_ID.fullmatch(bundle_id) or
            not isinstance(executable, str) or os.path.basename(executable) != executable or
            not os.path.isfile(os.path.join(source, executable))):
        raise RequestError("app bundle metadata or executable is invalid")
    package_suffix = re.sub(r"[^a-z0-9+.-]+", "-", bundle_id.lower()).strip(".-")
    package_name = ("0-sky-export." + package_suffix)[:250].rstrip(".-")
    version = re.sub(r"[^A-Za-z0-9.+:~-]+", ".",
                     _debian_value(info.get("CFBundleShortVersionString") or
                                   info.get("CFBundleVersion"), "1.0"))
    display = _debian_value(info.get("CFBundleDisplayName") or
                            info.get("CFBundleName"), os.path.splitext(os.path.basename(source))[0])
    parent = os.path.dirname(destination)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    workspace = os.path.join("/var/jb/var/tmp", "crypstore-export-" + str(uuid.uuid4()))
    temporary = destination + ".new." + str(uuid.uuid4())
    try:
        # Procursus dpkg extracts payload paths relative to the real filesystem
        # root.  A bare ``Applications`` directory therefore targets Apple's
        # sealed /Applications volume and fails with EROFS.  Keep exported app
        # packages genuinely rootless by placing the bundle below /var/jb;
        # integration_report() will subsequently hand this writable bundle to
        # the authenticated Cryptex/appregistrard installer.
        payload = os.path.join(
            workspace, "var", "jb", "Applications", os.path.basename(source))
        os.makedirs(os.path.dirname(payload), mode=0o755)
        shutil.copytree(source, payload, symlinks=True)
        control_dir = os.path.join(workspace, "DEBIAN")
        os.makedirs(control_dir, mode=0o755)
        control = (
            f"Package: {package_name}\n"
            f"Name: {display}\n"
            f"Version: {version}\n"
            "Architecture: iphoneos-arm64\n"
            "Section: Applications\n"
            "Maintainer: 0-Sky Project\n"
            "X-0-Sky-Rootless-App-Export: 1\n"
            f"Description: 0-Sky Control export of installed app {bundle_id}\n"
        )
        with open(os.path.join(control_dir, "control"), "w", encoding="utf-8") as handle:
            handle.write(control)
        completed = subprocess.run(
            ["/var/jb/usr/bin/dpkg-deb", "--build", "--root-owner-group",
             workspace, temporary], cwd="/var/jb/var/tmp", env=ENV,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=900, check=False)
        if completed.returncode:
            return {"status": completed.returncode, "stdout": "", "stderr":
                    completed.stderr.decode("utf-8", "replace")[:MAX_OUTPUT]}
        return _publish_export(temporary, destination)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
        try: os.unlink(temporary)
        except OSError: pass


def export_package(args):
    """Repack exactly one installed dpkg payload into a portable ``.deb``."""
    package = args[1]
    destination = args[2]
    # Make an otherwise orphaned executable preference bundle portable before
    # reading the package payload. Generated descriptors are added explicitly
    # because dpkg cannot own a file that was created after installation.
    repair = preference_repair(package)
    query = subprocess.run(
        ["/var/jb/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\\n${Status}\\n${Version}\\n",
         package], cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    rows = query.stdout.decode("utf-8", "replace").splitlines()
    if query.returncode or len(rows) < 3 or " installed" not in rows[1]:
        return {"status": 126, "stdout": "", "stderr": "Package is not installed."}
    binary_package = rows[0].split(":", 1)[0]
    status = subprocess.run(
        ["/var/jb/usr/bin/dpkg-query", "-s", package], cwd="/var/jb/var/tmp", env=ENV,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False)
    listing = subprocess.run(
        ["/var/jb/usr/bin/dpkg-query", "-L", package], cwd="/var/jb/var/tmp", env=ENV,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False)
    if status.returncode or listing.returncode:
        return {"status": 126, "stdout": "", "stderr":
                (status.stderr + listing.stderr).decode("utf-8", "replace")[:MAX_OUTPUT]}
    parent = os.path.dirname(destination)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    workspace = os.path.join("/var/jb/var/tmp", "crypstore-repack-" + str(uuid.uuid4()))
    temporary = destination + ".new." + str(uuid.uuid4())
    try:
        os.makedirs(workspace, mode=0o755)
        copied = 0
        listed_paths = listing.stdout.decode("utf-8", "replace").splitlines()
        listed_paths.extend(repair.get("descriptors", []))
        for listed in dict.fromkeys(listed_paths):
            if not listed.startswith("/") or listed in ("/", "/."):
                continue
            relative = os.path.normpath(listed).lstrip("/")
            if not relative or relative.startswith("../"):
                raise RequestError("installed package contains an unsafe path")
            candidates = [listed, "/var/jb" + listed]
            source = next((item for item in candidates if os.path.lexists(item)), None)
            if not source:
                continue
            target = os.path.join(workspace, relative)
            # dpkg -L includes virtual-root ancestors such as /var. On iOS
            # those can themselves be symlinks (for example /var ->
            # /private/var); reproducing that host-layout link inside the
            # package would make every later payload path escape the staging
            # tree. Directories are recreated from file parents instead.
            if os.path.isdir(source):
                continue
            if os.path.islink(source):
                os.makedirs(os.path.dirname(target), exist_ok=True)
                os.symlink(os.readlink(source), target)
                copied += 1
            elif os.path.isfile(source):
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copy2(source, target, follow_symlinks=False)
                copied += 1
        if copied < 1:
            return {"status": 126, "stdout": "", "stderr":
                    "The installed package has no readable payload files."}
        control_dir = os.path.join(workspace, "DEBIAN")
        os.makedirs(control_dir, mode=0o755, exist_ok=True)
        control_lines = []
        skipping_continuation = False
        for line in status.stdout.decode("utf-8", "replace").splitlines():
            field = line.split(":", 1)[0] if ":" in line and not line.startswith((" ", "\t")) else ""
            if field in ("Status", "Conffiles", "Config-Version", "Installed-Size"):
                skipping_continuation = True
                continue
            if line.startswith((" ", "\t")) and skipping_continuation:
                continue
            skipping_continuation = False
            control_lines.append(line)
        if not any(line.startswith("Package:") for line in control_lines):
            control_lines.insert(0, "Package: " + binary_package)
        if repair.get("descriptors"):
            control_lines.append("X-CrypStore-Preference-Conversion: 1")
            control_lines.append("X-0-Sky-Credit: 0-Sky Project")
        with open(os.path.join(control_dir, "control"), "w", encoding="utf-8") as handle:
            handle.write("\n".join(control_lines).rstrip() + "\n")
        info_roots = ("/var/jb/Library/dpkg/info", "/var/jb/var/lib/dpkg/info")
        for suffix in ("preinst", "postinst", "prerm", "postrm", "triggers", "conffiles"):
            source = next((os.path.join(root, binary_package + "." + suffix)
                           for root in info_roots
                           if os.path.isfile(os.path.join(root, binary_package + "." + suffix))), None)
            if source:
                shutil.copy2(source, os.path.join(control_dir, suffix))
        completed = subprocess.run(
            ["/var/jb/usr/bin/dpkg-deb", "--build", "--root-owner-group",
             workspace, temporary], cwd="/var/jb/var/tmp", env=ENV,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=900, check=False)
        if completed.returncode:
            return {"status": completed.returncode, "stdout": "", "stderr":
                    completed.stderr.decode("utf-8", "replace")[:MAX_OUTPUT]}
        result = _publish_export(temporary, destination)
        result["preference_repair"] = repair
        return result
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
        try: os.unlink(temporary)
        except OSError: pass

def queue_install(args):
    status = worker_status()
    if not status["connected"]:
        return {"status": 190, "stdout": "", "stderr": (
            "Mac companion is not connected. Connect this iPhone to the configured Mac, "
            "confirm the 0-Sky Control worker is running, then try again."
        )}

    source = os.path.realpath(args[-1])
    job_id = str(uuid.uuid4())
    root = os.path.join(SPOOL, job_id)
    os.makedirs(root, mode=0o700, exist_ok=False)
    destination = os.path.join(root, "input.ipa")
    try:
        if args[0] == "install-app-bundle":
            package_app_bundle(source, destination)
        else:
            shutil.copyfile(source, destination)
        os.chmod(destination, 0o600)
        atomic_json(os.path.join(root, "request.json"), {
            "job_id": job_id,
            "operation": "install",
            "original_name": os.path.basename(source),
            "arguments": args,
            "created_at": int(time.time()),
        })
        deadline = time.monotonic() + 1800
        result_path = os.path.join(root, "result.json")
        while time.monotonic() < deadline:
            if os.path.isfile(result_path):
                with open(result_path, "r", encoding="utf-8") as f:
                    result = json.load(f)
                if not isinstance(result, dict) or not isinstance(result.get("status"), int):
                    raise RuntimeError("Mac companion returned an invalid result")
                try: os.unlink(destination)
                except OSError: pass
                return result
            time.sleep(1)
        return {"status": 124, "stdout": "", "stderr": (
            "0-Sky Control timed out after 30 minutes. Keep the Mac connected and check the companion log."
        )}
    except Exception:
        try: shutil.rmtree(root)
        except OSError: pass
        raise


def queue_runtime_sync(package_name):
    """Ask the connected Mac to authorize the new package-owned code."""
    status = worker_status()
    if not status["connected"]:
        return {"status": 190, "stdout": "", "stderr":
                "Tweak files were installed, but the Mac companion is required to refresh the SRD trust cache."}
    job_id = str(uuid.uuid4())
    root = os.path.join(SPOOL, job_id)
    os.makedirs(root, mode=0o700, exist_ok=False)
    atomic_json(os.path.join(root, "request.json"), {
        "job_id": job_id, "operation": "runtime-sync", "package": package_name,
        "created_at": int(time.time()),
    })
    deadline = time.monotonic() + 1200
    result_path = os.path.join(root, "result.json")
    while time.monotonic() < deadline:
        if os.path.isfile(result_path):
            with open(result_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        time.sleep(1)
    return {"status": 124, "stdout": "", "stderr": "Timed out refreshing the SRD runtime trust cache."}

def package_payload(package_name):
    """Return installed apps and integration-relevant files owned by a package."""
    listed = subprocess.run(
        ["/var/jb/usr/bin/dpkg-query", "-L", package_name],
        cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if listed.returncode != 0:
        return {"apps": [], "tweaks": [], "preferences": [], "daemons": []}

    apps = set()
    tweaks = set()
    preferences = set()
    daemons = set()
    approved_app_roots = ("/var/jb/Applications/", "/Applications/")
    for raw_path in listed.stdout.decode("utf-8", "replace").splitlines():
        path = raw_path.strip()
        lower = path.lower()
        marker = lower.find(".app/")
        if marker >= 0:
            app = path[:marker + 4]
        elif lower.endswith(".app"):
            app = path
        else:
            app = ""
        if app.startswith(approved_app_roots) and os.path.isdir(app):
            apps.add(os.path.realpath(app))
        if (path.startswith(("/var/jb/usr/lib/TweakInject/",
                             "/var/jb/Library/MobileSubstrate/DynamicLibraries/")) and
                lower.endswith(".dylib")):
            tweaks.add(path)
        if path.startswith("/var/jb/Library/PreferenceBundles/"):
            preferences.add(path.split(".bundle", 1)[0] + ".bundle")
        if (path.startswith("/var/jb/Library/LaunchDaemons/") and
                lower.endswith(".plist")):
            daemons.add(path)
    return {
        "apps": sorted(apps),
        "tweaks": sorted(tweaks),
        "preferences": sorted(preferences),
        "daemons": sorted(daemons),
    }

def archive_contains_app(deb_path):
    """Determine whether the Debian payload contains a home-screen app bundle."""
    listed = subprocess.run(
        ["/var/jb/usr/bin/dpkg-deb", "--contents", deb_path],
        cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    if listed.returncode != 0:
        return False
    text = listed.stdout.decode("utf-8", "replace")
    return bool(re.search(
        r"(?:^|\s)\.?/(?:var/jb/)?Applications/[^\s/]+\.app/(?:Info\.plist|[^\s]+)",
        text, re.MULTILINE | re.IGNORECASE))

def dependency_error(output):
    lower = output.lower()
    return any(value in lower for value in (
        "unmet dependencies", "unable to locate package", "is not installable",
        "held broken packages", "but it is not going to be installed",
        "depends:",
    ))

def apt_install(destination):
    command = [
        "/var/jb/usr/bin/apt-get", "install", "-y", "--reinstall", "--no-remove",
        "--allow-downgrades", "--allow-change-held-packages",
        "-o", "Dpkg::Use-Pty=0", "-o", "APT::Sandbox::User=root",
        destination,
    ]
    completed = subprocess.run(
        command, cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900, check=False)
    refresh_output = b""
    combined = (completed.stdout + b"\n" + completed.stderr).decode("utf-8", "replace")
    if completed.returncode != 0 and dependency_error(combined):
        refresh = subprocess.run(
            ["/var/jb/usr/bin/apt-get", "update", "-o", "Dpkg::Use-Pty=0",
             "-o", "APT::Sandbox::User=root"],
            cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=420, check=False)
        refresh_output = (b"\n0-Sky Control refreshed package indexes before retrying dependencies.\n" +
                          refresh.stdout + refresh.stderr)
        completed = subprocess.run(
            command, cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900, check=False)
    return completed, refresh_output

def normalize_legacy_app_export(destination, metadata):
    """Migrate app DEBs exported by 0-Sky 2.4.6 to the rootless layout.

    The 2.4.6 exporter accidentally placed its one app at ``/Applications``.
    Only packages bearing the exact 0-Sky export identity and shape are
    rewritten; ordinary third-party/rootful packages remain untouched and
    therefore fail closed rather than being guessed into a new layout.
    """
    if metadata.get("X-0-Sky-Rootless-App-Export") == "1":
        return False
    if (not metadata.get("Package", "").startswith("0-sky-export.") or
            metadata.get("Maintainer") != "0-Sky Project" or
            not metadata.get("Description", "").startswith(
                "0-Sky Control export of installed app ")):
        return False
    workspace = os.path.join(
        "/var/jb/var/tmp", "crypstore-rootless-migration-" + str(uuid.uuid4()))
    rebuilt = destination + ".rootless." + str(uuid.uuid4())
    try:
        extracted = subprocess.run(
            ["/var/jb/usr/bin/dpkg-deb", "--raw-extract", destination, workspace],
            cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
        if extracted.returncode != 0:
            raise RequestError("Unable to inspect the legacy 0-Sky app export safely: " +
                               extracted.stderr.decode("utf-8", "replace")[:1024])
        top = {entry.name for entry in pathlib.Path(workspace).iterdir()}
        legacy = pathlib.Path(workspace) / "Applications"
        control_dir = pathlib.Path(workspace) / "DEBIAN"
        if top != {"Applications", "DEBIAN"} or legacy.is_symlink() or not legacy.is_dir():
            raise RequestError("Legacy 0-Sky app export has an unexpected payload layout")
        apps = list(legacy.iterdir())
        if (len(apps) != 1 or apps[0].is_symlink() or not apps[0].is_dir() or
                apps[0].suffix.lower() != ".app" or
                not (apps[0] / "Info.plist").is_file()):
            raise RequestError("Legacy 0-Sky app export does not contain exactly one valid app")
        control_files = {entry.name for entry in control_dir.iterdir()}
        if control_files != {"control"}:
            raise RequestError("Legacy 0-Sky app export contains unexpected maintainer scripts")
        rootless = pathlib.Path(workspace) / "var" / "jb" / "Applications"
        rootless.parent.mkdir(parents=True, exist_ok=True)
        legacy.rename(rootless)
        control = control_dir / "control"
        text = control.read_text(encoding="utf-8")
        if "X-0-Sky-Rootless-App-Export:" not in text:
            control.write_text(text.rstrip() + "\nX-0-Sky-Rootless-App-Export: 1\n",
                               encoding="utf-8")
        built = subprocess.run(
            ["/var/jb/usr/bin/dpkg-deb", "--build", "--root-owner-group",
             workspace, rebuilt], cwd="/var/jb/var/tmp", env=ENV,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=900, check=False)
        if built.returncode != 0:
            raise RequestError("Unable to migrate the legacy 0-Sky app export: " +
                               built.stderr.decode("utf-8", "replace")[:1024])
        os.chown(rebuilt, 0, 0)
        os.chmod(rebuilt, 0o644)
        os.replace(rebuilt, destination)
        return True
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
        try: os.unlink(rebuilt)
        except OSError: pass

def integration_report(package_name):
    """Register package-owned apps and report tweak/plugin activation state."""
    payload = package_payload(package_name)
    messages = []
    failures = []
    for app_path in payload["apps"]:
        try:
            result = queue_install(["install-app-bundle", app_path])
        except Exception as error:
            failures.append(f"{os.path.basename(app_path)}: {error}")
            continue
        if result.get("status") == 0:
            messages.append(
                f"Desktop app integrated through Cryptex/appregistrard: {os.path.basename(app_path)}")
            detail = str(result.get("stdout") or "").strip()
            if detail:
                messages.append(detail)
        else:
            failures.append(
                f"{os.path.basename(app_path)}: " +
                str(result.get("stderr") or f"integration status {result.get('status', 125)}"))

    if payload["preferences"]:
        messages.append(
            f"Installed {len(payload['preferences'])} PreferenceLoader bundle(s).")
    if payload["daemons"]:
        messages.append(
            f"Installed {len(payload['daemons'])} launch-daemon definition(s); package maintainer scripts control activation.")
    if payload["tweaks"] or payload["preferences"]:
        ps_path = "/var/jb/usr/bin/ps" if os.access("/var/jb/usr/bin/ps", os.X_OK) else "/bin/ps"
        process_list = subprocess.run(
            [ps_path, "aux"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10, check=False).stdout.decode("utf-8", "replace")
        loader_active = bool(re.search(
            r"/(?:ellekit/(?:loader|libinjector)|TweakLoader|srd-runtime-manager\.py)(?:\s|$)",
            process_list))
        if loader_active:
            messages.append(f"Installed {len(payload['tweaks'])} tweak dylib(s); ElleKit loader detected.")
        else:
            messages.append(
                f"Installed {len(payload['tweaks'])} tweak dylib(s), but the ElleKit loader is not active; "
                "the files are installed but cannot be injected on this boot.")
        if os.path.isfile(RUNTIME_MANAGER):
            requested = subprocess.run(
                ["/var/jb/usr/bin/python3", RUNTIME_MANAGER, "sync"],
                cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
            if requested.returncode == 0:
                messages.append("Dynamic ElleKit registry refresh requested.")
            else:
                failures.append("Dynamic ElleKit registry refresh failed: " +
                                requested.stderr.decode("utf-8", "replace")[-1000:])
    return payload, messages, failures


def appctl(arguments, timeout=120):
    if not os.path.isfile(APPCTL):
        return {"status": 127, "stdout": "", "stderr": "0-Sky Control app controller is unavailable"}
    completed = subprocess.run(
        ["/var/jb/usr/bin/python3", APPCTL] + arguments,
        cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return {"status": completed.returncode,
            "stdout": completed.stdout.decode("utf-8", "replace")[:MAX_OUTPUT],
            "stderr": completed.stderr.decode("utf-8", "replace")[:MAX_OUTPUT]}


def preference_repair(package=None):
    """Run 0-Sky Control's deterministic preference conversion/audit."""
    arguments = ["repair-preferences", "--json"]
    if package:
        arguments.append(package)
    result = appctl(arguments, timeout=90)
    if result.get("status") != 0:
        return {"changed": False, "descriptors": [], "generated": [],
                "retained": [], "unresolved": [], "removed": [],
                "summary": "Preference conversion failed: " +
                           str(result.get("stderr") or result.get("stdout") or
                               "unknown app-controller error")}
    try:
        report = json.loads(result.get("stdout") or "{}")
    except (TypeError, ValueError):
        report = {}
    if not isinstance(report, dict):
        report = {}
    report.setdefault("changed", False)
    report.setdefault("descriptors", [])
    report.setdefault("summary", "Preference conversion completed")
    return report


def clear_preference_loader_quarantine():
    """Ask the authoritative daemon to clear only the planned Settings edge."""
    if not os.path.isfile(RUNTIME_MANAGER):
        return
    subprocess.run(
        ["/var/jb/usr/bin/python3", RUNTIME_MANAGER, "clear-quarantine",
         "--package", "preferenceloader", "--target", "com.apple.Preferences"],
        cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    clear_request = os.path.join(RUNTIME_STATE_DIR,
                                 "quarantine-clear.request.json")
    deadline = time.monotonic() + 5
    while os.path.exists(clear_request) and time.monotonic() < deadline:
        time.sleep(0.1)


def repair_and_refresh_preferences(package=None, reason="0-Sky Control preference repair",
                                   force_refresh=False):
    """Convert menus, then authorize their executable bundles when needed."""
    report = preference_repair(package)
    refresh = None
    if force_refresh or report.get("changed"):
        if os.path.isfile(RUNTIME_MANAGER):
            subprocess.run(
                ["/var/jb/usr/bin/python3", RUNTIME_MANAGER, "sync"],
                cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        refresh = queue_runtime_sync(reason)
        if refresh.get("status") == 0 and os.path.isfile(RUNTIME_MANAGER):
            # Runtime replacement can terminate Settings while its first
            # PreferenceLoader injection is settling. Do not let that planned
            # process boundary permanently suppress the freshly converted
            # menus; clear only PreferenceLoader's Settings-target record.
            clear_preference_loader_quarantine()
    return report, refresh


def attach_preference_repair(result, package=None, reason="0-Sky Control operation",
                             force_refresh=False):
    """Attach conversion diagnostics without hiding a successful export/install."""
    if result.get("status") != 0:
        return result
    report, refresh = repair_and_refresh_preferences(
        package, reason=reason, force_refresh=force_refresh)
    result["preference_repair"] = report
    messages = [str(result.get("stdout") or "").strip(),
                str(report.get("summary") or "").strip()]
    if refresh:
        if refresh.get("status") == 0:
            messages.append(str(refresh.get("stdout") or
                                "Preference runtime refreshed.").strip())
        else:
            messages.append("Preference conversion was saved, but runtime refresh failed: " +
                            str(refresh.get("stderr") or refresh.get("status")))
        result["preference_runtime_refresh"] = refresh
    result["stdout"] = "\n".join(message for message in messages if message)
    return result


def registered_bundle_path(bundle_id):
    """Return LaunchServices' current path for *bundle_id*.

    MCM container UUIDs are not stable across a reboot or a coordinated app
    replacement.  The enrollment record intentionally preserves the original
    path for forensics, so it cannot be used as a live registration probe.
    Query uicache instead and validate the returned bundle before reporting it
    to the status UI.  The boolean distinguishes a successful empty query from
    a tool failure, allowing runtime_status() to use recorded state only as a
    compatibility fallback when uicache itself is unavailable.
    """
    try:
        completed = subprocess.run(
            ["/var/jb/usr/bin/uicache", "-l"], cwd="/var/jb/var/tmp", env=ENV,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30, check=False,
        )
    except Exception:
        return False, ""
    if completed.returncode:
        return False, ""
    prefix = bundle_id + " : "
    candidates = [
        line[len(prefix):].strip()
        for line in completed.stdout.decode("utf-8", "replace").splitlines()
        if line.startswith(prefix)
    ]
    if len(candidates) != 1:
        return True, ""
    candidate = os.path.realpath(candidates[0])
    allowed = (
        "/private/var/containers/Bundle/Application/",
        "/var/containers/Bundle/Application/",
        "/private/var/run/com.apple.security.cryptexd/mnt/",
    )
    if not candidate.startswith(allowed) or not os.path.isdir(candidate):
        return True, ""
    try:
        with open(os.path.join(candidate, "Info.plist"), "rb") as handle:
            if plistlib.load(handle).get("CFBundleIdentifier") != bundle_id:
                return True, ""
    except Exception:
        return True, ""
    return True, candidate


def runtime_status():
    """Return a small, unprivileged boot-success summary for local status UIs."""
    def read_json(name):
        try:
            with open(os.path.join(RUNTIME_STATE_DIR, name), "rb") as handle:
                value = json.load(handle)
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    registry = read_json("registry.json")
    injection = read_json("injection-state.json")
    targets = registry.get("targets") if isinstance(registry.get("targets"), dict) else {}
    quarantined = registry.get("quarantined")
    if not isinstance(quarantined, list):
        quarantined = []
    configured = sum(len(item.get("dylibs", [])) for item in targets.values()
                     if isinstance(item, dict) and isinstance(item.get("dylibs", []), list))
    loaded_values = injection.get("loaded") if isinstance(injection.get("loaded"), dict) else {}
    live_loaded = []
    for item in loaded_values.values():
        if not isinstance(item, dict) or not isinstance(item.get("pid"), int):
            continue
        try:
            os.kill(item["pid"], 0)
            live_loaded.append(item)
        except OSError:
            pass
    try:
        ps_path = "/var/jb/usr/bin/ps" if os.path.exists("/var/jb/usr/bin/ps") else "/bin/ps"
        process_list = subprocess.run(
            [ps_path, "ax", "-o", "command="], cwd="/var/jb/var/tmp",
            env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5, check=False).stdout.decode("utf-8", "replace")
    except Exception:
        process_list = ""
    manager_active = "/var/jb/usr/local/libexec/srd-runtime-manager.py daemon" in process_list
    paused = os.path.exists("/var/mobile/pl/srd-runtime-paused")
    # 0-Sky Control itself is a first-class part of the 0-Sky boot contract.  Its
    # Cryptex can remain mounted while LaunchServices points at a retired MCM
    # payload, so an icon alone is not enough to call it healthy.
    crypstore_state = {}
    try:
        with open("/var/jb/var/lib/crypstore/com.liquidsky.CrypStore.json", "rb") as handle:
            crypstore_state = json.load(handle)
    except (OSError, ValueError):
        pass
    listing_ok, crypstore_path = registered_bundle_path("com.liquidsky.CrypStore")
    if not listing_ok:
        # Older deployments may not have uicache while rootless bootstrap is
        # still settling. Prefer the keeper's latest observation, but never use
        # stale state after a successful LaunchServices query returned no app.
        for key in ("observed_registered_path", "rollback_repaired_path", "registered_path"):
            candidate = crypstore_state.get(key)
            if isinstance(candidate, str) and os.path.isdir(candidate):
                crypstore_path = candidate
                break
    crypstore_version = "unknown"
    if crypstore_path:
        try:
            with open(os.path.join(crypstore_path, "Info.plist"), "rb") as handle:
                info = plistlib.load(handle)
            crypstore_version = str(info.get("CFBundleShortVersionString") or
                                    info.get("CFBundleVersion") or "unknown")
        except (OSError, ValueError):
            pass
    crypstore_mounted = False
    wanted = crypstore_state.get("cryptex_identifier")
    mount_root = "/private/var/run/com.apple.security.cryptexd/mnt"
    try:
        crypstore_mounted = any(
            name.startswith(str(wanted) + ".") and
            os.path.isdir(os.path.join(mount_root, name, "Applications", "CrypStore.app"))
            for name in os.listdir(mount_root)) if wanted else False
    except OSError:
        pass
    crypstore_running = "/CrypStore.app/CrypStore" in process_list
    crypstore_ready = bool(crypstore_path and crypstore_mounted)
    ellekit_ready = bool(manager_active and not paused and configured > 0 and live_loaded)
    try:
        disk = shutil.disk_usage("/var/jb")
        rootless_free_mb = disk.free // (1024 * 1024)
    except OSError:
        rootless_free_mb = -1
    uname = os.uname()
    result = {
        "ok": bool(ellekit_ready and crypstore_ready),
        "ellekit_ok": ellekit_ready,
        "manager_active": manager_active,
        "paused": paused,
        "generation": registry.get("generation"),
        "configured_dylibs": configured,
        "quarantined_dylibs": len(quarantined),
        "effective_dylibs": max(0, configured - len(quarantined)),
        "configured_targets": len(targets),
        "loaded_dylibs": len(live_loaded),
        "loaded_targets": len({item.get("target") for item in live_loaded if item.get("target")}),
        "crypstore_ok": crypstore_ready,
        "crypstore_mounted": crypstore_mounted,
        "crypstore_registered": bool(crypstore_path),
        "crypstore_running": crypstore_running,
        "crypstore_version": crypstore_version,
        "bridge_euid": os.geteuid(),
        "bridge_user": "root" if os.geteuid() == 0 else "mobile" if os.geteuid() == 501 else "unknown",
        "darwin_release": uname.release,
        "machine": uname.machine,
        "rootless_free_mb": rootless_free_mb,
        "registry_generated_at": registry.get("generated_at"),
    }
    result["pairing"] = pairing_status()
    result["paired"] = result["pairing"]["paired"]
    return result


def bundle_id_at_path(path):
    try:
        with open(os.path.join(path, "Info.plist"), "rb") as handle:
            value = plistlib.load(handle).get("CFBundleIdentifier")
        return value if isinstance(value, str) and BUNDLE_ID.fullmatch(value) else None
    except Exception:
        return None


def remove_tweak_package(package):
    protected = {"apt", "dpkg", "ellekit", "preferenceloader", "sileo",
                 "org.coolstar.sileo", "com.liquidskysecurity.srd-runtime-manager"}
    if package.lower() in protected:
        return {"status": 126, "stdout": "", "stderr":
                "This foundational package cannot be removed from 0-Sky Control."}
    payload = package_payload(package)
    if not payload["tweaks"] and not payload["preferences"]:
        return {"status": 126, "stdout": "", "stderr":
                "Removal is limited to packages that own a tweak or preference bundle."}
    with LOCK:
        completed = subprocess.run(
            ["/var/jb/usr/bin/dpkg", "--remove", package],
            cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, check=False)
    output = (completed.stdout + completed.stderr).decode("utf-8", "replace")[:MAX_OUTPUT]
    result = {"status": completed.returncode, "stdout": output, "stderr": ""}
    if completed.returncode == 0:
        # Reconcile globally after dpkg has removed the payload. This deletes
        # any 0-Sky Control-generated descriptor for the package and renews the
        # runtime Cryptex so a removed menu cannot linger in Settings.
        return attach_preference_repair(
            result, reason=f"{package} removed", force_refresh=True)
    return result

def install_deb(path):
    """Validate and install one local .deb through fixed Procursus tools."""
    source = os.path.realpath(path)
    with open(source, "rb") as package:
        if package.read(8) != b"!<arch>\n":
            return {"status": 126, "stdout": "", "stderr":
                    "The selected file is not a valid Debian ar archive."}
    archive_dir = "/var/jb/var/cache/apt/archives"
    os.makedirs(archive_dir, mode=0o755, exist_ok=True)
    destination = os.path.join(archive_dir, "crypstore-" + str(uuid.uuid4()) + ".deb")
    try:
        shutil.copyfile(source, destination)
        os.chown(destination, 0, 0)
        os.chmod(destination, 0o644)
        inspection = subprocess.run(
            ["/var/jb/usr/bin/dpkg-deb", "--field", destination,
             "Package", "Version", "Architecture", "Maintainer", "Description",
             "X-0-Sky-Rootless-App-Export"],
            cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        if inspection.returncode != 0:
            return {"status": 126, "stdout": "", "stderr":
                    inspection.stderr.decode("utf-8", "replace")[:MAX_OUTPUT] or
                    "dpkg-deb rejected the selected package."}
        metadata = {}
        for line in inspection.stdout.decode("utf-8", "replace").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                metadata[key.strip()] = value.strip()
        package_arch = metadata.get("Architecture", "")
        package_name = metadata.get("Package", "")
        if not BUNDLE_ID.fullmatch(package_name):
            return {"status": 126, "stdout": inspection.stdout.decode("utf-8", "replace"),
                    "stderr": "The Debian package has an invalid or missing Package field."}
        system_arch_result = subprocess.run(
            ["/var/jb/usr/bin/dpkg", "--print-architecture"],
            cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
        system_arch = system_arch_result.stdout.decode("utf-8", "replace").strip()
        if package_arch not in ("all", system_arch):
            return {"status": 191, "stdout": inspection.stdout.decode("utf-8", "replace"),
                    "stderr": (f"Architecture mismatch: this package is {package_arch or 'unknown'}, "
                    f"but this rootless Procursus environment requires {system_arch or 'iphoneos-arm64'} "
                    "or all. Obtain the package's rootless build; the legacy rootful package was not installed.")}
        migrated_legacy_export = normalize_legacy_app_export(destination, metadata)
        if archive_contains_app(destination) and not worker_status()["connected"]:
            return {"status": 190, "stdout": inspection.stdout.decode("utf-8", "replace"),
                    "stderr": ("This package contains a desktop app. Connect the paired Mac before installing "
                               "so 0-Sky Control can build its Cryptex and register its icon atomically.")}
        with LOCK:
            completed, refresh_output = apt_install(destination)
        stdout = inspection.stdout + b"\n" + refresh_output + completed.stdout
        stderr = completed.stderr.decode("utf-8", "replace")
        if completed.returncode != 0:
            return {
                "status": completed.returncode,
                "stdout": stdout.decode("utf-8", "replace")[:MAX_OUTPUT],
                "stderr": stderr[:MAX_OUTPUT],
            }

        check = subprocess.run(
            ["/var/jb/usr/bin/apt-get", "check", "-o", "Dpkg::Use-Pty=0",
             "-o", "APT::Sandbox::User=root"],
            cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
        stdout += check.stdout
        stderr += check.stderr.decode("utf-8", "replace")
        if check.returncode != 0:
            return {
                "status": check.returncode,
                "stdout": stdout.decode("utf-8", "replace")[:MAX_OUTPUT],
                "stderr": (stderr + "\nDependency verification failed after installation.")[:MAX_OUTPUT],
            }

        messages = []
        if migrated_legacy_export:
            messages.append(
                "Migrated the legacy 0-Sky app export from the sealed /Applications path "
                "to the writable rootless /var/jb/Applications path.")
        repair = preference_repair(package_name)
        messages.append(str(repair.get("summary") or "Preference conversion completed."))
        payload, messages_after_repair, failures = integration_report(package_name)
        messages.extend(messages_after_repair)
        if payload["tweaks"] or payload["preferences"] or repair.get("changed"):
            sync_result = queue_runtime_sync(package_name)
            if sync_result.get("status") == 0:
                messages.append(str(sync_result.get("stdout") or
                                    "SRD runtime trust cache refreshed."))
                clear_preference_loader_quarantine()
            else:
                failures.append(str(sync_result.get("stderr") or
                                    "SRD runtime trust-cache refresh failed."))
        if messages:
            stdout += ("\n\n0-Sky Control integration:\n" + "\n".join(messages) + "\n").encode()
        if failures:
            stderr += "\nDesktop integration failed:\n" + "\n".join(failures)
        return {
            "status": 192 if failures else 0,
            "stdout": stdout.decode("utf-8", "replace")[:MAX_OUTPUT],
            "stderr": stderr[:MAX_OUTPUT],
            "integrated_apps": [os.path.basename(value) for value in payload["apps"]],
            "tweak_count": len(payload["tweaks"]),
            "preference_bundle_count": len(payload["preferences"]),
            "preference_repair": repair,
            "package": package_name,
            "version": metadata.get("Version", ""),
        }
    finally:
        try: os.unlink(destination)
        except OSError: pass

class Server(ThreadingHTTPServer):
    daemon_threads = True; allow_reuse_address = True
    def __init__(self, addr, handler): super().__init__(addr, handler); self.token = token()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def reply(self, code, payload):
        data=json.dumps(payload,separators=(",",":")).encode(); self.send_response(code)
        self.send_header("Content-Type","application/json"); self.send_header("Cache-Control","no-store")
        self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            return self.reply(200, {"ok": bridge_ready()})
        if parsed.path in ("/v1/status", "/v1/runtime", "/v1/pairing/status",
                           "/v1/pairing/result"):
            if not hmac.compare_digest(self.headers.get("X-TrollStore-Bridge-Token", ""),
                                       self.server.token):
                return self.reply(403, {"status": 126, "complete": True,
                                        "errorCode": "AUTHENTICATION_FAILED",
                                        "stderr": "authentication failed"})
        if parsed.path == "/v1/status":
            status = worker_status()
            status["device_bridge"] = bridge_ready()
            status["pairing"] = pairing_status()
            status["paired"] = status["pairing"]["paired"]
            return self.reply(200, status)
        if parsed.path == "/v1/pairing/status":
            return self.reply(200, pairing_status())
        if parsed.path == "/v1/pairing/result":
            job_id = (parse_qs(parsed.query).get("job_id") or [None])[0]
            result = pairing_result(job_id)
            code = 200 if result.get("status") not in (2, 22) else 404
            return self.reply(code, result)
        if parsed.path == "/v1/inventory":
            result = appctl(["list", "--json"])
            if result["status"] != 0:
                return self.reply(500, {"ok": False, "error": result["stderr"]})
            try:
                return self.reply(200, json.loads(result["stdout"]))
            except Exception as error:
                return self.reply(500, {"ok": False, "error": str(error)})
        if parsed.path == "/v1/runtime":
            return self.reply(200, runtime_status())
        self.reply(404, {"ok": False})
    def do_POST(self):
        privileged_paths = ("/v1/runtime/refresh", "/v1/crypstore/repair",
                            "/v1/trollstore", "/v1/geranium", "/v1/core",
                            "/v1/pairing/request", "/v1/pairing/cancel",
                            "/v1/device-password")
        if self.path in privileged_paths:
            if not hmac.compare_digest(self.headers.get("X-TrollStore-Bridge-Token", ""),
                                       self.server.token):
                return self.reply(403, {"status": 126, "stdout": "",
                                        "stderr": "authentication failed"})
            # Pairing request and cancellation must be usable before trust is
            # established. They are still token-authenticated above. Gating
            # cancellation on pairing_status() made the Cancel button
            # impossible to use during the very operation it must stop.
            if self.path not in ("/v1/pairing/request", "/v1/pairing/cancel"):
                denial = pairing_denial()
                if denial:
                    return self.reply(403, denial)
        if self.path == "/v1/pairing/request":
            result = queue_pair_verify()
            return self.reply(202 if result.get("status") == 0 else 503, result)
        if self.path == "/v1/pairing/cancel":
            try:
                n = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                return self.reply(400, {"status": 22, "stderr": "invalid cancellation request"})
            result = cancel_pair_verify(payload.get("job_id"))
            return self.reply(200 if result.get("status") == 0 else 404, result)
        if self.path == "/v1/core":
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n < 1 or n > MAX_BODY:
                    raise RequestError("invalid request length")
                payload = json.loads(self.rfile.read(n).decode("utf-8"))
                caller = pairing_status()
                result = core_runtime().handle_ipc(payload, caller=caller)
                return self.reply(200 if result.get("success") else 400, result)
            except (ValueError, UnicodeDecodeError, RequestError) as error:
                return self.reply(400, {"protocolVersion": 1,
                    "requestId": "invalid", "timestamp": time.time(),
                    "success": False, "result": None,
                    "errorCode": "INVALID_REQUEST", "errorMessage": str(error)})
        if self.path == "/v1/device-password":
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n < 1 or n > 1024:
                    raise RequestError("invalid account-password request length")
                payload = json.loads(self.rfile.read(n).decode("utf-8"))
                result = set_device_account_password(payload)
                # Deliberately log only the account and result. The request
                # body contains cleartext transiently and must never enter the
                # bridge audit log.
                with open(LOG, "a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"operation": "device-password",
                        "account": payload.get("account"),
                        "status": result["status"]}) + "\n")
                return self.reply(200, result)
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError,
                    RequestError) as error:
                return self.reply(400, {"status": 22, "stdout": "",
                                        "stderr": str(error)})
            except Exception:
                # Do not include exception text here: some runtimes may echo
                # request data in an error, and this endpoint handles secrets.
                return self.reply(500, {"status": 125, "stdout": "",
                    "stderr": "Unable to update password securely"})
        if self.path == "/v1/runtime/refresh":
            messages = ["[0-Sky] authenticated local refresh request",
                        "[0-Sky] rescanning installed dpkg/filter metadata"]
            local = subprocess.run(
                ["/var/jb/usr/bin/python3", RUNTIME_MANAGER, "sync"],
                cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
            messages.append("[runtime-manager] " +
                            (local.stdout + local.stderr).decode("utf-8", "replace").strip())
            messages.append("[0-Sky Control] auditing durable app Cryptex payloads")
            keeper = subprocess.run(
                ["/var/jb/usr/bin/python3", "/var/jb/usr/local/libexec/crypstore-keeper.py",
                 "--once", "--automatic"],
                cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False)
            messages.append(f"[0-Sky Control] keeper audit status={keeper.returncode}")
            messages.append("[SRD] rebuilding and renewing the ElleKit runtime Cryptex trust cache")
            result = queue_runtime_sync("0-Sky user refresh")
            messages.append(str(result.get("stdout") or "").strip())
            error = str(result.get("stderr") or "").strip()
            if error:
                messages.append("[error] " + error)
            # The runtime renewal restarts SpringBoard and can retire an MCM
            # registration while the durable app Cryptex remains mounted.
            # Reconcile again after renewal so 0-Sky Control does not become a
            # stale icon that immediately exits.
            if result.get("status") == 0:
                messages.append("[0-Sky Control] post-renewal registration health check")
                post = appctl(["repair-from-cryptex", "com.liquidsky.CrypStore"], timeout=180)
                messages.append("[0-Sky Control] post-renewal repair status=" + str(post.get("status")))
                if post.get("stdout"):
                    messages.append(str(post["stdout"]).strip())
            messages.append("[0-Sky] refresh complete" if result.get("status") == 0
                            else "[0-Sky] refresh failed")
            return self.reply(200, {"status": result.get("status", 125),
                                    "stdout": "\n".join(filter(None, messages)),
                                    "stderr": error, "runtime": runtime_status()})
        if self.path == "/v1/crypstore/repair":
            before = runtime_status()
            result = appctl(["repair-from-cryptex", "com.liquidsky.CrypStore"], timeout=180)
            after = runtime_status()
            return self.reply(200, {"status": result.get("status", 125),
                                    "stdout": "[0-Sky Control] bundled recovery requested\n" +
                                              str(result.get("stdout") or ""),
                                    "stderr": result.get("stderr", ""),
                                    "before": before, "runtime": after})
        if self.path not in ("/v1/trollstore", "/v1/geranium"):
            return self.reply(404,{"status":127,"stdout":"","stderr":"not found"})
        try:
            n=int(self.headers.get("Content-Length","0"))
            if n<1 or n>MAX_BODY: raise RequestError("invalid request length")
            request=json.loads(self.rfile.read(n).decode())
            if self.path == "/v1/geranium":
                return self.reply(200, run_geranium(request.get("arguments")))
            try:
                with open(LOG,"a",encoding="utf-8") as f:
                    f.write(json.dumps({"request_arguments":request.get("arguments")})+"\n")
            except OSError:
                pass
            args=validate(request.get("arguments"))
            installing = args[0] in ("install", "install-app-bundle")
            if args[0] == "repair-preferences":
                package = args[1] if len(args) == 2 else None
                report, refresh = repair_and_refresh_preferences(
                    package, reason=package or "0-Sky Control manual preference repair",
                    force_refresh=True)
                refresh_status = refresh.get("status", 125) if refresh else 0
                messages = [str(report.get("summary") or "Preference conversion completed")]
                if refresh:
                    messages.append(str(refresh.get("stdout") or refresh.get("stderr") or ""))
                return self.reply(200, {"status": refresh_status,
                    "stdout": "\n".join(filter(None, messages)),
                    "stderr": "" if refresh_status == 0 else str(refresh.get("stderr") or ""),
                    "preference_repair": report,
                    "preference_runtime_refresh": refresh})
            if args[0] == "export-app":
                started=time.monotonic()
                with LOCK:
                    result=export_app(args)
                result=attach_preference_repair(
                    result, reason="0-Sky Control IPA export preference audit")
                with open(LOG,"a",encoding="utf-8") as f:
                    f.write(json.dumps({"id":str(uuid.uuid4()),
                        "args":["export-app",os.path.basename(args[1]),os.path.basename(args[2])],
                        "status":result.get("status",125),
                        "duration_ms":int((time.monotonic()-started)*1000)})+"\n")
                return self.reply(200,result)
            if args[0] in ("export-app-deb", "export-package"):
                started=time.monotonic()
                with LOCK:
                    result=(export_app_deb(args) if args[0] == "export-app-deb"
                            else export_package(args))
                # Package export has already converted its package before
                # assembly; an app DEB export performs a global preference
                # audit. Only a changed conversion triggers an SRD renewal.
                if args[0] == "export-package":
                    report = result.get("preference_repair", {})
                    if result.get("status") == 0 and report.get("changed"):
                        _, refresh = repair_and_refresh_preferences(
                            args[1], reason=args[1], force_refresh=True)
                        result["preference_runtime_refresh"] = refresh
                else:
                    result=attach_preference_repair(
                        result, reason="0-Sky Control app DEB export preference audit")
                with open(LOG,"a",encoding="utf-8") as f:
                    f.write(json.dumps({"id":str(uuid.uuid4()),
                        "args":[args[0],os.path.basename(args[1]),os.path.basename(args[2])],
                        "status":result.get("status",125),
                        "duration_ms":int((time.monotonic()-started)*1000)})+"\n")
                return self.reply(200,result)
            if args[0] == "install-deb":
                started=time.monotonic()
                result=install_deb(args[-1])
                if result.get("status") == 0:
                    journal_change("package_installed", result.get("package") or
                                   os.path.basename(args[-1]), current={
                                       "version": result.get("version"),
                                       "tweakCount": result.get("tweak_count", 0),
                                       "preferenceBundleCount": result.get(
                                           "preference_bundle_count", 0),
                                   }, transaction_id=str(uuid.uuid4()))
                with open(LOG,"a",encoding="utf-8") as f:
                    f.write(json.dumps({"id":str(uuid.uuid4()),"args":["install-deb",os.path.basename(args[-1])],
                        "status":result.get("status",125),
                        "duration_ms":int((time.monotonic()-started)*1000),
                        "stdout":result.get("stdout",""),"stderr":result.get("stderr","")})+"\n")
                return self.reply(200,result)
            if args[0] in ("uninstall", "uninstall-path"):
                bundle = args[-1] if args[0] == "uninstall" else bundle_id_at_path(args[-1])
                if not bundle:
                    return self.reply(400, {"status": 126, "stdout": "",
                                            "stderr": "Unable to determine a safe bundle identifier"})
                result = appctl(["remove", bundle, "--reason", "removed from 0-Sky Control"])
                if result.get("status") == 0:
                    journal_change("application_removed", bundle,
                                   previous={"registered": True},
                                   current={"registered": False})
                return self.reply(200, result)
            if args[0] == "remove-package":
                result = remove_tweak_package(args[1])
                if result.get("status") == 0:
                    journal_change("package_removed", args[1],
                                   previous={"installed": True},
                                   current={"installed": False})
                return self.reply(200, result)
            if installing:
                started=time.monotonic()
                result=queue_install(args)
                result=attach_preference_repair(
                    result, reason="0-Sky Control IPA import preference audit")
                with open(LOG,"a",encoding="utf-8") as f:
                    f.write(json.dumps({"id":str(uuid.uuid4()),"args":args,
                        "status":result.get("status",125),
                        "duration_ms":int((time.monotonic()-started)*1000),
                        "stdout":result.get("stdout",""),"stderr":result.get("stderr","")})+"\n")
                return self.reply(200,result)
            # TrollStore's legacy LS registration dictionary is rejected by
            # iOS 27. Preserve the installed bundle, then register it with the
            # SRD-aware appregistrard helper instead.
            if installing and "skip-uicache" not in args:
                args.insert(-1, "skip-uicache")
            started=time.monotonic()
            with LOCK:
                p=subprocess.run([HELPER]+args,cwd="/var/jb/var/tmp",env=ENV,stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=900,check=False)
            out=p.stdout.decode("utf-8","replace")[:MAX_OUTPUT]; err=p.stderr.decode("utf-8","replace")[:MAX_OUTPUT]
            status=p.returncode
            if installing and status == 0:
                matches=re.findall(r"\[installApp\] new app path: (.+)", err)
                if not matches:
                    status=181
                    err += "\nSRD bridge could not determine the installed app path."
                else:
                    app_path=matches[-1].strip()
                    approved=inside(app_path, ("/var/containers/Bundle/Application/",
                                               "/private/var/containers/Bundle/Application/"))
                    with LOCK:
                        registration=subprocess.run(
                            [APPREGISTRARD,"register","--path",approved,"--absolute",
                             "--install-coordination"], cwd="/var/jb/var/tmp", env=ENV,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=120, check=False)
                    out += registration.stdout.decode("utf-8","replace")[:MAX_OUTPUT]
                    err += registration.stderr.decode("utf-8","replace")[:MAX_OUTPUT]
                    status = 0 if registration.returncode == 0 else 181
            with open(LOG,"a",encoding="utf-8") as f:
                f.write(json.dumps({"id":str(uuid.uuid4()),"args":args,"status":status,
                                    "duration_ms":int((time.monotonic()-started)*1000),
                                    "stdout":out,"stderr":err})+"\n")
            return self.reply(200,{"status":status,"stdout":out,"stderr":err})
        except subprocess.TimeoutExpired as e: return self.reply(504,{"status":124,"stdout":"","stderr":str(e)})
        except RequestError as e:
            try:
                with open(LOG,"a",encoding="utf-8") as f:
                    f.write(json.dumps({"rejected":str(e)})+"\n")
            except OSError:
                pass
            return self.reply(403,{"status":126,"stdout":"","stderr":str(e)})
        except Exception as e: return self.reply(500,{"status":125,"stdout":"","stderr":str(e)})

if __name__ == "__main__":
    Server((HOST,PORT),Handler).serve_forever()
