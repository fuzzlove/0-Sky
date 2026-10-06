#!/var/jb/usr/bin/python3
"""Loopback-only, authenticated broker for fixed TrollStore Lite operations."""
import base64, crypt, glob, hashlib, hmac, json, os, pathlib, plistlib, re, shutil, stat, subprocess, sys, threading, time, traceback, uuid, zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# In the installed package zero_sky_core is adjacent to this script.  In the
# source tree it lives beside the existing runtime-manager implementation.
_HERE = pathlib.Path(__file__).resolve().parent
for _candidate in (_HERE, _HERE.parent / "tools/srd-runtime-manager"):
    if (_candidate / "zero_sky_core").is_dir() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from zero_sky_core import CoreRuntime
from zero_sky_core.bootsplash import snapshot as bootsplash_snapshot
from zero_sky_core import control_install_service
from zero_sky_core import sileo_package_service
from zero_sky_core.ipc import response as core_response, validate_request
from zero_sky_core.package_integration import PackageIntegrationError, resolve_owner

HOST, PORT = "127.0.0.1", 48654
TOKEN_FILE = "/var/jb/etc/trollstorelite-srd-bridge.token"
CONTROL_BUNDLE_ID = "com.liquidsky.CrypStore"
CONTROL_DATA_ROOT = "/var/mobile/Containers/Data/Application"
CONTROL_TOKEN_FILE = ("/var/mobile/Library/Application Support/Containers/"
                      "com.liquidsky.CrypStore/Documents/.0sky/bridge.token")
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

def sanitized_error_detail(error):
    """Bound exception text for the root-only log without credentials or host PII."""
    value = str(error)[:1024]
    value = re.sub(r"(?i)(token|password|secret)(\s*[:=]\s*)\S+",
                   r"\1\2<redacted>", value)
    value = re.sub(r"https?://[^/@\s]+:[^/@\s]+@", "https://<redacted>@", value)
    value = re.sub(r"/Users/[^/\s]+", "/Users/<redacted>", value)
    return value

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


def control_token_destinations(legacy_destination=CONTROL_TOKEN_FILE):
    """Return verified MCM and legacy token destinations for 0-Sky Control."""
    matching = []
    try:
        entries = list(os.scandir(CONTROL_DATA_ROOT))
    except OSError:
        entries = []
    for entry in entries:
        if not entry.is_dir(follow_symlinks=False):
            continue
        metadata = os.path.join(
            entry.path, ".com.apple.mobile_container_manager.metadata.plist")
        try:
            metadata_info = os.lstat(metadata)
            if (not stat.S_ISREG(metadata_info.st_mode) or
                    metadata_info.st_uid != 0):
                continue
            with open(metadata, "rb") as stream:
                values = plistlib.load(stream)
            if values.get("MCMMetadataIdentifier") != CONTROL_BUNDLE_ID:
                continue
            container = os.path.realpath(entry.path)
            root = os.path.realpath(CONTROL_DATA_ROOT) + os.sep
            if not container.startswith(root):
                continue
            documents = os.path.join(container, "Documents")
            documents_info = os.lstat(documents)
            if (not stat.S_ISDIR(documents_info.st_mode) or
                    documents_info.st_uid != 501):
                continue
            matching.append((metadata_info.st_mtime_ns, documents))
        except (OSError, ValueError, plistlib.InvalidFileException):
            continue
    destinations = []
    if matching:
        # Prefer the newest exact bundle match if an interrupted reinstall
        # left an older MCM container behind.
        matching.sort(reverse=True)
        destinations.append(os.path.join(
            matching[0][1], ".0sky", "bridge.token"))
    destinations.append(legacy_destination)
    return destinations


def _publish_control_bridge_token(value, destination, allowed_documents,
                                  uid=501, gid=501):
    parent = os.path.dirname(destination)
    documents = os.path.dirname(parent)
    if (os.path.realpath(documents) not in allowed_documents or
            os.path.lexists(parent) and os.path.islink(parent)):
        raise RuntimeError("Control token destination is unsafe")
    os.makedirs(parent, mode=0o700, exist_ok=True)
    os.chown(parent, uid, gid)
    os.chmod(parent, 0o700)
    temporary = destination + ".tmp." + str(os.getpid())
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return {"path": destination, "mode": "0600", "owner": uid}


def publish_control_bridge_token(source=TOKEN_FILE, destination=None,
                                 uid=501, gid=501):
    """Publish the device-local bridge token inside Control's private tree.

    iOS 27 applies the registered application's sandbox before legacy
    no-sandbox entitlements, so the app cannot read the rootless source file.
    The derivative contains no credential: this mode-0600 copy is generated on
    the device and refreshed by the root broker whenever it starts.
    """
    source_info = os.lstat(source)
    if (not stat.S_ISREG(source_info.st_mode) or source_info.st_uid != 0 or
            source_info.st_mode & 0o007 or source_info.st_size > 256):
        raise RuntimeError("bridge token source failed security checks")
    with open(source, "rb") as stream:
        value = stream.read(257)
    if (len(value) > 256 or len(value.strip()) < 64 or
            b"\0" in value or b"\r" in value):
        raise RuntimeError("bridge token source is invalid")
    destinations = ([destination] if destination else control_token_destinations())
    allowed_documents = {os.path.realpath(os.path.dirname(os.path.dirname(path)))
                         for path in destinations}
    results = [_publish_control_bridge_token(
        value, path, allowed_documents, uid=uid, gid=gid)
        for path in destinations]
    return results[0] if destination else results


def core_runtime():
    global _CORE_RUNTIME
    with CORE_LOCK:
        if _CORE_RUNTIME is None:
            # The runtime manager owns collection.  The bridge shares the same
            # database for bounded reads and must not duplicate sensor work.
            _CORE_RUNTIME = CoreRuntime(
                telemetry_owner=False, crane_handoff=queue_crane_target_handoffs)
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
            "control_installer_backend": heartbeat.get("control_installer_backend"),
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
    remote_ports = sorted({int(host["ssh_remote_port"]) for host in enrolled_hosts.values()
                           if str(host.get("ssh_remote_port", "")).isdigit()
                           and 1 <= int(host["ssh_remote_port"]) <= 65535})
    result.update({
        "ssh_remote_ports": remote_ports,
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

def queue_control_install(source, manifest):
    """Submit only the verified Link-bundled Control IPA to the paired worker."""
    status = worker_status()
    if not status["connected"] or status.get("control_installer_backend") != "paired-srd-worker-v1":
        return {"status": 190, "stderr": "Verified Mac Control installer is unavailable",
                "rollback": "NOT_NEEDED"}
    job_id = str(uuid.uuid4())
    root = os.path.join(SPOOL, job_id)
    os.makedirs(root, mode=0o700, exist_ok=False)
    destination = os.path.join(root, "input.ipa")
    expected = manifest["ipa_sha256"]
    try:
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o600)
        observed = _file_sha256(destination)
        if observed != expected:
            raise RuntimeError("staged Control IPA hash mismatch")
        atomic_json(os.path.join(root, "request.json"), {
            "job_id": job_id, "operation": "control-install",
            "original_name": "0-Sky Control",
            "source_sha256": expected,
            "required_entitlements": manifest["permissions"]["required_entitlements"],
            "created_at": int(time.time()),
        })
        result_path = os.path.join(root, "result.json")
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            if os.path.isfile(result_path):
                with open(result_path, "r", encoding="utf-8") as stream:
                    result = json.load(stream)
                if not isinstance(result, dict) or not isinstance(result.get("status"), int):
                    raise RuntimeError("Mac Control installer returned an invalid result")
                return result
            time.sleep(1)
        return {"status": 124, "stderr": "Mac Control installer timed out",
                "rollback": "UNKNOWN"}
    finally:
        try: os.unlink(destination)
        except OSError: pass


def queue_install(args, launch_validation=None):
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
        digest = hashlib.sha256()
        with open(destination, "rb") as staged:
            for block in iter(lambda: staged.read(1024 * 1024), b""):
                digest.update(block)
        if args[0] == "install-app-bundle":
            existing = verified_existing_app_integration(source, digest.hexdigest())
            if existing is not None:
                shutil.rmtree(root, ignore_errors=True)
                return existing
        request = {
            "job_id": job_id,
            "operation": "install",
            "original_name": os.path.basename(source),
            "arguments": args,
            "created_at": int(time.time()),
            "source_sha256": digest.hexdigest(),
        }
        if launch_validation is not None:
            request["launch_validation"] = launch_validation
        atomic_json(os.path.join(root, "request.json"), request)
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
    # A preceding app-integration job can hold the worker's serialized SSH
    # channel longer than the 15-second heartbeat freshness window. The worker
    # writes its result before its heartbeat thread can reacquire that channel,
    # so an immediate runtime-sync used to report status 190 even though the
    # same worker had just completed successfully. Give the post-job heartbeat
    # one bounded interval to arrive; a genuinely disconnected worker still
    # fails closed below.
    deadline = time.monotonic() + 20
    status = worker_status()
    while not status["connected"] and time.monotonic() < deadline:
        time.sleep(0.25)
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
        return {"apps": [], "tweaks": [], "preferences": [], "daemons": [],
                "adapters": []}

    apps = set()
    tweaks = set()
    preferences = set()
    daemons = set()
    adapters = set()
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
        if (path.startswith("/var/jb/usr/share/0-sky/package-adapters/") and
                lower.endswith(".json")):
            adapters.add(path)
    return {
        "apps": sorted(apps),
        "tweaks": sorted(tweaks),
        "preferences": sorted(preferences),
        "daemons": sorted(daemons),
        "adapters": sorted(adapters),
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


def archive_contains_runtime_code(deb_path):
    """Detect code whose first execution must wait for Cryptex renewal."""
    listed = subprocess.run(
        ["/var/jb/usr/bin/dpkg-deb", "--contents", deb_path],
        cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    if listed.returncode != 0:
        return False
    text = listed.stdout.decode("utf-8", "replace")
    return bool(re.search(
        r"(?:^|\s)(?:\./|/)?var/jb/(?:Library/MobileSubstrate/DynamicLibraries|"
        r"usr/lib/TweakInject)/[^\s/]+\.dylib(?:\s|$)",
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

TRUSTED_LAUNCHCTL_SHA256 = "a2d095b681cd4bf1ac819a7052b5b376516ed663bd989edc60d25297fa1e9bbc"


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def trusted_launchctl():
    patterns = (
        "/private/var/run/com.apple.security.cryptexd/mnt/"
        "com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd",
        "/private/var/run/com.apple.security.cryptexd/mnt/"
        "com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd",
    )
    candidates = []
    for pattern in patterns:
        candidates.extend(glob.glob(pattern))
    trusted = []
    for path in sorted(set(candidates)):
        try:
            if (os.path.isfile(path) and not os.path.islink(path) and
                    _file_sha256(path) == TRUSTED_LAUNCHCTL_SHA256):
                trusted.append(path)
        except OSError:
            pass
    if len(trusted) != 1:
        raise RuntimeError("exactly one verified SRD launch helper is required")
    probe = subprocess.run([trusted[0], "version"], cwd="/var/jb/var/tmp", env=ENV,
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=10, check=False)
    if probe.returncode:
        raise RuntimeError("verified SRD launch helper cannot execute")
    return trusted[0]


def validate_crane_binary_transformations(package, value):
    """Require the exact reviewed iOS 27 binary adaptation evidence."""
    expected = []
    if package == "com.opa334.crane":
        expected = [{
            "adapter": "ios27-native-menu-subtitle-v1",
            "path": ("/var/jb/Library/MobileSubstrate/DynamicLibraries/"
                     "CraneSB.dylib"),
            "original_sha256": ("2448ee43ab7ebe53322f117d13351710"
                                "48337f127d9f1a3139b2c48e15badc30"),
            "adapted_sha256": ("fced01a6d7bf59a1a5ac90842f1e7cb"
                               "0e8e83ae66e5e7612f6faf12115c83e1f"),
            "change": "use inherited UIMenuElement subtitle storage for CRSubtitleMenu",
            "reason": ("iOS 27 renders copied context-menu subtitles from UIKit's "
                       "native menu-element state"),
        }, {
            "adapter": "ios27-shared-cache-hook-v1",
            "path": ("/var/jb/Library/MobileSubstrate/DynamicLibraries/"
                     "CraneSupport.dylib"),
            "original_sha256": ("91f1d8969ad16051645e8dd34c4e67b7"
                                "49e2b80e23a9eb83b15e79323d5ca5f1"),
            "adapted_sha256": ("1cbd343957156e4668510dc2bff814d3"
                               "7896d028fa9d4a6c0b5b8d1d84f19159"),
            "change": "defer __CFPrefsGetPathForTriplet direct hook",
            "reason": ("iOS 27 rejects executable restoration of modified signed "
                       "shared-cache pages"),
        }, {
            "adapter": "ios27-rootless-support-signing-v1",
            "path": "/var/jb/usr/lib/libcrane.dylib",
            "original_sha256": ("c367a60abdd759bc8682521ccc5bdec6"
                                "bfee1869673b822b85fe31f298d2f058"),
            "adapted_sha256": ("a5a10059a4d9af20d03676d525e8d2c"
                               "ffbe37185227ae0090a9c54ffa7ccd595"),
            "change": "deterministic ad-hoc signature for the rootless support library",
            "reason": ("sandboxed iOS 27 daemon injection requires the dependency bytes "
                       "to match the active SRD trust-cache generation"),
        }, {
            "adapter": "ios27-preference-bundle-signing-v1",
            "path": ("/var/jb/Library/PreferenceBundles/"
                     "CranePrefs.bundle/CranePrefs"),
            "original_sha256": ("20d85ee4f3c656162ac7cb5805ef14f07"
                                "6b4ef283935a8cc7d276e379754e3a8"),
            "adapted_sha256": ("f785613bba274b1f9f10f95180d73e77"
                               "79fc8640cacdbad1bfaa083668b302b7"),
            "change": "deterministic ad-hoc signature for the Crane preference executable",
            "reason": ("iOS 27 rejects direct NSBundle loading when the package reinstall "
                       "restores Crane's unsigned preference executable"),
        }, {
            "adapter": "ios27-springboard-menu-children-v6",
            "path": ("/var/jb/Library/MobileSubstrate/DynamicLibraries/"
                     "CraneSBCompat.dylib"),
            "source_sha256": ("eda48d25c8699521386c327746ba52ec"
                              "dbb0130c01dd209cd6a033ee0e3987c5"),
            "adapted_sha256": ("420b7efc5b0efb8776c08959506e96e8"
                               "0243fb065f656e1c9f51c1e65732b8a9"),
            "filter_sha256": ("e7dc57a8e03d8bfbdcc532669806e918"
                              "49452e5974645aad9dffde2d6e2a90d5"),
            "change": "replace the sentinel in UIMenu children using Crane's reviewed menu builder",
            "reason": ("iOS 27 bypasses Crane's legacy private menu-construction hooks "
                       "after producing a title-based container-selection sentinel"),
        }]
    if value != expected:
        raise RuntimeError(package + ": binary transformations differ from the reviewed contract")


def validate_crane_applications(package, value):
    """Require an exact lifecycle contract for Crane's hidden companion app."""
    expected = []
    if package == "com.opa334.crane":
        expected = [{
            "path": "/var/jb/Applications/CraneApplication.app",
            "bundle_identifier": "com.opa334.CraneApplication",
            "role": "hidden-companion",
            "launch_validation": "controlled-exit-v1",
            "original_executable_sha256": (
                "485210d727140983493be0b7fc9cbcc724b8c696dc5becd86af9d6b2bb5289e6"
            ),
        }]
    if value != expected:
        raise RuntimeError(package + ": application lifecycle contract differs")


def package_adapter_manifest(package, payload):
    expected = "/var/jb/usr/share/0-sky/package-adapters/" + package + ".json"
    if payload.get("adapters") != [expected]:
        return None
    info = os.lstat(expected)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_mode & 0o022 or info.st_size > 64 * 1024):
        raise RuntimeError(package + ": package adapter manifest is not protected")
    with open(expected, "rb") as stream:
        value = json.load(stream)
    if (not isinstance(value, dict) or value.get("schema") != 1 or
            value.get("adapter") != "crane-family-v2" or
            value.get("package") != package or
            package not in ("com.opa334.crane", "com.opa334.cranelite")):
        raise RuntimeError(package + ": package adapter manifest is not supported")
    if set(value) != {"schema", "adapter", "package", "original_sha256",
                      "suppressed_scripts", "compatibility_components",
                      "permissions", "services", "runtime",
                      "binary_transformations", "applications"}:
        raise RuntimeError(package + ": package adapter manifest has unexpected fields")
    validate_crane_binary_transformations(package, value.get("binary_transformations"))
    validate_crane_applications(package, value.get("applications"))
    components = value.get("compatibility_components")
    expected_starter = (b"#!/bin/sh\n# 0-Sky crane-family-v2: cranehelperd is "
                        b"managed by the SRD service backend.\nexit 0\n")
    if (not isinstance(components, list) or len(components) != 1 or
            not isinstance(components[0], dict) or
            set(components[0]) != {"path", "original_sha256", "adapted_sha256",
                                   "adapter", "behavior"} or
            components[0].get("path") != "/var/jb/usr/local/bin/cranehelperd_start" or
            components[0].get("adapter") != "srd-service-starter-v1" or
            components[0].get("behavior") != "defer-to-transactional-service-backend" or
            not re.fullmatch(r"[0-9a-f]{64}",
                             str(components[0].get("original_sha256") or "")) or
            components[0].get("adapted_sha256") !=
                    hashlib.sha256(expected_starter).hexdigest()):
        raise RuntimeError(package + ": helper launcher adapter differs from the reviewed contract")
    starter = components[0]["path"]
    try:
        starter_info = os.lstat(starter)
        with open(starter, "rb") as stream:
            starter_payload = stream.read(len(expected_starter) + 1)
    except OSError as error:
        raise RuntimeError(package + ": helper launcher adapter is unavailable") from error
    if (not stat.S_ISREG(starter_info.st_mode) or starter_info.st_uid != 0 or
            starter_info.st_gid != 0 or starter_info.st_mode & 0o022 or
            not starter_info.st_mode & stat.S_IXUSR or starter_payload != expected_starter):
        raise RuntimeError(package + ": helper launcher adapter is not protected")
    runtime = value.get("runtime")
    root = "/var/jb/Library/MobileSubstrate/DynamicLibraries"
    expected_source = ({
        "kind": "plist-string",
        "path": "/var/mobile/Library/Preferences/com.opa334.craneliteprefs.plist",
        "key": "selectedApplication",
    } if package == "com.opa334.cranelite" else {
        "kind": "control-app-allowlist",
        "path": "/var/jb/var/lib/srd-runtime/tweak-targets/com.opa334.crane.json",
    })
    required_dylibs = [root + "/CraneSB.dylib", root + "/CraneSupport.dylib"]
    process_selectors = [{
        "dylib": root + "/CraneSB.dylib",
        "executable": "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
        "sandbox_dependencies": [
            "/var/jb/usr/lib/libcrane.dylib",
            "/var/jb/usr/lib/libsandy.dylib",
            "/var/jb/usr/lib/libellekit.dylib",
        ],
    }]
    if package == "com.opa334.crane":
        required_dylibs.insert(1, root + "/CraneSBCompat.dylib")
        process_selectors.append({
            "dylib": root + "/CraneSBCompat.dylib",
            "executable": "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
        })
    process_selectors.append({
        "dylib": root + "/CraneSupport.dylib",
        "executable": "/usr/sbin/cfprefsd",
        "environment": {
            "XPC_SERVICE_NAME": "com.apple.cfprefsd.xpc.daemon",
        },
        "sandbox_dependencies": [
            "/var/jb/usr/lib/libcrane.dylib",
            "/var/jb/usr/lib/libsandy.dylib",
            "/var/jb/usr/lib/libellekit.dylib",
        ],
    })
    expected_runtime = {
        "required_dylibs": required_dylibs,
        "configuration_dependent": [{
            "dylib": root + "/ Crane.dylib",
            "legacy_filter": "com.apple.Foundation",
            "target_source": expected_source,
            "sandbox_dependencies": [
                "/var/jb/usr/lib/libcrane.dylib",
                "/var/jb/usr/lib/libsandy.dylib",
                "/var/jb/usr/lib/libellekit.dylib",
            ],
        }],
        "process_selectors": process_selectors,
    }
    if runtime != expected_runtime:
        raise RuntimeError(package + ": runtime adapter differs from the reviewed contract")
    return value


def record_validated_runtime_adapter(package, manifest):
    """Publish Bridge-validated policy for already sealed runtime bytes."""
    source = pathlib.Path(
        "/var/jb/usr/share/0-sky/package-adapters/" + package + ".json")
    directory = pathlib.Path("/var/jb/var/lib/0-sky/validated-package-adapters")
    directory.mkdir(parents=True, exist_ok=True)
    os.chown(directory, 0, 0)
    os.chmod(directory, 0o700)
    record = {
        "schema": 1,
        "package": package,
        "adapter": manifest["adapter"],
        "manifest_sha256": _file_sha256(source),
        "runtime": manifest["runtime"],
        "validated_at": int(time.time()),
    }
    target = directory / (package + ".json")
    temporary = directory / ("." + package + "." + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(temporary,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        data = (json.dumps(record, sort_keys=True, separators=(",", ":")) +
                "\n").encode("utf-8")
        os.write(descriptor, data)
        os.fsync(descriptor)
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    os.replace(temporary, target)
    return str(target)


def _launch_job(launchctl, label):
    completed = subprocess.run(
        [launchctl, "print", "system/" + label], cwd="/var/jb/var/tmp", env=ENV,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False)
    text = completed.stdout.decode("utf-8", "replace")
    program = re.search(r"^\s*program = (.+)$", text, re.MULTILINE)
    pid = re.search(r"^\s*pid = ([0-9]+)$", text, re.MULTILINE)
    return {"loaded": completed.returncode == 0,
            "program": program.group(1).strip() if program else None,
            "pid": int(pid.group(1)) if pid else None,
            "output": text[-4000:]}


def _sealed_companion_path(package, logical_path):
    """Preflight one exact package-owned companion in the active Cryptex."""
    if (package not in ("com.opa334.crane", "com.opa334.cranelite") or
            logical_path != "/var/jb/usr/local/libexec/cranehelperd"):
        return None
    candidates = []
    pattern = (SRDSH_MOUNT_ROOT +
               "/codes.openai.research.ellekitloader.*/usr/share/0-sky/"
               "dynamic-tweak-manifest.json")
    for manifest_path in glob.glob(pattern):
        try:
            if os.path.islink(manifest_path) or os.path.getsize(manifest_path) > 4 * 1024 * 1024:
                continue
            with open(manifest_path, "r", encoding="utf-8") as stream:
                manifest = json.load(stream)
            records = [item for item in manifest.get("companion_executables", [])
                       if isinstance(item, dict) and item.get("kind") == "daemon"
                       and item.get("package") == package
                       and item.get("path") == logical_path
                       and re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256") or ""))]
            if manifest.get("schema") != 1 or len(records) != 1:
                continue
            digest = records[0]["sha256"]
            mount = pathlib.Path(manifest_path).parents[3]
            executable = (mount / "usr/libexec/ellekit/trust-payloads/companions" /
                          digest / "cranehelperd")
            if (executable.is_symlink() or not executable.is_file()
                    or not os.access(executable, os.X_OK)
                    or _file_sha256(executable) != digest):
                continue
            executable.resolve(strict=True).relative_to(
                pathlib.Path(SRDSH_MOUNT_ROOT).resolve(strict=True))
            candidates.append(executable)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue
    return str(max(candidates, key=lambda item: item.parents[6].stat().st_mtime_ns)) \
        if candidates else None


def _write_service_adapter(package, service):
    """Write a fixed launchd contract that resolves the current sealed helper."""
    sealed = _sealed_companion_path(package, service["program"])
    if sealed is None:
        raise RuntimeError(package + ": reviewed sealed helper is unavailable")
    directory = pathlib.Path("/var/jb/var/lib/0-sky/service-adapters")
    directory.mkdir(parents=True, exist_ok=True)
    os.chown(directory, 0, 0)
    os.chmod(directory, 0o700)
    target = directory / (service["label"] + ".plist")
    payload = {
        "Label": service["label"],
        "Program": "/var/jb/usr/bin/python3",
        "ProgramArguments": [
            "/var/jb/usr/bin/python3", RUNTIME_MANAGER, "launch-companion",
            package, service["program"],
        ],
        "EnvironmentVariables": {"_MSSafeMode": "1", "_SafeMode": "1"},
        "KeepAlive": True,
        "MachServices": {name: True for name in service["mach_services"]},
        "ProcessType": "Interactive",
        "RunAtLoad": True,
        "UserName": "root",
    }
    temporary = target.with_name(target.name + "." + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(temporary,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        data = plistlib.dumps(payload, fmt=plistlib.FMT_BINARY, sort_keys=True)
        os.write(descriptor, data)
        os.fsync(descriptor)
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    os.replace(temporary, target)
    return str(target), "/var/jb/usr/bin/python3", sealed


def activate_package_adapter(package, payload):
    manifest = package_adapter_manifest(package, payload)
    if manifest is None:
        return {"result": "NOT_APPLICABLE", "services": []}
    allowed_permissions = {
        "/var/jb/usr/local/libexec/cranehelperd": (0, 0, 0o755),
        "/var/jb/usr/local/bin/cranehelperd_start": (0, 0, 0o755),
    }
    if not isinstance(manifest.get("permissions"), list):
        raise RuntimeError(package + ": invalid adapter permissions")
    for record in manifest["permissions"]:
        if (not isinstance(record, dict) or
                set(record) != {"path", "uid", "gid", "mode"}):
            raise RuntimeError(package + ": invalid adapter permission record")
        expected = allowed_permissions.get(record.get("path"))
        try:
            actual = (int(record.get("uid")), int(record.get("gid")),
                      int(str(record.get("mode")), 8))
        except (TypeError, ValueError):
            actual = None
        path = record.get("path")
        if expected != actual or not isinstance(path, str) or os.path.islink(path):
            raise RuntimeError(package + ": unsupported adapter permission")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fchown(descriptor, expected[0], expected[1])
            os.fchmod(descriptor, expected[2])
        finally:
            os.close(descriptor)
    services = manifest.get("services")
    if not isinstance(services, list) or len(services) != 1:
        raise RuntimeError(package + ": invalid adapter service set")
    service = services[0]
    expected_service = {
        "label": "com.opa334.cranehelperd",
        "program": "/var/jb/usr/local/libexec/cranehelperd",
        "plist": "/var/jb/Library/LaunchDaemons/com.opa334.cranehelperd.plist",
        "mach_services": ["com.opa334.cranehelperd.preferences.xpc",
                          "com.opa334.cranehelperd.xpc"],
    }
    if service != expected_service or service["plist"] not in payload.get("daemons", []):
        raise RuntimeError(package + ": service adapter differs from installed payload")
    service_plist, effective_program, sealed_program = _write_service_adapter(
        package, service)
    launchctl = trusted_launchctl()
    before = _launch_job(launchctl, service["label"])
    if before["loaded"]:
        stopped = subprocess.run(
            [launchctl, "bootout", "system/" + service["label"]],
            cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
        if stopped.returncode:
            raise RuntimeError(package + ": existing helper service could not be retired")
    started = subprocess.run(
        [launchctl, "bootstrap", "system", service_plist],
        cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
    if started.returncode:
        raise RuntimeError(package + ": helper service bootstrap failed: " +
                           started.stderr.decode("utf-8", "replace")[-600:])
    current = {}
    for _ in range(20):
        time.sleep(0.25)
        current = _launch_job(launchctl, service["label"])
        if current.get("program") == effective_program and current.get("pid"):
            break
    if current.get("program") != effective_program or not current.get("pid"):
        evidence = str(current.get("output") or "")[-1200:]
        subprocess.run([launchctl, "bootout", "system/" + service["label"]],
                       cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=15, check=False)
        raise RuntimeError(package + ": helper service did not remain healthy: " + evidence)
    if any(name not in current.get("output", "") for name in service["mach_services"]):
        raise RuntimeError(package + ": helper service did not publish its required endpoints")
    policy = record_validated_runtime_adapter(package, manifest)
    return {"result": "PASS", "validated_runtime_policy": policy,
             "services": [{"label": service["label"],
             "program": service["program"], "sealed_program": sealed_program,
             "launcher": current["program"], "pid": current["pid"]}]}


def deactivate_package_adapter(package, payload):
    manifest = package_adapter_manifest(package, payload)
    if manifest is None:
        return {"result": "NOT_APPLICABLE", "services": []}
    launchctl = trusted_launchctl()
    stopped = []
    for service in manifest["services"]:
        state = _launch_job(launchctl, service["label"])
        if state["loaded"]:
            completed = subprocess.run(
                [launchctl, "bootout", "system/" + service["label"]],
                cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
            if completed.returncode:
                raise RuntimeError(package + ": helper service could not be stopped")
            stopped.append(service["label"])
    policy = pathlib.Path(
        "/var/jb/var/lib/0-sky/validated-package-adapters/" + package + ".json")
    policy.unlink(missing_ok=True)
    return {"result": "PASS", "services": stopped}


def integration_report(package_name, app_filter=None):
    """Register package-owned apps and report tweak/plugin activation state."""
    payload = package_payload(package_name)
    messages = []
    failures = []
    adapter = package_adapter_manifest(package_name, payload)
    for app_path in payload["apps"]:
        if app_filter is not None and app_path != app_filter:
            continue
        try:
            launch_validation = None
            if adapter is not None:
                with open(os.path.join(app_path, "Info.plist"), "rb") as stream:
                    app_bundle_id = plistlib.load(stream).get("CFBundleIdentifier")
                matches = [item for item in adapter["applications"]
                           if item["bundle_identifier"] == app_bundle_id]
                if len(matches) > 1:
                    raise RuntimeError("multiple application lifecycle contracts matched")
                launch_validation = matches[0] if matches else None
            result = queue_install(["install-app-bundle", app_path], launch_validation)
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
            f"Installed {len(payload['daemons'])} launch-daemon definition(s); activation requires the verified 0-Sky service backend.")
    if payload["tweaks"] or payload["preferences"]:
        ps_path = "/var/jb/usr/bin/ps" if os.access("/var/jb/usr/bin/ps", os.X_OK) else "/bin/ps"
        process_list = subprocess.run(
            [ps_path, "aux"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10, check=False).stdout.decode("utf-8", "replace")
        # The SRD runtime manager invokes the Cryptex loader for each target.
        # A loader process exits after injection, so its absence from ps is not
        # evidence that tweak injection is unavailable.
        manager_active = bool(re.search(
            r"/srd-runtime-manager\.py daemon(?:\s|$)", process_list))
        if manager_active:
            messages.append(
                f"Installed {len(payload['tweaks'])} tweak dylib(s); runtime manager active. "
                "Injection still requires a controlled runtime probe before READY.")
        else:
            # This report runs before queue_runtime_sync().  A stopped manager
            # is therefore a pre-sync observation, not evidence that the
            # package is incompatible.  The authenticated Mac sync below is
            # responsible for installing the new runtime generation and
            # starting the manager; tweak_runtime_validation() then requires
            # registry and live-loader evidence before the transaction can
            # commit.
            messages.append(
                f"Installed {len(payload['tweaks'])} tweak dylib(s); runtime manager "
                "activation is pending the verified Mac runtime sync.")
        # Do not ask the live manager to inject newly installed bytes before
        # queue_runtime_sync() has sealed those exact CodeDirectories into a
        # personalized trust generation. The authenticated Mac sync below
        # renews the Cryptex, restarts the manager, and performs first injection.
        messages.append("Dynamic ElleKit registry refresh deferred until the "
                        "authenticated Mac runtime sync completes.")
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


def queue_crane_container_cleanup(parameters):
    """Remove one user-deleted Crane container through the paired Mac.

    Crane can update its preference inventory inside the mobile bootstrap, but
    iOS 27 MAC denies that process traversal of another application's data
    container.  The Mac worker has the existing authorized SRD transport.  It
    independently revalidates the MCM owner and Crane metadata before deleting
    the exact orphan directory supplied here.
    """
    package = parameters.get("package")
    bundle_id = parameters.get("bundleID")
    container_id = parameters.get("containerID")
    requested_root = parameters.get("dataRoot")
    if package != "com.opa334.crane":
        raise RequestError("unsupported Crane package")
    if not isinstance(bundle_id, str) or not BUNDLE_ID.fullmatch(bundle_id):
        raise RequestError("invalid Crane application identifier")
    if bundle_id in {CONTROL_BUNDLE_ID, "codes.liquidsky.research.zerosky",
                     "com.amywhile.sileo", "com.opa334.CraneApplication"}:
        raise RequestError("protected application cannot be a Crane cleanup target")
    if (not isinstance(container_id, str) or not re.fullmatch(
            r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}",
            container_id)):
        raise RequestError("invalid Crane container identifier")

    runtime = core_runtime()
    eligible = {app.get("bundleID"): app.get("compatibility") for app in
                runtime._tweak_target_apps(package)["applications"]}
    if eligible.get(bundle_id) != "COMPATIBLE_WITH_ADAPTER":
        raise RequestError("Crane cleanup target has not passed the 0-Sky adapter")
    if (not isinstance(requested_root, str) or not re.fullmatch(
            r"/(?:private/)?var/mobile/Containers/Data/Application/"
            r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}",
            requested_root)):
        raise RequestError("Crane cleanup target is outside the MCM data root")
    data_root = ("/private" + requested_root
                 if requested_root.startswith("/var/mobile/") else requested_root)

    status = worker_status()
    if not status.get("connected"):
        return {"status": 190, "result": "BLOCKED", "stage": "BRIDGE",
                "stderr": "Connect the trusted Mac to finish deleting the Crane container."}
    job_id = str(uuid.uuid4())
    root = os.path.join(SPOOL, job_id)
    os.makedirs(root, mode=0o700, exist_ok=False)
    atomic_json(os.path.join(root, "request.json"), {
        "job_id": job_id,
        "operation": "crane-container-cleanup",
        "package": package,
        "bundle_id": bundle_id,
        "container_id": container_id.upper(),
        "data_root": data_root,
        "created_at": int(time.time()),
    })
    result_path = os.path.join(root, "result.json")
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if os.path.isfile(result_path):
            with open(result_path, "r", encoding="utf-8") as stream:
                result = json.load(stream)
            if not isinstance(result, dict) or not isinstance(result.get("status"), int):
                raise RuntimeError("Mac Crane cleanup returned an invalid result")
            return result
        time.sleep(0.25)
    return {"status": 124, "result": "FAILED", "stage": "CLEANUP",
            "stderr": "Timed out while the trusted Mac removed the Crane container."}


def queue_crane_target_handoffs(handoffs):
    """Commit Crane's per-app pre-main handoffs through paired root SSH."""
    if (not isinstance(handoffs, list) or len(handoffs) > 64 or
            not all(isinstance(item, dict) and
                    set(item) == {"bundle_id", "data_root", "active"}
                    for item in handoffs)):
        raise RequestError("invalid Crane target handoff plan")
    normalized = []
    seen = set()
    for item in handoffs:
        bundle_id = item["bundle_id"]
        data_root = item["data_root"]
        active = item["active"]
        if (not isinstance(bundle_id, str) or not BUNDLE_ID.fullmatch(bundle_id) or
                bundle_id in seen):
            raise RequestError("invalid or duplicate Crane handoff application")
        if (not isinstance(data_root, str) or not re.fullmatch(
                r"/private/var/mobile/Containers/Data/Application/"
                r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}",
                data_root)):
            raise RequestError("Crane handoff target is outside the MCM data root")
        if (active != "DEFAULT" and (not isinstance(active, str) or not re.fullmatch(
                r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}", active))):
            raise RequestError("invalid Crane active container")
        seen.add(bundle_id)
        normalized.append({"bundle_id": bundle_id, "data_root": data_root,
                           "active": active})
    if not normalized:
        return {"status": 0, "result": "PASS", "stage": "HANDOFF",
                "evidence": [], "rollback": "NOT_NEEDED"}
    status = worker_status()
    if not status.get("connected"):
        raise RequestError("Connect the trusted Mac to update Crane targets")
    job_id = str(uuid.uuid4())
    root = os.path.join(SPOOL, job_id)
    os.makedirs(root, mode=0o700, exist_ok=False)
    atomic_json(os.path.join(root, "request.json"), {
        "job_id": job_id,
        "operation": "crane-target-handoff",
        "package": "com.opa334.crane",
        "handoffs": normalized,
        "created_at": int(time.time()),
    })
    result_path = os.path.join(root, "result.json")
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if os.path.isfile(result_path):
            with open(result_path, "r", encoding="utf-8") as stream:
                result = json.load(stream)
            if not isinstance(result, dict) or not isinstance(result.get("status"), int):
                raise RuntimeError("Mac Crane handoff returned an invalid result")
            if result.get("status") != 0:
                raise RuntimeError(str(result.get("stderr") or
                                       "Mac Crane handoff transaction failed"))
            return result
        time.sleep(0.25)
    raise RuntimeError("Timed out while the trusted Mac updated Crane targets")


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


def _bundle_tree_sha256(root):
    """Match the host worker's content identity for an enrolled app bundle."""
    root = pathlib.Path(root)
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root))):
        relative = str(path.relative_to(root)).encode()
        if path.is_symlink():
            kind, value = b"L", os.readlink(path).encode()
        elif path.is_file():
            value = bytes.fromhex(_file_sha256(path))
            kind = b"F"
        elif path.is_dir():
            kind, value = b"D", b""
        else:
            kind, value = b"O", b""
        digest.update(kind + b"\0" + relative + b"\0" + value + b"\n")
    return digest.hexdigest()


def verified_existing_app_integration(source, source_sha256,
                                      state_root="/var/jb/var/lib/crypstore",
                                      mount_root="/private/var/run/com.apple.security.cryptexd/mnt/"):
    """Accept an exact, still healthy Cryptex integration idempotently.

    A transient RemoteXPC reset can occur while reinstalling an app that the
    same transaction already integrated successfully. Rebuilding that exact
    generation adds risk and caused the package transaction to roll back. The
    shortcut below requires the original IPA hash, current LaunchServices URL,
    mounted Cryptex, Info.plist, and complete MCM bundle hash to match the
    worker's prior strict enrollment evidence.
    """
    if not isinstance(source_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
        return None
    try:
        with open(os.path.join(source, "Info.plist"), "rb") as handle:
            info = plistlib.load(handle)
        bundle_id = info.get("CFBundleIdentifier")
        if not isinstance(bundle_id, str) or not BUNDLE_ID.fullmatch(bundle_id):
            return None
        state_path = pathlib.Path(state_root) / (bundle_id + ".json")
        metadata = state_path.lstat()
        if (state_path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or
                metadata.st_uid != 0 or metadata.st_mode & 0o022 or
                metadata.st_size > 64 * 1024):
            return None
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if (state.get("bundle_id") != bundle_id or
                state.get("source_sha256") != source_sha256):
            return None
        queried, registered = registered_bundle_path(bundle_id)
        if not queried or not registered:
            return None
        recorded = os.path.realpath(str(state.get("registered_path") or ""))
        observed = os.path.realpath(str(state.get("observed_registered_path") or recorded))
        if os.path.realpath(registered) not in {recorded, observed}:
            return None
        mount = os.path.realpath(str(state.get("mount") or ""))
        mount_root = os.path.realpath(mount_root).rstrip("/") + "/"
        if (not mount.startswith(mount_root) or not os.path.ismount(mount) or
                not os.path.isdir(os.path.join(mount, "Applications",
                                               os.path.basename(source)))):
            return None
        info_path = os.path.join(registered, "Info.plist")
        info_hash = _file_sha256(info_path)
        if (info_hash != state.get("expected_info_plist_hash") or
                _bundle_tree_sha256(registered) != state.get("expected_bundle_sha256")):
            return None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    return {"status": 0, "stdout":
            "Exact app artifact is already integrated through Cryptex/appregistrard.\n" +
            registered, "stderr": "", "bundle_id": bundle_id,
            "already_integrated": True,
            "foreground_launch": state.get("foreground_launch", "UNKNOWN")}


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


def tweak_runtime_validation(package, payload, timeout=60):
    """Require package-owned registry and live-loader evidence for a tweak."""
    tweak_paths = {os.path.realpath(value) for value in payload.get("tweaks", [])}
    if not tweak_paths:
        return {"result": "NOT_APPLICABLE", "expected": 0, "loaded": 0,
                "detail": "package owns no tweak dylib"}

    def read_json(name):
        path = os.path.join(RUNTIME_STATE_DIR, name)
        try:
            info = os.lstat(path)
            if (not stat.S_ISREG(info.st_mode) or info.st_size > 4 * 1024 * 1024):
                return {}
            with open(path, "r", encoding="utf-8") as handle:
                value = json.load(handle)
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    adapter = None
    try:
        adapter = package_adapter_manifest(package, payload)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
        # Adapter validation is an installation requirement and is reported by
        # activate_package_adapter.  Never use an invalid manifest to weaken
        # the set of dylibs required here.
        adapter = None
    runtime_contract = adapter.get("runtime", {}) if adapter else {}
    required_paths = {
        os.path.realpath(path) for path in runtime_contract.get("required_dylibs", [])
        if isinstance(path, str)
    }
    deferred = {
        os.path.realpath(item["dylib"]): item
        for item in runtime_contract.get("configuration_dependent", [])
        if isinstance(item, dict) and isinstance(item.get("dylib"), str)
    }
    # Every ordinary tweak dylib remains required. A reviewed typed adapter is
    # the only mechanism allowed to defer one until an explicit app selection.
    required_paths |= tweak_paths - set(deferred)

    def configured_deferred_paths():
        configured = set()
        for path, item in deferred.items():
            source = item.get("target_source", {})
            source_path = source.get("path")
            try:
                if not isinstance(source_path, str):
                    continue
                info = os.lstat(source_path)
                if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or
                        info.st_size > 1024 * 1024):
                    continue
                if source.get("kind") == "plist-string":
                    key = source.get("key")
                    if not isinstance(key, str):
                        continue
                    with open(source_path, "rb") as stream:
                        preferences = plistlib.load(stream)
                    if (isinstance(preferences, dict) and
                            isinstance(preferences.get(key), str) and preferences[key]):
                        configured.add(path)
                elif source.get("kind") == "control-app-allowlist":
                    with open(source_path, "r", encoding="utf-8") as stream:
                        allowlist = json.load(stream)
                    identifiers = allowlist.get("bundle_identifiers", []) \
                        if isinstance(allowlist, dict) else []
                    if (set(allowlist) == {"schema", "package", "bundle_identifiers",
                                          "updated_at"} and
                            allowlist.get("schema") == 1 and
                            allowlist.get("package") == package and
                            isinstance(identifiers, list) and identifiers and
                            len(identifiers) <= 64 and len(set(identifiers)) == len(identifiers) and
                            all(isinstance(value, str) and BUNDLE_ID.fullmatch(value)
                                for value in identifiers)):
                        configured.add(path)
            except (OSError, ValueError, TypeError, plistlib.InvalidFileException,
                    json.JSONDecodeError):
                continue
        return configured

    deadline = time.monotonic() + max(0, min(timeout, 60))
    last = None
    while True:
        registry = read_json("registry.json")
        state = read_json("injection-state.json")
        quarantine = read_json("injection-quarantine.json")
        quarantined = []
        for value in (quarantine.get("entries", {}) or {}).values():
            if isinstance(value, dict) and value.get("package") == package:
                quarantined.append({"target": value.get("target"),
                                    "reason": str(value.get("reason") or "quarantined")[:500]})
        expected = []
        targets = registry.get("targets", {})
        if isinstance(targets, dict):
            for target in targets.values():
                if not isinstance(target, dict):
                    continue
                target_name = str(target.get("name") or "")
                for dylib in target.get("dylibs", []):
                    if (isinstance(dylib, dict) and dylib.get("package") == package and
                            os.path.realpath(str(dylib.get("path") or "")) in tweak_paths):
                        expected.append({"target": target_name,
                                         "dylib": os.path.realpath(str(dylib.get("path") or "")),
                                         "sha256": str(dylib.get("sha256") or "")})
        loaded_rows = [value for value in (state.get("loaded", {}) or {}).values()
                       if isinstance(value, dict)]
        loaded = []
        for requirement in expected:
            for item in loaded_rows:
                if (item.get("target") == requirement["target"] and
                        os.path.realpath(str(item.get("dylib") or "")) == requirement["dylib"] and
                        item.get("sha256") == requirement["sha256"] and
                        isinstance(item.get("pid"), int)):
                    try:
                        os.kill(item["pid"], 0)
                    except OSError:
                        continue
                    loaded.append({**requirement, "pid": item["pid"]})
                    break
        if quarantined:
            return {"result": "FAIL", "expected": len(expected),
                    "loaded": len(loaded), "quarantine": quarantined,
                    "detail": "runtime manager quarantined the installed tweak"}
        registered_paths = {item["dylib"] for item in expected}
        configured_deferred = configured_deferred_paths()
        required_now = required_paths | configured_deferred
        missing_required = sorted(required_now - registered_paths)
        loaded_keys = {(item["target"], item["dylib"], item["sha256"])
                       for item in loaded}
        unloaded_required = [item for item in expected
                             if item["dylib"] in required_now and
                             (item["target"], item["dylib"], item["sha256"])
                             not in loaded_keys]
        deferred_unconfigured = sorted(set(deferred) - configured_deferred)
        complete = not missing_required and not unloaded_required
        result_value = ("PASS" if complete and not deferred_unconfigured else
                        "CONFIGURATION_REQUIRED" if complete and deferred_unconfigured else
                        "PENDING")
        if result_value == "PENDING" and time.monotonic() >= deadline:
            result_value = "FAIL"
        last = {"result": result_value,
                "expected": len(expected), "loaded": len(loaded),
                "missing_registry": sorted(tweak_paths - registered_paths),
                "missing_required": missing_required,
                "configuration_dependent": deferred_unconfigured,
                "targets": sorted({item["target"] for item in expected}),
                "detail": ("all required package-owned injection targets are loaded"
                           if result_value == "PASS" else
                           "select an application before validating the configurable app hook"
                           if result_value == "CONFIGURATION_REQUIRED" else
                           "a required runtime registry target or live injection is absent"
                           if result_value == "FAIL" else
                           "runtime registry or live target evidence is pending")}
        if last["result"] in ("PASS", "CONFIGURATION_REQUIRED", "FAIL"):
            return last
        time.sleep(1)


def record_compatibility_runtime(result, evidence):
    """Persist runtime evidence for every analyzed artifact in this request."""
    from zero_sky_compat.integration import record_runtime_validation
    compatibility = result.get("compatibility")
    decisions = compatibility.get("decisions", []) if isinstance(compatibility, dict) else []
    reports = []
    for decision in decisions:
        key = decision.get("registry_key") if isinstance(decision, dict) else None
        if not key:
            continue
        try:
            report = record_runtime_validation(key, evidence)
            reports.append({"registry_key": key,
                            "compatibility_state": report["compatibility_state"]})
        except (OSError, ValueError, RuntimeError) as error:
            reports.append({"registry_key": key, "compatibility_state": "UNKNOWN",
                            "error_code": type(error).__name__})
    return reports


def bundle_id_at_path(path):
    try:
        with open(os.path.join(path, "Info.plist"), "rb") as handle:
            value = plistlib.load(handle).get("CFBundleIdentifier")
        return value if isinstance(value, str) and BUNDLE_ID.fullmatch(value) else None
    except Exception:
        return None


def remove_tweak_package(package, expected_version=None):
    if package.lower() in sileo_package_service.PROTECTED_REMOVE_PACKAGES:
        return {"status": 126, "stdout": "", "stderr":
                "This foundational package cannot be removed from 0-Sky Control."}
    with LOCK:
        if (expected_version is not None and
                installed_package_versions().get(package) != expected_version):
            return {"status": 193, "stdout": "", "stderr":
                    "Installed package version changed; refresh before removing it."}
        payload = package_payload(package)
        if not payload["tweaks"] and not payload["preferences"]:
            return {"status": 126, "stdout": "", "stderr":
                    "Removal is limited to packages that own a tweak or preference bundle."}
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
            result, package=package, reason=package, force_refresh=True)
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
    pause_path = "/var/mobile/pl/srd-runtime-paused"
    pause_owned = False
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
        if archive_contains_runtime_code(destination) and not os.path.exists(pause_path):
            os.makedirs(os.path.dirname(pause_path), mode=0o755, exist_ok=True)
            descriptor = os.open(
                pause_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
            pause_owned = True
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
        if pause_owned:
            try: os.unlink(pause_path)
            except OSError: pass
        try: os.unlink(destination)
        except OSError: pass


def sileo_package_operation(request):
    """Run a user-selected Sileo APT operation in the paired root service."""
    operation, specs = sileo_package_service.validate_request(request)
    if operation in ("plan-remove", "remove"):
        package, version = specs[0].split("=", 1)
        if package in sileo_package_service.PROTECTED_REMOVE_PACKAGES:
            return {"status": 193, "result": "BLOCKED", "stage": "PROTECTED_PACKAGE",
                    "stdout": "", "stderr": package + ": foundational package removal is blocked"}
        if installed_package_versions().get(package) != version:
            return {"status": 193, "result": "BLOCKED", "stage": "VERSION_CHECK",
                    "stdout": "", "stderr": "Installed version changed; refresh Sileo before removal"}
        payload = package_payload(package)
        if not payload["tweaks"] and not payload["preferences"]:
            return {"status": 193, "result": "BLOCKED", "stage": "PACKAGE_CLASS",
                    "stdout": "", "stderr": "Sileo removal currently supports tweak packages with verified ownership"}
        plan_request = {"operation": "plan-remove", "packages": request["packages"]}
        with LOCK:
            plan = sileo_package_service.execute(plan_request, env=ENV)
        if plan.get("status") != 0 or operation == "plan-remove":
            return plan
        try:
            service_stop = deactivate_package_adapter(package, payload)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
            return {"status": 192, "result": "REPAIR_REQUIRED",
                    "stage": "SERVICE_STOP", "stdout": "",
                    "stderr": str(error)[:2048]}
        removed = remove_tweak_package(package, expected_version=version)
        if removed.get("status") != 0:
            if service_stop.get("result") == "PASS":
                try:
                    activate_package_adapter(package, payload)
                except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
                    pass
            return {**removed, "result": "REPAIR_REQUIRED" if package not in
                    installed_package_versions() else "FAILED", "stage": "REMOVE"}
        if package in installed_package_versions():
            return {**removed, "status": 192, "result": "REPAIR_REQUIRED",
                    "stage": "VERIFY_REMOVAL", "stderr": "Package remains installed after removal"}
        refresh = removed.get("preference_runtime_refresh") or {}
        if refresh.get("status") != 0:
            return {**removed, "status": 192, "result": "REPAIR_REQUIRED",
                    "stage": "RUNTIME_REFRESH", "stderr":
                    "Package removed, but the runtime refresh was not verified"}
        try:
            installed_status = sileo_package_service.installed_status_snapshot()
        except (OSError, sileo_package_service.SileoRequestError) as error:
            return {**removed, "status": 192, "result": "REPAIR_REQUIRED",
                    "stage": "STATUS_SNAPSHOT", "error_code": type(error).__name__,
                    "stderr": "Package removed, but its installed-state snapshot failed: "
                              + str(error)[:2048]}
        return {**removed, "result": "REMOVED_AND_VERIFIED", "stage": "VERIFY_REMOVAL",
                "removed_package": package,
                "service_stop": service_stop,
                "installed_status_b64": base64.b64encode(installed_status).decode("ascii")}
    if operation == "install" and not worker_status().get("connected"):
        return {"status": 190, "result": "BLOCKED", "stage": "PREFLIGHT",
                "stderr": "Connect the trusted Mac before installing packages or tweaks."}
    with LOCK:
        before = installed_package_versions() if operation == "install" else {}
        result = sileo_package_service.execute(request, env=ENV)
        if result["status"] != 0 or operation in ("plan", "refresh"):
            return result
        check = subprocess.run(
            ["/var/jb/usr/bin/apt-get", "check", "-o", "Dpkg::Use-Pty=0"],
            cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
        if check.returncode:
            return {**result, "status": 192, "result": "REPAIR_REQUIRED",
                    "stage": "DEPENDENCY_VERIFY", "stderr":
                    check.stderr.decode("utf-8", "replace")[:4096]}
        after = installed_package_versions()
        changed = sorted(package for package, version in after.items()
                         if before.get(package) != version)
        integration_failures = []
        integration_messages = []
        runtime_packages = []
        package_payloads = {}
        for package in changed:
            payload, messages, failures = integration_report(package)
            package_payloads[package] = payload
            integration_messages.extend(messages)
            integration_failures.extend(failures)
            # Writable-prefix installation does not admit a new Mach-O
            # CodeDirectory on an SRD. The host synchronizer safely inspects
            # dpkg-owned CLI code and its dependency closure too.
            runtime_packages.append(package)
            if payload["tweaks"] or payload["preferences"]:
                repair = preference_repair(package)
                if str(repair.get("summary", "")).startswith("Preference conversion failed"):
                    integration_failures.append(package + ": " + str(repair["summary"]))
        if runtime_packages and not integration_failures:
            sync = queue_runtime_sync(",".join(runtime_packages))
            if sync.get("status") != 0:
                integration_failures.append(str(sync.get("stderr") or
                                                 "injection runtime refresh failed"))
        runtime_evidence = {}
        service_evidence = {}
        if not integration_failures:
            for package, payload in package_payloads.items():
                if payload.get("adapters"):
                    try:
                        service_evidence[package] = activate_package_adapter(package, payload)
                    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
                        service_evidence[package] = {"result": "FAIL",
                            "detail": str(error)[:1000], "services": []}
                        integration_failures.append(package + ": " + str(error)[:1000])
                if payload["tweaks"]:
                    runtime_evidence[package] = tweak_runtime_validation(package, payload)
                    if runtime_evidence[package]["result"] == "FAIL":
                        integration_failures.append(
                            package + ": " + runtime_evidence[package]["detail"])
        result["changed_packages"] = changed
        result["integration_messages"] = integration_messages[:32]
        result["runtime_validation"] = runtime_evidence
        result["service_validation"] = service_evidence
        combined_evidence = list(runtime_evidence.values()) + list(service_evidence.values())
        if combined_evidence:
            aggregate = ("FAIL" if any(value["result"] == "FAIL"
                                       for value in combined_evidence) else
                         "PASS" if all(value["result"] == "PASS"
                                       for value in combined_evidence) else "PENDING")
            result["compatibility_reports"] = record_compatibility_runtime(
                result, {"result": aggregate, "functional": False,
                         "packages": runtime_evidence,
                         "services": service_evidence})
        if integration_failures:
            if not result.get("compatibility_reports"):
                result["compatibility_reports"] = record_compatibility_runtime(
                    result, {"result": "FAIL", "functional": False,
                             "stage": "RUNTIME_INTEGRATION",
                             "failures": integration_failures[:16]})
            fresh_tweaks = [package for package, payload in package_payloads.items()
                            if package not in before and payload["tweaks"]]
            rollback = []
            for package in reversed(fresh_tweaks):
                try:
                    deactivate_package_adapter(package, package_payloads[package])
                except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
                    pass
                removed = subprocess.run(
                    ["/var/jb/usr/bin/dpkg", "--remove", package],
                    cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=300, check=False)
                rollback.append({"package": package, "status": removed.returncode,
                                 "stderr": removed.stderr.decode("utf-8", "replace")[-1000:]})
            rollback_sync = None
            if fresh_tweaks:
                # The runtime-sync worker accepts only a comma-separated list
                # of exact dpkg package identifiers.  Prefixing this value
                # with a human-readable reason made rollback refreshes fail
                # validation and could leave removed tweak code in the active
                # runtime generation until the next successful sync.
                rollback_sync = queue_runtime_sync(",".join(fresh_tweaks))
            return {**result, "status": 192, "result": "REPAIR_REQUIRED",
                    "stage": "RUNTIME_INTEGRATION",
                    "rollback": rollback,
                    "rollback_runtime_sync": rollback_sync,
                    "rollback_verified": bool(rollback) and all(
                        item["status"] == 0 for item in rollback) and all(
                        package not in installed_package_versions() for package in fresh_tweaks) and
                        bool(rollback_sync) and rollback_sync.get("status") == 0,
                    "stderr": "\n".join(integration_failures)[:4096]}
        try:
            installed_status = sileo_package_service.installed_status_snapshot()
        except (OSError, sileo_package_service.SileoRequestError) as error:
            return {**result, "status": 192, "result": "REPAIR_REQUIRED",
                    "stage": "STATUS_SNAPSHOT", "error_code": type(error).__name__,
                    "stderr": "Package installed, but its installed-state snapshot failed: "
                              + str(error)[:2048]}
        all_loaded = bool(combined_evidence) and all(
            value["result"] == "PASS" for value in combined_evidence)
        return {**result,
                "result": "INSTALLED_AND_LOADED" if all_loaded else "INSTALLED_UNVERIFIED",
                "stage": "FUNCTIONAL_UAT_PENDING" if all_loaded else
                         "RUNTIME_SMOKE_TEST_PENDING",
                "installed_status_b64": base64.b64encode(installed_status).decode("ascii")}


def installed_package_versions():
    completed = subprocess.run(
        ["/var/jb/usr/bin/dpkg-query", "--show",
         "--showformat=${Package}\t${Version}\t${db:Status-Abbrev}\n"],
        cwd="/var/jb/var/tmp", env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode:
        raise RequestError("package database could not be read")
    values = {}
    for line in completed.stdout.decode("utf-8", "replace").splitlines():
        fields = line.split("\t")
        if len(fields) == 3 and fields[2].startswith("ii") and BUNDLE_ID.fullmatch(fields[0]):
            name, version = fields[:2]
            values[name] = version
    return values

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
                           "/v1/pairing/result", "/v1/bootsplash/status",
                           "/v1/control/install/status"):
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
        if parsed.path == "/v1/control/install/status":
            try:
                value = control_install_service.inspect(runtime_status, pairing_status, worker_status)
                return self.reply(200, control_install_service.public_status(value))
            except Exception as error:
                return self.reply(409, {"result": "BLOCKED", "stage": "PRECHECK",
                                        "code": type(error).__name__.upper(),
                                        "explanation": str(error)[:300]})
        if parsed.path == "/v1/pairing/status":
            return self.reply(200, pairing_status())
        if parsed.path == "/v1/bootsplash/status":
            status = bootsplash_snapshot(pairing_status, runtime_reader=runtime_status)
            try:
                core_runtime().logger.log("INFO", "CORE", "bootsplash snapshot",
                    root=status["root_status"], bootstrap=status["bootstrap_status"],
                    trustedHost=status["trusted_host_status"], ssh=status["ssh_status"],
                    runtime=status["runtime_status"], control=status["control_status"],
                    deviceMode=status["device_mode"],
                    durationMs=status["duration_ms"], diagnostics=status["diagnostics"])
            except Exception:
                pass
            return self.reply(200, status)
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
                            "/v1/device-password", "/v1/control/install")
        if self.path in privileged_paths:
            if not hmac.compare_digest(self.headers.get("X-TrollStore-Bridge-Token", ""),
                                       self.server.token):
                return self.reply(403, {"status": 126, "stdout": "",
                                        "stderr": "authentication failed"})
            # Pairing request and cancellation must be usable before trust is
            # established. They are still token-authenticated above. Gating
            # cancellation on pairing_status() made the Cancel button
            # impossible to use during the very operation it must stop.
            if self.path not in ("/v1/pairing/request", "/v1/pairing/cancel", "/v1/core"):
                denial = pairing_denial()
                if denial:
                    return self.reply(403, denial)
        if self.path == "/v1/sileo/package":
            if not sileo_package_service.authenticated(
                    self.headers.get("X-0Sky-Sileo-Token", "")):
                return self.reply(403, {"status": 126, "result": "BLOCKED",
                                        "stage": "AUTH", "stderr": "Sileo Bridge authentication failed"})
            denial = pairing_denial()
            if denial:
                return self.reply(403, {"status": denial.get("status", 193),
                                        "result": "BLOCKED", "stage": "TRUST",
                                        "stderr": denial.get("stderr", "Trusted Mac unavailable")})
            request_stage = "REQUEST_DECODE"
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size < 1 or size > 8192:
                    raise RequestError("invalid Sileo request size")
                request = json.loads(self.rfile.read(size).decode("utf-8"))
                request_stage = "PACKAGE_OPERATION"
                result = sileo_package_operation(request)
                with open(LOG, "a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"operation": "sileo-package",
                        "stage": result.get("stage"), "result": result.get("result"),
                        "status": result.get("status")}) + "\n")
                return self.reply(200 if result.get("status") == 0 else 409, result)
            except (ValueError, UnicodeDecodeError, RequestError,
                    sileo_package_service.SileoRequestError) as error:
                return self.reply(400, {"status": 126, "result": "BLOCKED",
                                        "stage": "VALIDATE", "stderr": str(error)[:300]})
            except subprocess.TimeoutExpired:
                return self.reply(504, {"status": 124, "result": "FAILED",
                                        "stage": "APT", "stderr": "APT timed out"})
            except Exception as error:
                # Never let an unexpected analysis or adapter error turn into
                # Sileo's opaque status 190. Preserve the traceback in the
                # root-only service log and return a bounded, credential-free
                # result. The client retains the exact verified archive for a
                # deterministic retry.
                traceback.print_exc(file=sys.stderr)
                try:
                    with open(LOG, "a", encoding="utf-8") as stream:
                        stream.write(json.dumps({
                            "operation": "sileo-package",
                            "stage": request_stage,
                            "result": "FAILED",
                            "status": 192,
                            "error_code": type(error).__name__,
                            "error_detail": sanitized_error_detail(error),
                        }, separators=(",", ":")) + "\n")
                except OSError:
                    pass
                return self.reply(500, {"status": 192, "result": "FAILED",
                    "stage": request_stage, "error_code": type(error).__name__,
                    "stderr": ("0-Sky Bridge failed during package preflight; "
                               "the verified archive was preserved for retry")})
        if self.path == "/v1/pairing/request":
            result = queue_pair_verify()
            return self.reply(202 if result.get("status") == 0 else 503, result)
        if self.path == "/v1/control/install":
            if self.headers.get("Content-Length", "0") not in ("0", ""):
                return self.reply(400, {"result": "BLOCKED", "code": "UNEXPECTED_BODY"})
            try:
                result = control_install_service.install(
                    runtime_status, pairing_status, worker_status, queue_control_install)
                with open(LOG, "a", encoding="utf-8") as stream:
                    for event in result.get("events", []):
                        stream.write(json.dumps(event, separators=(",", ":")) + "\n")
                return self.reply(200 if result.get("result") in
                                  ("INSTALLED_AND_VERIFIED", "ALREADY_INSTALLED_AND_VERIFIED")
                                  else 409, result)
            except Exception as error:
                return self.reply(409, {"result": "FAILED", "stage": "PRECHECK",
                                        "code": type(error).__name__.upper(),
                                        "explanation": str(error)[:300],
                                        "rollback": "NOT_NEEDED"})
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
                request = validate_request(payload)
                caller = pairing_status()
                # Local, token-authenticated reads remain available when the
                # Mac heartbeat or Apple pairing needs repair. Mutations retain
                # the live trusted-Mac requirement.
                if request.access == "write":
                    denial = pairing_denial()
                    if denial:
                        return self.reply(403, denial)
                if request.operation == "cleanupCraneContainer":
                    result = queue_crane_container_cleanup(request.parameters)
                    envelope = core_response(
                        request.request_id, result.get("status") == 0,
                        result=result if result.get("status") == 0 else None,
                        error_code=(None if result.get("status") == 0 else
                                    str(result.get("result") or "CLEANUP_FAILED")),
                        error_message=(None if result.get("status") == 0 else
                                       str(result.get("stderr") or
                                           "Crane container cleanup failed")),
                    )
                    return self.reply(200 if envelope["success"] else 409, envelope)
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
        if self.path in ("/v1/runtime/refresh", "/v1/crypstore/repair"):
            from zero_sky_compat.integration import CompatibilityBlocked, block_legacy_mutation
            try:
                block_legacy_mutation(self.path)
            except CompatibilityBlocked as error:
                return self.reply(409, {"status": 193, "stdout": "", "stderr": str(error)})
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
            if args[0] in ("repair-preferences", "refresh", "refresh-all", "transfer-apps",
                           "modify-registration", "enable-jit", "export-app", "export-app-deb", "export-package"):
                from zero_sky_compat.integration import CompatibilityBlocked, block_legacy_mutation
                try:
                    block_legacy_mutation(args[0])
                except CompatibilityBlocked as error:
                    return self.reply(409, {"status": 193, "stdout": "", "stderr": str(error)})
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

def integrate_package_app_cli(arguments):
    """Complete Sileo's post-apt app install through the existing Mac worker.

    Sileo invokes this as root with a typed argument array. The broker resolves
    package ownership itself; the app cannot name a package or a Cryptex job.
    """
    if len(arguments) != 1 or os.geteuid() != 0:
        return {"status": 126, "error": "root and one package app path are required"}
    try:
        app_path = arguments[0]
        package = resolve_owner(app_path)
        denial = pairing_denial()
        if denial:
            return {"status": 190, "package": package,
                    "error": "trusted Mac Bridge is unavailable for Cryptex integration"}
        payload = package_payload(package)
        if os.path.realpath(app_path) not in payload["apps"]:
            raise PackageIntegrationError("app is absent from its package file inventory")
        if payload["tweaks"] or payload["preferences"] or payload["daemons"]:
            return {"status": 192, "package": package,
                    "error": "mixed app/runtime package requires 0-Sky Control's transactional installer"}
        _, messages, failures = integration_report(
            package, app_filter=os.path.realpath(app_path))
        return {"status": 192 if failures else 0, "package": package,
                "integrated_apps": [os.path.basename(app_path)] if not failures else [],
                "messages": messages[:16], "errors": failures[:16]}
    except (PackageIntegrationError, OSError, subprocess.TimeoutExpired) as error:
        return {"status": 192, "error": str(error)[:300]}


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--provision-sileo-bridge" and len(sys.argv) == 2:
            try:
                raw_identity = sys.stdin.buffer.read(2049)
                if len(raw_identity) > 2048:
                    raise ValueError("Sileo identity request is too large")
                identity = (json.loads(raw_identity.decode("utf-8"))
                            if raw_identity.strip() else None)
                outcome = sileo_package_service.provision(device_identity=identity)
                print(json.dumps({"status": 0, "result": outcome}))
                raise SystemExit(0)
            except (OSError, ValueError) as error:
                print(json.dumps({"status": 126, "result": "BLOCKED",
                                  "error": str(error)[:300]}))
                raise SystemExit(126)
        if sys.argv[1] != "--integrate-package-app":
            print(json.dumps({"status": 126, "error": "unknown broker command"}))
            raise SystemExit(126)
        result = integrate_package_app_cli(sys.argv[2:])
        print(json.dumps(result, separators=(",", ":")))
        raise SystemExit(0 if result["status"] == 0 else 1)
    # The bridge's existing KeepAlive service is loaded after each rootless
    # bootstrap. Bind its status endpoint first, then start the isolated,
    # once-per-boot Link launcher. A failure cannot prevent the bridge serving.
    server = Server((HOST, PORT), Handler)
    try:
        publish_control_bridge_token()
    except Exception as error:
        try:
            core_runtime().logger.log("WARN", "CORE", "Control token publication failed",
                                      errorClass=type(error).__name__)
        except Exception:
            pass
    try:
        splash = pathlib.Path("/var/jb/usr/local/libexec/bootsplash-launch.py")
        if splash.is_file() and not splash.is_symlink():
            subprocess.Popen(["/var/jb/usr/bin/python3", str(splash)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, close_fds=True,
                             start_new_session=True)
    except Exception as error:
        try:
            core_runtime().logger.log("WARN", "CORE", "bootsplash launch failed",
                                      errorClass=type(error).__name__)
        except Exception:
            pass
    server.serve_forever()
