"""Bounded APT operations for the iOS 27 Sileo research build.

Sileo remains sandboxed.  Only this paired, authenticated device service may
launch APT, using the device's configured and signature-checked APT sources.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


BUNDLE_ID = "com.amywhile.sileo"
TOKEN_FILE = Path("/var/jb/etc/0sky-sileo-bridge.token")
DATA_ROOT = Path("/private/var/mobile/Containers/Data/Application")
CONTAINER_RECORD = Path("/var/jb/etc/0sky-sileo-container.json")
APP_TOKEN_NAME = "0sky-sileo-bridge.token"
APP_IDENTITY_NAME = "0sky-device-identity.json"
AUTHORIZED_ARCHIVE_DIRECTORY = "0sky-authorized-packages"
APT = "/var/jb/usr/bin/apt-get"
APT_CACHE = "/var/jb/usr/bin/apt-cache"
DPKG_DEB = "/var/jb/usr/bin/dpkg-deb"
APT_SOURCES = Path("/var/jb/etc/apt/sources.list.d")
APT_LISTS = Path("/var/jb/var/lib/apt/lists")
APT_KEYS = Path("/var/jb/etc/apt")
SOURCE_MANIFEST = Path(__file__).with_name("apt_source_manifest.json")
SOURCE_MANIFEST_SHA256 = "7872ab40c878c7735d756728dd9b709fbcf934faba67460bcc92ad9691187640"
DPKG_STATUS = Path("/var/jb/Library/dpkg/status")
REFRESH_STAMP = Path("/var/jb/var/lib/0sky/sileo-source-refresh-stamp")
PACKAGE_ID = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}\Z")
VERSION = re.compile(r"[0-9][A-Za-z0-9.+:~_-]{0,127}\Z")
DEVICE_UDID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}\Z")
DEVICE_MODEL = re.compile(r"(?:iPhone|iPad)[0-9]{1,3},[0-9]{1,3}\Z")
ARCHIVE_NAME = re.compile(r"([0-9a-f]{64})\.deb\Z")
CONTAINER_NAME = re.compile(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\Z")
MAX_RESPONSE = 65536
PROTECTED_REMOVE_PACKAGES = frozenset({
    "apt", "dpkg", "ellekit", "preferenceloader", "sileo",
    "org.coolstar.sileo", "com.liquidskysecurity.srd-runtime-manager",
})
APT_OPTIONS = (
    "--no-remove", "-o", "APT::Get::AllowUnauthenticated=false",
    "-o", "Acquire::AllowInsecureRepositories=false",
    "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
    "-o", "Dpkg::Use-Pty=0", "-o", "APT::Sandbox::User=root",
)


class SileoRequestError(ValueError):
    pass


def _checked_token(path: Path) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_size != 65:
        raise SileoRequestError("Sileo Bridge credential failed ownership checks")
    value = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SileoRequestError("Sileo Bridge credential is invalid")
    return value


def authenticated(presented: str, token_file: Path = TOKEN_FILE) -> bool:
    if not isinstance(presented, str):
        return False
    try:
        expected = _checked_token(token_file)
    except (OSError, SileoRequestError, UnicodeError):
        return False
    return hmac.compare_digest(expected, presented)


def _validate_container(candidate: Path, root: Path) -> Path:
    if (not candidate.is_absolute() or candidate.parent != root or
            not CONTAINER_NAME.fullmatch(candidate.name) or
            candidate.is_symlink() or not candidate.is_dir()):
        raise SileoRequestError("recorded Sileo data container path is invalid")
    metadata = candidate / ".com.apple.mobile_container_manager.metadata.plist"
    try:
        info = metadata.lstat()
        identifier = plistlib.loads(metadata.read_bytes()).get("MCMMetadataIdentifier")
    except (OSError, ValueError) as error:
        raise SileoRequestError("recorded Sileo data container metadata is unavailable") from error
    if (not stat.S_ISREG(info.st_mode) or metadata.is_symlink() or
            identifier != BUNDLE_ID):
        raise SileoRequestError("recorded Sileo data container identity is invalid")
    return candidate


def _discover_container(root: Path = DATA_ROOT) -> Path:
    matches = []
    for child in root.iterdir():
        if child.is_symlink() or not child.is_dir():
            continue
        metadata = child / ".com.apple.mobile_container_manager.metadata.plist"
        if metadata.is_symlink() or not metadata.is_file():
            continue
        try:
            if plistlib.loads(metadata.read_bytes()).get("MCMMetadataIdentifier") == BUNDLE_ID:
                matches.append(child)
        except (OSError, ValueError):
            continue
    if len(matches) != 1:
        raise SileoRequestError("exactly one registered Sileo data container is required")
    return matches[0]


def _container(root: Path = DATA_ROOT,
               record: Path = CONTAINER_RECORD) -> Path:
    """Resolve the provisioned container without enumerating MCM at runtime.

    iOS permits the trusted provisioning process to discover the container, but
    a long-running launch daemon can be denied directory enumeration after an
    APT transaction.  The daemon therefore consumes a root-owned record and
    revalidates the exact container's MCM bundle identity before every use.
    """
    if root == DATA_ROOT and record.exists():
        try:
            info = record.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    info.st_mode & 0o077 or info.st_size > 1024):
                raise SileoRequestError("Sileo container record failed ownership checks")
            value = json.loads(record.read_text(encoding="utf-8"))
            required = {"schema", "bundle_id", "path", "device", "inode", "uid", "gid"}
            if (not isinstance(value, dict) or set(value) != required or
                    value.get("schema") != 2 or value.get("bundle_id") != BUNDLE_ID or
                    not isinstance(value.get("path"), str) or
                    any(not isinstance(value.get(key), int)
                        for key in ("device", "inode", "uid", "gid"))):
                raise SileoRequestError("Sileo container record is invalid")
            candidate = Path(value["path"])
            if (not candidate.is_absolute() or candidate.parent != root or
                    not CONTAINER_NAME.fullmatch(candidate.name) or candidate.is_symlink()):
                raise SileoRequestError("recorded Sileo data container path is invalid")
            candidate_info = candidate.lstat()
            observed = (candidate_info.st_dev, candidate_info.st_ino,
                        candidate_info.st_uid, candidate_info.st_gid)
            expected = (value["device"], value["inode"], value["uid"], value["gid"])
            if (not stat.S_ISDIR(candidate_info.st_mode) or candidate_info.st_uid == 0 or
                    observed != expected):
                raise SileoRequestError("recorded Sileo data container identity changed")
            return candidate
        except (OSError, UnicodeError, ValueError) as error:
            if isinstance(error, SileoRequestError):
                raise
            # App updates can retire the recorded MCM UUID. Rediscover only
            # when that exact directory vanished, then revalidate and pin the
            # replacement container before returning it. Other failures remain
            # fail closed.
            if isinstance(error, FileNotFoundError):
                discovered = _discover_container(root)
                if root == DATA_ROOT and os.geteuid() == 0:
                    _record_container(discovered, record)
                return discovered
            raise SileoRequestError("Sileo container record is unreadable") from error
    return _discover_container(root)


def _record_container(container: Path, record: Path = CONTAINER_RECORD) -> None:
    validated = _validate_container(container, DATA_ROOT)
    info = validated.lstat()
    if info.st_uid == 0:
        raise SileoRequestError("Sileo data container has unexpected root ownership")
    value = json.dumps({"schema": 2, "bundle_id": BUNDLE_ID,
                        "path": str(validated), "device": info.st_dev,
                        "inode": info.st_ino, "uid": info.st_uid,
                        "gid": info.st_gid},
                       separators=(",", ":"), sort_keys=True).encode("utf-8")
    record.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _atomic_credential(record, value, 0, 0)


def provision(token_file: Path = TOKEN_FILE, data_root: Path = DATA_ROOT,
              device_identity: dict[str, object] | None = None) -> str:
    """Called by the trusted installer after registration, never by Sileo."""
    if os.geteuid() != 0:
        raise SileoRequestError("root installer is required")
    container = _discover_container(data_root)
    documents = container / "Documents"
    if documents.is_symlink() or not documents.is_dir():
        raise SileoRequestError("Sileo Documents container is unavailable")
    app_token = documents / APP_TOKEN_NAME
    if app_token.is_symlink():
        raise SileoRequestError("Sileo Bridge credential path is symbolic")
    if token_file.exists():
        value = _checked_token(token_file)
    else:
        value = secrets.token_hex(32)
        token_file.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        _atomic_credential(token_file, value, 0, 0)
    owner = container.stat()
    if owner.st_uid == 0:
        raise SileoRequestError("Sileo data container has unexpected root ownership")
    _atomic_credential(app_token, value, owner.st_uid, owner.st_gid)
    mirror_existing_sources(documents, owner.st_uid, owner.st_gid)
    if device_identity is not None:
        _provision_device_identity(documents, owner.st_uid, owner.st_gid,
                                   device_identity)
    if data_root == DATA_ROOT:
        _record_container(container)
    return "SILEO_BRIDGE_CREDENTIAL_PROVISIONED"


def _provision_device_identity(documents: Path, uid: int, gid: int,
                               identity: dict[str, object]) -> None:
    """Publish only the identity fields required by a repository login flow."""
    if (not isinstance(identity, dict) or set(identity) != {"udid", "model"} or
            not isinstance(identity.get("udid"), str) or
            not isinstance(identity.get("model"), str) or
            not DEVICE_UDID.fullmatch(identity["udid"]) or
            not DEVICE_MODEL.fullmatch(identity["model"])):
        raise SileoRequestError("validated device identity is required")
    destination = documents / APP_IDENTITY_NAME
    if destination.is_symlink():
        raise SileoRequestError("Sileo device identity path is symbolic")
    value = json.dumps({"schema": 1, "udid": identity["udid"],
                        "model": identity["model"]},
                       separators=(",", ":"), sort_keys=True).encode("ascii")
    _atomic_credential(destination, value, uid, gid)


def _deb822_fields(raw: str) -> dict[str, str]:
    result = {}
    for line in raw.splitlines():
        if line.startswith((" ", "\t")) or ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.lower()] = value.strip()
    return result


def _reviewed_manifest(path: Path = SOURCE_MANIFEST) -> list[dict]:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
            info.st_mode & 0o022 or
            info.st_size > 32768):
        raise SileoRequestError("reviewed APT source manifest is unsafe")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_MANIFEST_SHA256:
        raise SileoRequestError("reviewed APT source manifest hash changed")
    manifest = json.loads(raw)
    if (manifest.get("schema_version") != 1 or
            not isinstance(manifest.get("sources"), list)):
        raise SileoRequestError("reviewed APT source manifest is malformed")
    return manifest["sources"]


def _reviewed_key(source: dict, fields: dict[str, str], key_root: Path) -> Path | None:
    identifier = source.get("id")
    if identifier not in {"procursus", "chariz", "havoc"}:
        return None
    name = "memo.gpg" if identifier == "procursus" else identifier + ".gpg"
    candidates = [key_root / "trusted.gpg.d" / name]
    if identifier != "procursus":
        candidates.insert(0, key_root / "keyrings" / ("0sky-" + name))
    configured = fields.get("signed-by")
    if configured:
        selected = Path(configured)
        if selected not in candidates:
            return None
        candidates = [selected]
    elif identifier != "procursus":
        return None
    for key in candidates:
        try:
            parent, info = key.parent.lstat(), key.lstat()
            if (stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and
                    not parent.st_mode & 0o022 and
                    stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                    not info.st_mode & 0o022 and
                    hashlib.sha256(key.read_bytes()).hexdigest() == source["key_sha256"]):
                return key
        except (OSError, KeyError):
            continue
    return None


def _release_evidence(source: dict, key: Path, list_root: Path,
                      run=subprocess.run) -> bool:
    identifier = source["id"]
    if identifier == "procursus":
        release = list_root / "apt.procurs.us_dists_1900_InRelease"
        arguments = ["/var/jb/usr/bin/gpgv", "--status-fd", "1", "--keyring",
                     str(key), str(release)]
    else:
        host = "repo.chariz.com" if identifier == "chariz" else "havoc.app"
        release = list_root / (host + "_._Release")
        arguments = ["/var/jb/usr/bin/gpgv", "--status-fd", "1", "--keyring",
                     str(key), str(release) + ".gpg", str(release)]
    try:
        info = release.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_mode & 0o022 or info.st_size > 4 * 1024 * 1024):
            return False
        result = run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, timeout=30, check=False)
        return (result.returncode == 0 and len(result.stdout) <= 8192 and
                ("[GNUPG:] VALIDSIG " + source["signing_fingerprint"] + " ").encode()
                in result.stdout)
    except (OSError, KeyError, subprocess.TimeoutExpired):
        return False


def reviewed_sources(*, source_root: Path = APT_SOURCES, list_root: Path = APT_LISTS,
                     key_root: Path = APT_KEYS, verify_cached: bool = True,
                     run=subprocess.run) -> list[dict[str, str]]:
    """Build canonical stanzas from pinned source identities and key bytes."""
    directory = source_root.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid() or
            directory.st_mode & 0o022):
        raise SileoRequestError("APT source directory is unsafe")
    configured = []
    for path in sorted(source_root.glob("*.sources")):
        try:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    info.st_mode & 0o022 or
                    info.st_size > 65536):
                continue
            configured.append(_deb822_fields(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError):
            continue
    selected = []
    for source in _reviewed_manifest():
        identifier = source.get("id")
        if (identifier not in {"procursus", "chariz", "havoc"} or
                source.get("trust_state") not in {"OFFICIAL", "VERIFIED_COMMUNITY"}):
            continue
        for fields in configured:
            if (fields.get("types") != "deb" or fields.get("uris") != source.get("uri") or
                    fields.get("suites") != source.get("suite") or
                    fields.get("components", "") != source.get("components", "") or
                    fields.get("architectures", source.get("architecture")) != source.get("architecture") or
                    fields.get("trusted", "").lower() in {"yes", "true", "1"}):
                continue
            key = _reviewed_key(source, fields, key_root)
            if key is None or (verify_cached and not _release_evidence(source, key, list_root, run=run)):
                continue
            stanza = ("Types: deb\nURIs: " + source["uri"] + "\nSuites: " +
                      source["suite"] + "\nArchitectures: " + source["architecture"] +
                      "\nSigned-By: " + str(key) + "\n")
            if source.get("components"):
                stanza += "Components: " + source["components"] + "\n"
            selected.append({"id": identifier, "uri": source["uri"],
                             "host": urlsplit(source["uri"]).hostname or "",
                             "stanza": stanza})
            break
    if not selected or not any(item["id"] == "procursus" for item in selected):
        raise SileoRequestError("reviewed Procursus APT source is unavailable")
    return selected


@contextmanager
def isolated_apt_sources(*, source_root: Path = APT_SOURCES,
                         list_root: Path = APT_LISTS, key_root: Path = APT_KEYS,
                         temporary_root: Path = Path("/var/jb/var/tmp"),
                         verify_cached: bool = True, run=subprocess.run):
    approved = reviewed_sources(source_root=source_root, list_root=list_root,
                                key_root=key_root, verify_cached=verify_cached,
                                run=run)
    with tempfile.TemporaryDirectory(prefix=".0sky-sileo-sources-",
                                     dir=temporary_root) as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        for source in approved:
            (root / (source["id"] + ".sources")).write_text(source["stanza"], encoding="utf-8")
        yield ["-o", "Dir::Etc::sourcelist=/dev/null",
               "-o", "Dir::Etc::sourceparts=" + str(root)]


def mirror_existing_sources(documents: Path, uid: int, gid: int,
                            source_root: Path = APT_SOURCES,
                            list_root: Path = APT_LISTS) -> dict:
    """Copy signed, currently configured root APT metadata into Sileo data.

    Root APT remains the authority for installs.  This gives sandboxed Sileo
    a read-only view without exposing randomized preboot paths to the app.
    """
    if documents.is_symlink() or not documents.is_dir():
        raise SileoRequestError("Sileo Documents directory is unsafe")
    approved = reviewed_sources(source_root=source_root, list_root=list_root)
    selected = [item["stanza"] for item in approved]
    hosts = {item["host"] for item in approved}
    cache = documents / "lists"
    if cache.is_symlink() or (cache.exists() and not cache.is_dir()):
        raise SileoRequestError("Sileo list cache is unsafe")
    cache.mkdir(mode=0o700, exist_ok=True)
    os.chown(cache, uid, gid)
    os.chmod(cache, 0o700)
    copied = 0
    total = 0
    for path in sorted(list_root.iterdir()):
        if not any(path.name.startswith(host + "_") for host in hosts):
            continue
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022 or info.st_size > 16 * 1024 * 1024 or
                not path.name.endswith(("_Packages", "_Release", "_Release.gpg", "_InRelease"))):
            continue
        total += info.st_size
        if total > 64 * 1024 * 1024:
            raise SileoRequestError("signed APT metadata exceeds the Sileo cache limit")
        _atomic_credential(cache / path.name, path.read_bytes(), uid, gid)
        copied += 1
    source_path = documents / "sileo.sources"
    if source_path.is_symlink():
        raise SileoRequestError("Sileo sources file is symbolic")
    existing = source_path.read_text(encoding="utf-8") if source_path.exists() else ""
    if len(existing.encode("utf-8")) > 65536:
        raise SileoRequestError("existing Sileo source settings exceed the size limit")
    existing_uris = {entry.get("uris") for block in existing.split("\n\n")
                     if (entry := _deb822_fields(block)).get("uris")}
    additions = [raw for raw in selected if _deb822_fields(raw).get("uris") not in existing_uris]
    merged = existing.rstrip() + ("\n\n" if existing.strip() and additions else "") + "\n\n".join(additions)
    _atomic_credential(source_path, merged.encode("utf-8") + b"\n", uid, gid)
    _mirror_status_file(documents, uid, gid, DPKG_STATUS)
    return {"signed_sources": len(selected), "cached_files": copied,
            "user_sources_preserved": bool(existing.strip())}


def _mirror_status_file(documents: Path, uid: int, gid: int,
                        status_path: Path) -> None:
    """Publish one bounded, root-owned dpkg snapshot to Sileo atomically."""
    raw = installed_status_snapshot(status_path)
    destination = documents / "sileo-dpkg-status"
    if destination.is_symlink():
        raise SileoRequestError("Sileo installed package view is symbolic")
    _atomic_credential(destination, raw, uid, gid)


def installed_status_snapshot(status_path: Path = DPKG_STATUS) -> bytes:
    """Read a bounded, root-owned dpkg status snapshot for an authenticated client."""
    descriptor = os.open(status_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022 or info.st_size > 4 * 1024 * 1024):
            raise SileoRequestError("installed package database failed ownership checks")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise SileoRequestError("installed package database exceeds the Sileo limit")
    finally:
        os.close(descriptor)
    return raw


def mirror_installed_status(*, data_root: Path = DATA_ROOT,
                            status_path: Path = DPKG_STATUS) -> None:
    """Refresh Sileo's installed view after a verified package transaction."""
    if os.geteuid() != 0:
        raise SileoRequestError("root installer is required")
    container = _container(data_root)
    documents = container / "Documents"
    if documents.is_symlink() or not documents.is_dir():
        raise SileoRequestError("Sileo Documents container is unavailable")
    owner = container.stat()
    if owner.st_uid == 0:
        raise SileoRequestError("Sileo data container has unexpected root ownership")
    _mirror_status_file(documents, owner.st_uid, owner.st_gid, status_path)


def _atomic_credential(path: Path, value: str | bytes, uid: int, gid: int) -> None:
    temporary = path.with_name(path.name + ".tmp." + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value if isinstance(value, bytes) else (value + "\n").encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _stage_authorized_archive(name: str, fields: dict[str, str], cwd: Path,
                              run=subprocess.run) -> Path:
    """Copy one Sileo download through an open descriptor and verify signed metadata."""
    match = ARCHIVE_NAME.fullmatch(name)
    expected_hash = fields.get("sha256", "").lower()
    try:
        expected_size = int(fields.get("size", ""))
    except ValueError as error:
        raise SileoRequestError("signed package size is invalid") from error
    if (match is None or match.group(1) != expected_hash or expected_size < 1 or
            expected_size > 512 * 1024 * 1024):
        raise SileoRequestError("authorized archive differs from signed package metadata")
    container = _container()
    owner = container.stat()
    documents = container / "Documents"
    directory = documents / AUTHORIZED_ARCHIVE_DIRECTORY
    for path, label in ((documents, "Documents"), (directory, "archive directory")):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or
                info.st_uid != owner.st_uid or info.st_mode & 0o022):
            raise SileoRequestError("Sileo " + label + " failed ownership checks")
    source = directory / name
    source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    temporary_descriptor = -1
    temporary_name = ""
    copy_complete = False
    try:
        info = os.fstat(source_descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner.st_uid or
                info.st_mode & 0o022 or info.st_size != expected_size):
            raise SileoRequestError("authorized archive failed ownership or size checks")
        temporary_descriptor, temporary_name = tempfile.mkstemp(
            prefix=".0sky-sileo-authorized-", suffix=".deb", dir=cwd)
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(source_descriptor, "rb", closefd=False) as source_stream, \
                os.fdopen(temporary_descriptor, "wb", closefd=False) as destination_stream:
            while chunk := source_stream.read(1024 * 1024):
                total += len(chunk)
                if total > expected_size:
                    raise SileoRequestError("authorized archive grew during validation")
                digest.update(chunk)
                destination_stream.write(chunk)
            destination_stream.flush()
            os.fsync(destination_stream.fileno())
        if total != expected_size or digest.hexdigest() != expected_hash:
            raise SileoRequestError("authorized archive hash verification failed")
        os.fchown(temporary_descriptor, 0, 0)
        os.fchmod(temporary_descriptor, 0o600)
        copy_complete = True
    finally:
        os.close(source_descriptor)
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if not copy_complete and temporary_name:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass
    staged = Path(temporary_name)
    try:
        control = run([DPKG_DEB, "-f", str(staged)], stdin=subprocess.DEVNULL,
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      timeout=30, check=False)
        if control.returncode or len(control.stdout) > 128 * 1024:
            raise SileoRequestError("authorized archive control metadata is invalid")
        actual = _deb822_fields(control.stdout.decode("utf-8", "replace"))
        expected = {key: fields.get(key, "") for key in
                    ("package", "version", "architecture")}
        if any(actual.get(key) != value for key, value in expected.items()):
            raise SileoRequestError("authorized archive identity differs from signed metadata")
        return staged
    except Exception:
        try:
            staged.unlink()
        except FileNotFoundError:
            pass
        raise


def validate_request(payload: object) -> tuple[str, list[str]]:
    if not isinstance(payload, dict) or set(payload) != {"operation", "packages"}:
        raise SileoRequestError("invalid Sileo package request")
    operation, packages = payload["operation"], payload["packages"]
    if operation == "refresh" and packages == []:
        return operation, []
    if (operation not in ("plan", "install", "plan-remove", "remove") or
            not isinstance(packages, list) or
            not 1 <= len(packages) <= (1 if operation in ("plan-remove", "remove") else 16)):
        raise SileoRequestError("unsupported Sileo package operation")
    specs = []
    for item in packages:
        if (not isinstance(item, dict) or
                not {"id", "version"}.issubset(item) or
                not set(item).issubset({"id", "version", "archive"})):
            raise SileoRequestError("invalid package selection")
        name, version = item["id"], item["version"]
        if (not isinstance(name, str) or not isinstance(version, str) or
                not PACKAGE_ID.fullmatch(name) or not VERSION.fullmatch(version)):
            raise SileoRequestError("invalid package identity or version")
        archive = item.get("archive")
        if archive is not None and (operation != "install" or
                not isinstance(archive, str) or not ARCHIVE_NAME.fullmatch(archive)):
            raise SileoRequestError("invalid authorized package archive")
        spec = name + "=" + version
        if spec in specs:
            raise SileoRequestError("duplicate package selection")
        specs.append(spec)
    return operation, specs


def selected_package_metadata(spec: str, *, env: dict[str, str], cwd: str,
                              expected_sha256: str | None = None,
                              source_options: tuple[str, ...] = (),
                              run=subprocess.run) -> dict[str, str]:
    """Read the exact APT version selected by Sileo before touching the device."""
    name, version = spec.split("=", 1)
    completed = run([APT_CACHE, *source_options, "show", spec], cwd=cwd, env=env,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode or len(completed.stdout) > 128 * 1024:
        raise SileoRequestError("selected package metadata is unavailable; refresh signed sources")
    matches = []
    for block in completed.stdout.decode("utf-8", "replace").split("\n\n"):
        fields = _deb822_fields(block)
        if (fields.get("package") == name and fields.get("version") == version and
                (expected_sha256 is None or
                 fields.get("sha256", "").lower() == expected_sha256)):
            matches.append(fields)
    if not matches or any((item.get("section"), item.get("architecture"),
                           item.get("depends")) !=
                          (matches[0].get("section"), matches[0].get("architecture"),
                           matches[0].get("depends")) for item in matches[1:]):
        raise SileoRequestError("selected package version has missing or conflicting metadata")
    return matches[0]


def compatibility_preflight(specs: list[str], *, env: dict[str, str], cwd: str,
                            archive_hashes: dict[str, str] | None = None,
                            staged_archives: dict[str, Path] | None = None,
                            source_options: tuple[str, ...] = (),
                            run=subprocess.run) -> dict | None:
    """Analyze exact tweak archives before admitting install-and-test.

    Metadata alone can identify a tweak but cannot establish compatibility.  A
    downloaded, hash-verified archive is sent through the compatibility engine;
    upstream jailbreak support declarations are never used as a negative SRD
    compatibility verdict.
    """
    decisions = []
    for spec in specs:
        fields = selected_package_metadata(spec, env=env, cwd=cwd,
                                           expected_sha256=(archive_hashes or {}).get(spec),
                                           source_options=source_options, run=run)
        if fields.get("architecture") not in {"iphoneos-arm64", "iphoneos-arm", "all"}:
            return {"admission": "BLOCKED", "compatibility_state":
                    "BLOCKED_BY_ARCHITECTURE", "blockers": [
                        spec.split("=", 1)[0] +
                        ": package architecture is unavailable on this SRD"]}
        section = fields.get("section", "").lower()
        dependencies = fields.get("depends", "").lower()
        if section.startswith("tweak") or any(name in dependencies for name in
                ("mobilesubstrate", "ellekit", "substitute", "libhooker")):
            archive = (staged_archives or {}).get(spec)
            if archive is None:
                return {"admission": "ANALYSIS_REQUIRED",
                        "compatibility_state": "ADAPTATION_REQUIRED",
                        "blockers": [spec.split("=", 1)[0] +
                            ": the exact package archive is required for analysis"]}
            try:
                from zero_sky_compat.tweak import analyze_verified_deb
                decision = analyze_verified_deb(archive, dpkg_deb=DPKG_DEB)
            except (OSError, ValueError, RuntimeError) as error:
                return {"admission": "ANALYSIS_REQUIRED",
                        "compatibility_state": "UNKNOWN",
                        "error_code": type(error).__name__,
                        "blockers": [spec.split("=", 1)[0] +
                            ": compatibility analysis did not complete"]}
            decision = dict(decision)
            decision["spec"] = spec
            decisions.append(decision)
            if decision.get("admission") != "INSTALL_AND_TEST":
                return decision
    return {"admission": "INSTALL_AND_TEST", "decisions": decisions} if decisions else None


def execute(payload: object, *, env: dict[str, str], cwd: str = "/var/jb/var/tmp",
            run=subprocess.run) -> dict:
    operation, specs = validate_request(payload)
    if operation == "remove":
        raise SileoRequestError("package removal requires the paired Bridge transaction")
    with isolated_apt_sources(temporary_root=Path(cwd),
                              verify_cached=operation != "refresh", run=run) as options:
        archives = {item["id"] + "=" + item["version"]:
                    item["archive"].removesuffix(".deb")
                    for item in payload.get("packages", [])
                    if isinstance(item, dict) and isinstance(item.get("archive"), str)}
        return _execute_selected(operation, specs, env=env, cwd=cwd,
                                 archive_items=payload.get("packages", []),
                                 archive_hashes=archives,
                                 source_options=tuple(options), run=run)


def _execute_selected(operation: str, specs: list[str], *, env: dict[str, str],
                      cwd: str, source_options: tuple[str, ...],
                      archive_items: list[dict] | None = None,
                      archive_hashes: dict[str, str] | None = None,
                      run=subprocess.run) -> dict:
    if operation == "plan-remove":
        package = specs[0].split("=", 1)[0]
        if package in PROTECTED_REMOVE_PACKAGES:
            return {"status": 193, "operation": operation, "result": "BLOCKED",
                    "stage": "PROTECTED_PACKAGE", "stdout": "",
                    "stderr": package + ": foundational package removal is blocked"}
    base = [APT, *source_options, *APT_OPTIONS]
    if operation == "refresh":
        previous = 0
        if REFRESH_STAMP.exists() and not REFRESH_STAMP.is_symlink():
            info = REFRESH_STAMP.stat()
            if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077 and info.st_size <= 32:
                try:
                    previous = int(REFRESH_STAMP.read_text(encoding="ascii").strip())
                except (ValueError, OSError, UnicodeError):
                    previous = 0
        now = int(time.time())
        if 0 <= now - previous < 900:
            container = _container()
            owner = container.stat()
            mirror = mirror_existing_sources(container / "Documents", owner.st_uid, owner.st_gid)
            return {"status": 0, "operation": "refresh", "stdout": "",
                    "stderr": "", "result": "CACHED_SOURCE_METADATA",
                    "apt_status": None, "source_cache": mirror, "packages": []}
        command = [APT, *source_options, "update", *APT_OPTIONS[1:]]
        timeout = 420
    elif operation == "plan":
        command = [APT, *source_options, "-sqf", *APT_OPTIONS,
                   "-o", "APT::Format::for-sileo=true",
                   "-o", "APT::Format::JSON=true", "install", "--reinstall", *specs]
        timeout = 90
    elif operation == "plan-remove":
        command = [APT, *source_options, "-sqf", *APT_OPTIONS[1:],
                   "-o", "APT::Format::for-sileo=true",
                   "-o", "APT::Format::JSON=true", "remove", specs[0].split("=", 1)[0]]
        timeout = 90
    else:
        staged = []
        adapted = []
        compatibility = None
        try:
            for item, spec in zip(archive_items or [], specs):
                archive = item.get("archive")
                if archive is not None:
                    fields = selected_package_metadata(
                        spec, env=env, cwd=cwd, expected_sha256=archive.removesuffix(".deb"),
                        source_options=source_options, run=run)
                    staged.append(_stage_authorized_archive(
                        archive, fields, Path(cwd), run=run))
            staged_specs = {item.get("id") + "=" + item.get("version"): path
                            for item, path in zip(
                                [value for value in (archive_items or []) if value.get("archive")],
                                staged)}
            compatibility = compatibility_preflight(
                specs, env=env, cwd=cwd, archive_hashes=archive_hashes,
                staged_archives=staged_specs,
                source_options=source_options, run=run)
            if compatibility and compatibility.get("admission") != "INSTALL_AND_TEST":
                evidence = ("package archive was downloaded and hash verified"
                            if staged else "signed package metadata was verified")
                blockers = compatibility.get("blockers") or [
                    "compatibility analysis requires a reviewed adapter"]
                state = compatibility.get("compatibility_state", "UNKNOWN")
                return {"status": 193, "operation": operation,
                        "result": ("BLOCKED" if str(state).startswith("BLOCKED_BY_")
                                   else "ANALYSIS_REQUIRED"),
                        "compatibility_state": state,
                        "stage": "COMPATIBILITY_ANALYSIS", "stdout": "",
                        "stderr": "; ".join(blockers) + "; " + evidence,
                        "recommended_remediation":
                            "Review the exact blocker in 0-Sky Control → Compatibility.",
                        "registry_key": compatibility.get("registry_key"),
                        "packages": [spec.split("=", 1)[0] for spec in specs]}
            install_archives = dict(staged_specs)
            for decision in (compatibility or {}).get("decisions", []):
                if not decision.get("requires_transformation"):
                    continue
                spec = decision.get("spec")
                source = staged_specs.get(spec)
                if source is None:
                    raise SileoRequestError(
                        "reviewed adaptation requires the verified package archive")
                from zero_sky_compat.tweak import adapt_verified_deb
                transformed = adapt_verified_deb(source, Path(cwd), dpkg_deb=DPKG_DEB)
                adapted.append(transformed["path"])
                install_archives[spec] = transformed["path"]
                decision["adapted_sha256"] = transformed["adapted_sha256"]
                decision["adapter_manifest"] = transformed["manifest"]
            arguments = [install_archives.get(spec, spec) for spec in specs]
            command = [*base, "install", "-y", "--reinstall", *arguments]
            timeout = 900
            completed = run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
        finally:
            for path in staged + adapted:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
    if operation != "install":
        completed = run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=timeout, check=False)
    stdout = completed.stdout.decode("utf-8", "replace")[:MAX_RESPONSE]
    stderr = completed.stderr.decode("utf-8", "replace")[:MAX_RESPONSE]
    if operation == "plan-remove" and completed.returncode == 0:
        operations = []
        for line in stdout.splitlines():
            if line.startswith("{"):
                try:
                    item = json.loads(line)
                except ValueError:
                    item = {}
                if isinstance(item, dict) and "Type" in item:
                    operations.append(item)
        package, version = specs[0].split("=", 1)
        if (len(operations) != 1 or operations[0].get("Type") != "Remv" or
                operations[0].get("Package") != package or
                operations[0].get("Version") != version):
            return {"status": 193, "operation": operation, "result": "BLOCKED",
                    "stage": "DEPENDENCY_PLAN", "stdout": "", "stderr":
                    "Removal would change additional packages or a different version; no package was removed",
                    "packages": [package]}
    if operation == "refresh":
        REFRESH_STAMP.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        _atomic_credential(REFRESH_STAMP, str(int(time.time())), 0, 0)
        container = _container()
        owner = container.stat()
        mirror = mirror_existing_sources(container / "Documents", owner.st_uid, owner.st_gid)
        return {"status": 0, "operation": "refresh", "stdout": stdout,
                "stderr": stderr, "result": "SOURCES_REFRESHED" if completed.returncode == 0 else
                          "CACHED_SOURCE_METADATA", "apt_status": completed.returncode,
                "source_cache": mirror, "packages": []}
    response = {"status": completed.returncode, "operation": operation,
            "stdout": stdout, "stderr": stderr,
            "result": "PLAN_READY" if operation in ("plan", "plan-remove") and completed.returncode == 0 else
                      "INSTALL_REQUIRES_VERIFICATION" if operation == "install" and completed.returncode == 0 else
                      "FAILED", "packages": [spec.split("=", 1)[0] for spec in specs]}
    if operation == "install" and compatibility:
        response["compatibility"] = compatibility
    return response
