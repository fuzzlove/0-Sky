"""Bounded, integrity-checked application snapshots for authorized SRDs.

Only data belonging to an exact, currently installed third-party bundle is
eligible.  Keychain databases, caches, temporary data, container metadata and
unrelated containers are deliberately outside the allowlist.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import plistlib
import shutil
import stat
import subprocess
import time
import uuid
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator

from .database import EventStore
from .paths import RootlessPaths

METADATA_VERSION = 1
MAX_FILES = 50_000
MAX_BYTES = 2 * 1024 * 1024 * 1024
MIN_FREE_BYTES = 32 * 1024 * 1024
COPY_BLOCK = 1024 * 1024
INCLUDED_ROOTS = (
    PurePosixPath("Documents"),
    PurePosixPath("Library/Preferences"),
    PurePosixPath("Library/Application Support"),
    PurePosixPath("Library/Saved Application State"),
)
DENIED_PARTS = frozenset({"keychains", "keychain", "caches", "tmp"})


class SnapshotError(RuntimeError):
    """A fail-closed snapshot validation or coordination error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        current = os.fstat(descriptor)
        if not stat.S_ISREG(current.st_mode):
            raise SnapshotError("UNSAFE_FILE", "snapshot input is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while True:
                block = stream.read(COPY_BLOCK)
                if not block:
                    break
                digest.update(block)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _state_digest(files: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(files, key=lambda value: value["path"]):
        digest.update(str(entry["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(entry["size"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(entry["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


class SnapshotCoordinator:
    """Coordinate explicit user-requested snapshots and rollback.

    The coordinator does not poll.  Filesystem traversal occurs only for an
    authenticated operation or an explicit integrity inspection.
    """

    def __init__(self, paths: RootlessPaths, store: EventStore,
                 stop_app: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
                 wall_clock: Callable[[], float] = time.time) -> None:
        self.paths = paths
        self.store = store
        self.stop_app = stop_app or (lambda app: {"wasRunning": False, "stopped": True})
        self.wall_clock = wall_clock
        self.lock_path = self.paths.snapshot_directory / ".operation.lock"

    @staticmethod
    def _read_plist(path: Path) -> dict[str, Any]:
        try:
            value = plistlib.loads(path.read_bytes())
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
            return {}

    def _device_path(self, path: Path) -> str:
        if self.paths.root == Path("/"):
            return str(path)
        try:
            return "/" + str(path.resolve().relative_to(self.paths.root.resolve()))
        except ValueError as error:
            raise SnapshotError("UNSAFE_PATH", "path is outside the selected device root") from error

    def _registered_bundle_paths(self) -> dict[str, Path] | None:
        """Read the current LaunchServices/uicache registration when available.

        This matters on SRDs because an app may be registered directly from a
        mounted research Cryptex while an older MCM copy remains on disk.
        """
        binaries = (self.paths.jailbreak("/usr/bin/uicache"),
                    self.paths.system("/usr/bin/uicache"))
        binary = next((value for value in binaries
                       if value.is_file() and os.access(value, os.X_OK)), None)
        if binary is None:
            return None
        try:
            result = subprocess.run([str(binary), "-l"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=8, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0 or len(result.stdout) > 2 * 1024 * 1024:
            return None
        answer: dict[str, Path] = {}
        ambiguous: set[str] = set()
        for raw in result.stdout.decode("utf-8", "replace").splitlines()[:8192]:
            bundle_id, marker, raw_path = raw.partition(": ")
            bundle_id, raw_path = bundle_id.strip(), raw_path.strip()
            if (not marker or not bundle_id or len(bundle_id) > 255 or
                    bundle_id.startswith("com.apple.") or
                    any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
                        for char in bundle_id)):
                continue
            pure = PurePosixPath(raw_path)
            if not pure.is_absolute() or ".." in pure.parts or pure.suffix != ".app":
                continue
            mapped = self.paths.system(pure)
            try:
                resolved = mapped.resolve(strict=True)
                display = self._device_path(resolved)
            except (OSError, ValueError, SnapshotError):
                continue
            mcm = display.startswith("/private/var/containers/Bundle/Application/")
            cryptex = (display.startswith(
                "/private/var/run/com.apple.security.cryptexd/mnt/") and
                "/Applications/" in display)
            if not (mcm or cryptex) or not resolved.is_dir():
                continue
            info = self._read_plist(resolved / "Info.plist")
            if info.get("CFBundleIdentifier") != bundle_id:
                continue
            if bundle_id in ambiguous:
                continue
            if bundle_id in answer and answer[bundle_id] != resolved:
                # Ambiguous active registration is not a safe snapshot target.
                answer.pop(bundle_id, None)
                ambiguous.add(bundle_id)
            elif bundle_id in answer:
                continue
            else:
                answer[bundle_id] = resolved
        return answer

    @staticmethod
    def _bounded_children(path: Path, limit: int = 8192) -> Iterator[Path]:
        try:
            children = sorted(path.iterdir(), key=lambda value: value.name.casefold())
        except OSError:
            return iter(())
        return iter(children[:limit])

    def installed_apps(self) -> list[dict[str, Any]]:
        """Resolve bundle/data pairs from Apple's container metadata."""
        bundle_root = self.paths.system("/var/containers/Bundle/Application")
        data_root = self.paths.system("/var/mobile/Containers/Data/Application")
        bundles: dict[str, dict[str, Any]] = {}
        registered = self._registered_bundle_paths()
        candidates: list[Path] = []
        if registered is not None:
            candidates = list(registered.values())
        else:
            for owner in self._bounded_children(bundle_root):
                if owner.is_symlink() or not owner.is_dir():
                    continue
                for app_path in self._bounded_children(owner, 32):
                    if not app_path.is_symlink() and app_path.is_dir() and app_path.suffix == ".app":
                        candidates.append(app_path)
        for app_path in candidates[:8192]:
            info = self._read_plist(app_path / "Info.plist")
            bundle_id = info.get("CFBundleIdentifier")
            if (not isinstance(bundle_id, str) or not bundle_id or
                    len(bundle_id) > 255 or bundle_id.startswith("com.apple.")):
                continue
            executable = info.get("CFBundleExecutable")
            bundles[bundle_id] = {
                "bundleID": bundle_id,
                "name": str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or bundle_id)[:255],
                "version": str(info.get("CFBundleShortVersionString") or
                               info.get("CFBundleVersion") or "unknown")[:128],
                "bundlePath": app_path,
                "executablePath": app_path / str(executable) if isinstance(executable, str) else None,
            }
        for container in self._bounded_children(data_root):
            if container.is_symlink() or not container.is_dir():
                continue
            metadata = self._read_plist(container / ".com.apple.mobile_container_manager.metadata.plist")
            bundle_id = metadata.get("MCMMetadataIdentifier")
            if isinstance(bundle_id, str) and bundle_id in bundles:
                # A bundle must map to exactly one current data container.
                if "containerPath" in bundles[bundle_id]:
                    bundles[bundle_id]["ambiguousContainer"] = True
                else:
                    bundles[bundle_id]["containerPath"] = container
        result = []
        for bundle_id, app in bundles.items():
            if "containerPath" not in app or app.get("ambiguousContainer"):
                continue
            result.append({**app,
                           "bundlePathDisplay": self._device_path(app["bundlePath"]),
                           "containerPathDisplay": self._device_path(app["containerPath"])})
        return sorted(result, key=lambda value: (value["name"].casefold(), value["bundleID"]))[:2048]

    def resolve_app(self, bundle_id: str) -> dict[str, Any]:
        if (not isinstance(bundle_id, str) or not bundle_id or len(bundle_id) > 255 or
                any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_" for char in bundle_id)):
            raise SnapshotError("INVALID_BUNDLE_ID", "invalid bundle identifier")
        matches = [app for app in self.installed_apps() if app["bundleID"] == bundle_id]
        if len(matches) != 1:
            raise SnapshotError("APP_NOT_FOUND", "the exact third-party application container is unavailable")
        return matches[0]

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        self.paths.snapshot_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise SnapshotError("SNAPSHOT_BUSY", "another snapshot operation is in progress") from error
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    @staticmethod
    def _safe_relative(relative: Path) -> PurePosixPath:
        value = PurePosixPath(relative.as_posix())
        if value.is_absolute() or ".." in value.parts or not value.parts:
            raise SnapshotError("UNSAFE_PATH", "snapshot path is not canonical")
        if any(part.casefold() in DENIED_PARTS for part in value.parts):
            raise SnapshotError("UNSAFE_PATH", "snapshot path intersects protected data")
        if not any(value == root or root in value.parents for root in INCLUDED_ROOTS):
            raise SnapshotError("UNSAFE_PATH", "snapshot path is outside the application-state allowlist")
        return value

    def _enumerate(self, container: Path) -> list[tuple[Path, PurePosixPath, os.stat_result]]:
        rows: list[tuple[Path, PurePosixPath, os.stat_result]] = []
        total = 0
        for relative_root in INCLUDED_ROOTS:
            source_root = container.joinpath(*relative_root.parts)
            if not source_root.exists():
                continue
            if source_root.is_symlink() or not source_root.is_dir():
                raise SnapshotError("UNSAFE_FILE", "an application-state root is not a safe directory")
            for current, directories, files in os.walk(source_root, topdown=True, followlinks=False):
                current_path = Path(current)
                kept = []
                for name in sorted(directories):
                    candidate = current_path / name
                    relative = candidate.relative_to(container)
                    if candidate.is_symlink() or name.casefold() in DENIED_PARTS:
                        continue
                    self._safe_relative(relative)
                    kept.append(name)
                directories[:] = kept
                for name in sorted(files):
                    source = current_path / name
                    relative = self._safe_relative(source.relative_to(container))
                    info = source.lstat()
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    total += info.st_size
                    rows.append((source, relative, info))
                    if len(rows) > MAX_FILES or total > MAX_BYTES:
                        raise SnapshotError("SNAPSHOT_TOO_LARGE", "application state exceeds the bounded snapshot limit")
        return rows

    @staticmethod
    def _copy_regular(source: Path, destination: Path, expected: os.stat_result) -> str:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        destination_fd = -1
        digest = hashlib.sha256()
        try:
            current = os.fstat(source_fd)
            if (not stat.S_ISREG(current.st_mode) or current.st_dev != expected.st_dev or
                    current.st_ino != expected.st_ino or current.st_size != expected.st_size):
                raise SnapshotError("SOURCE_CHANGED", "application state changed during snapshot")
            destination_fd = os.open(destination,
                                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                                     0o600)
            while True:
                block = os.read(source_fd, COPY_BLOCK)
                if not block:
                    break
                digest.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(destination_fd, view)
                    view = view[written:]
            os.fsync(destination_fd)
            os.fchmod(destination_fd, stat.S_IMODE(current.st_mode) & 0o777)
        finally:
            if destination_fd >= 0:
                os.close(destination_fd)
            os.close(source_fd)
        return digest.hexdigest()

    def capability(self) -> dict[str, Any]:
        apps = self.installed_apps()
        try:
            statvfs = os.statvfs(self.paths.snapshot_directory)
            free = int(statvfs.f_bavail * statvfs.f_frsize)
        except OSError:
            free = 0
        supported = bool(apps) and os.access(self.paths.snapshot_directory, os.W_OK)
        return {"state": "Supported" if supported else "Unsupported",
                "reason": ("Exact application and data containers are available"
                           if supported else "No exact writable third-party application container is available"),
                "applicationCount": len(apps), "freeBytes": free,
                "includedRoots": [str(value) for value in INCLUDED_ROOTS],
                "excludedData": ["keychain databases", "caches", "temporary data", "other containers"]}

    def create(self, bundle_id: str, purpose: str = "manual",
               parent_snapshot_id: int | None = None) -> dict[str, Any]:
        with self.exclusive():
            return self._create_locked(bundle_id, purpose, parent_snapshot_id)

    def _create_locked(self, bundle_id: str, purpose: str,
                       parent_snapshot_id: int | None = None) -> dict[str, Any]:
        app = self.resolve_app(bundle_id)
        container: Path = app["containerPath"]
        rows = self._enumerate(container)
        free = os.statvfs(self.paths.snapshot_directory)
        free_bytes = int(free.f_bavail * free.f_frsize)
        required = sum(value.st_size for _, _, value in rows) + MIN_FREE_BYTES
        if free_bytes < required:
            raise SnapshotError("LOW_DISK", "not enough free space for a bounded safety margin")
        snapshot_key = uuid.uuid4().hex
        bundle_root = self.paths.snapshot_directory / bundle_id
        staging = bundle_root / ("." + snapshot_key + ".partial")
        final = bundle_root / snapshot_key
        if bundle_root.exists() and bundle_root.is_symlink():
            raise SnapshotError("UNSAFE_PATH", "snapshot bundle directory is a symbolic link")
        staging.mkdir(mode=0o700, parents=True, exist_ok=False)
        files: list[dict[str, Any]] = []
        try:
            for source, relative, info in rows:
                destination = staging / "files" / Path(*relative.parts)
                digest = self._copy_regular(source, destination, info)
                files.append({"path": str(relative), "size": info.st_size,
                              "sha256": digest, "mode": stat.S_IMODE(info.st_mode) & 0o777,
                              "uid": int(info.st_uid), "gid": int(info.st_gid)})
            stamp = float(self.wall_clock())
            manifest = {
                "metadataVersion": METADATA_VERSION,
                "snapshotID": snapshot_key,
                "bundleID": bundle_id,
                "appVersion": app["version"],
                "timestamp": stamp,
                "containerPath": app["containerPathDisplay"],
                "bundlePath": app["bundlePathDisplay"],
                "preferenceFiles": [entry["path"] for entry in files
                                    if entry["path"].startswith("Library/Preferences/")],
                "snapshotFiles": files,
                "totalSize": sum(entry["size"] for entry in files),
                "hashes": {entry["path"]: entry["sha256"] for entry in files},
                "stateDigest": _state_digest(files),
                "purpose": str(purpose)[:64],
            }
            encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
            manifest_path = staging / "manifest.json"
            descriptor = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            manifest_sha = hashlib.sha256(encoded).hexdigest()
            os.replace(staging, final)
            database_id = self.store.record_app_snapshot(
                bundle_id=bundle_id, app_version=app["version"],
                manifest_path=str(final / "manifest.json"),
                total_size=manifest["totalSize"], manifest_sha256=manifest_sha,
                file_count=len(files), state_digest=manifest["stateDigest"],
                container_path=app["containerPathDisplay"],
                bundle_path=app["bundlePathDisplay"], purpose=str(purpose)[:64],
                parent_snapshot_id=parent_snapshot_id)
            result = {**manifest, "id": database_id, "manifestSHA256": manifest_sha,
                      "integrity": "Verified"}
            return result
        except Exception:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
            if final.exists() and not (final / "manifest.json").exists():
                shutil.rmtree(final, ignore_errors=True)
            raise

    def _row_and_manifest(self, snapshot_id: int) -> tuple[dict[str, Any], dict[str, Any], Path]:
        if not isinstance(snapshot_id, int) or isinstance(snapshot_id, bool) or snapshot_id < 1:
            raise SnapshotError("INVALID_SNAPSHOT", "snapshot identifier must be a positive integer")
        row = self.store.app_snapshot(snapshot_id)
        if row is None or row.get("state") == "deleted":
            raise SnapshotError("SNAPSHOT_NOT_FOUND", "snapshot does not exist")
        manifest_path = Path(str(row["manifest_path"]))
        expected_root = self.paths.snapshot_directory.resolve()
        try:
            manifest_path.resolve(strict=True).relative_to(expected_root)
        except (OSError, ValueError) as error:
            raise SnapshotError("UNSAFE_PATH", "snapshot manifest is outside snapshot storage") from error
        if manifest_path.is_symlink() or manifest_path.name != "manifest.json":
            raise SnapshotError("UNSAFE_PATH", "snapshot manifest path is unsafe")
        encoded = manifest_path.read_bytes()
        if hashlib.sha256(encoded).hexdigest() != row.get("manifest_sha256"):
            raise SnapshotError("INTEGRITY_FAILED", "snapshot manifest hash does not match")
        try:
            manifest = json.loads(encoded)
        except (ValueError, TypeError) as error:
            raise SnapshotError("INTEGRITY_FAILED", "snapshot manifest is malformed") from error
        if (not isinstance(manifest, dict) or manifest.get("metadataVersion") != METADATA_VERSION or
                manifest.get("bundleID") != row.get("bundle_id")):
            raise SnapshotError("INTEGRITY_FAILED", "snapshot identity does not match its record")
        return row, manifest, manifest_path

    def inspect(self, snapshot_id: int, verify_files: bool = True) -> dict[str, Any]:
        row, manifest, manifest_path = self._row_and_manifest(snapshot_id)
        files = manifest.get("snapshotFiles")
        if not isinstance(files, list) or len(files) > MAX_FILES:
            raise SnapshotError("INTEGRITY_FAILED", "snapshot file list is invalid")
        verified = 0
        total = 0
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry in files:
            if not isinstance(entry, dict):
                raise SnapshotError("INTEGRITY_FAILED", "snapshot file entry is invalid")
            relative = self._safe_relative(Path(str(entry.get("path") or "")))
            key = str(relative)
            if key in seen:
                raise SnapshotError("INTEGRITY_FAILED", "snapshot contains duplicate paths")
            seen.add(key)
            size = entry.get("size")
            digest = entry.get("sha256")
            mode = entry.get("mode")
            uid, gid = entry.get("uid"), entry.get("gid")
            if (not isinstance(size, int) or isinstance(size, bool) or size < 0 or
                    not isinstance(digest, str) or len(digest) != 64 or
                    not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o777 or
                    not isinstance(uid, int) or isinstance(uid, bool) or uid < 0 or
                    not isinstance(gid, int) or isinstance(gid, bool) or gid < 0):
                raise SnapshotError("INTEGRITY_FAILED", "snapshot file metadata is invalid")
            source = manifest_path.parent / "files" / Path(*relative.parts)
            if source.is_symlink() or not source.is_file():
                raise SnapshotError("INTEGRITY_FAILED", "snapshot file is missing or unsafe")
            info = source.stat()
            if info.st_size != size or (verify_files and _sha256(source) != digest):
                raise SnapshotError("INTEGRITY_FAILED", "snapshot file hash does not match")
            total += size
            verified += 1
            normalized.append({"path": key, "size": size, "sha256": digest})
            if total > MAX_BYTES:
                raise SnapshotError("INTEGRITY_FAILED", "snapshot exceeds the size limit")
        if total != manifest.get("totalSize") or _state_digest(normalized) != manifest.get("stateDigest"):
            raise SnapshotError("INTEGRITY_FAILED", "snapshot aggregate integrity does not match")
        if manifest.get("hashes") != {entry["path"]: entry["sha256"] for entry in normalized}:
            raise SnapshotError("INTEGRITY_FAILED", "snapshot hash index does not match")
        verified_at = float(self.wall_clock())
        self.store.mark_snapshot_verified(snapshot_id, verified_at)
        return {**row, "verified_at": verified_at,
                "manifest": manifest, "integrity": "Verified",
                "verifiedFiles": verified, "verifiedBytes": total}

    def list(self, bundle_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        return self.store.list_app_snapshots(bundle_id, limit)

    def current_state_digest(self, bundle_id: str) -> str:
        app = self.resolve_app(bundle_id)
        files = []
        for source, relative, info in self._enumerate(app["containerPath"]):
            files.append({"path": str(relative), "size": info.st_size,
                          "sha256": _sha256(source)})
        return _state_digest(files)

    def restore(self, snapshot_id: int) -> dict[str, Any]:
        with self.exclusive():
            detail = self.inspect(snapshot_id, verify_files=True)
            manifest = detail["manifest"]
            app = self.resolve_app(manifest["bundleID"])
            stop = self.stop_app(app)
            if stop.get("wasRunning") and not stop.get("stopped"):
                raise SnapshotError("APP_RUNNING", "target application could not be stopped safely")
            safety = self._create_locked(manifest["bundleID"], "pre-restore-safety", snapshot_id)
            try:
                self._restore_files(app["containerPath"], Path(detail["manifest_path"]).parent,
                                    manifest)
            except Exception:
                # Best-effort immediate rollback from the already verified safety
                # snapshot; preserve both snapshots and surface the original error.
                safety_detail = self.inspect(int(safety["id"]), verify_files=True)
                self._restore_files(app["containerPath"],
                                    Path(safety_detail["manifest_path"]).parent,
                                    safety_detail["manifest"])
                raise
            return {"snapshotID": snapshot_id, "bundleID": manifest["bundleID"],
                    "restoredStateDigest": manifest["stateDigest"],
                    "safetySnapshotID": safety["id"], "appStop": stop,
                    "fileCount": len(manifest["snapshotFiles"]),
                    "totalSize": manifest["totalSize"], "integrity": "Verified",
                    "reversible": True}

    def _restore_files(self, container: Path, snapshot_root: Path,
                       manifest: dict[str, Any]) -> None:
        desired: set[str] = set()
        container_owner = container.stat()
        for entry in manifest["snapshotFiles"]:
            relative = self._safe_relative(Path(entry["path"]))
            desired.add(str(relative))
            source = snapshot_root / "files" / Path(*relative.parts)
            destination = container / Path(*relative.parts)
            # Reject a symlink in any existing destination parent.
            cursor = container
            for part in relative.parts[:-1]:
                cursor = cursor / part
                if cursor.exists() and cursor.is_symlink():
                    raise SnapshotError("UNSAFE_PATH", "restore destination contains a symbolic link")
                existed = cursor.exists()
                cursor.mkdir(mode=0o700, exist_ok=True)
                if not existed:
                    os.chown(cursor, container_owner.st_uid, container_owner.st_gid)
            temporary = destination.with_name(destination.name + ".0sky-restore-" + uuid.uuid4().hex)
            info = source.lstat()
            self._copy_regular(source, temporary, info)
            os.chmod(temporary, int(entry.get("mode", 0o600)) & 0o777)
            os.chown(temporary, int(entry["uid"]), int(entry["gid"]))
            os.replace(temporary, destination)
        # Exact rollback inside the documented allowlist only.  The pre-restore
        # safety snapshot makes these removals reversible.
        for source, relative, _ in reversed(self._enumerate(container)):
            if str(relative) not in desired:
                source.unlink()
        for relative_root in INCLUDED_ROOTS:
            root = container.joinpath(*relative_root.parts)
            if not root.is_dir() or root.is_symlink():
                continue
            for current, directories, _ in os.walk(root, topdown=False, followlinks=False):
                for name in directories:
                    candidate = Path(current) / name
                    try:
                        candidate.rmdir()
                    except OSError:
                        pass

    def delete(self, snapshot_id: int) -> dict[str, Any]:
        with self.exclusive():
            row, manifest, manifest_path = self._row_and_manifest(snapshot_id)
            directory = manifest_path.parent
            expected = self.paths.snapshot_directory.resolve()
            try:
                directory.resolve(strict=True).relative_to(expected)
            except (OSError, ValueError) as error:
                raise SnapshotError("UNSAFE_PATH", "snapshot directory is outside storage") from error
            if directory.is_symlink() or directory.name != manifest.get("snapshotID"):
                raise SnapshotError("UNSAFE_PATH", "snapshot directory identity is invalid")
            for current, directories, files in os.walk(directory, topdown=False, followlinks=False):
                for name in files:
                    candidate = Path(current) / name
                    if candidate.is_symlink():
                        raise SnapshotError("UNSAFE_PATH", "snapshot contains a symbolic link")
                    candidate.unlink()
                for name in directories:
                    candidate = Path(current) / name
                    if candidate.is_symlink():
                        raise SnapshotError("UNSAFE_PATH", "snapshot contains a symbolic link")
                    candidate.rmdir()
            directory.rmdir()
            self.store.mark_snapshot_deleted(snapshot_id, self.wall_clock())
            return {"snapshotID": snapshot_id, "bundleID": row["bundle_id"],
                    "deleted": True, "reversible": False}
