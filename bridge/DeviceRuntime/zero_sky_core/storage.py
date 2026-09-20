"""Bounded, classification-first storage inventory.

This module does not delete anything.  A candidate is produced from an exact
known root and identity, never from a substring match.
"""
from __future__ import annotations

import hashlib
import os
import stat
import time
from pathlib import Path
from typing import Any, Callable

from .paths import RootlessPaths


class StorageScanner:
    MAX_FILES = 50_000
    CATEGORIES = (
        "Applications", "Application Data", "Application Caches",
        "Package Archives", "Logs", "Crash Reports", "Snapshots",
        "0-Sky Data", "Temporary Data",
    )
    SAFETY = ("Safe", "Review", "Never Automatically Delete")

    def __init__(self, paths: RootlessPaths,
                 app_provider: Callable[[], list[dict[str, Any]]]) -> None:
        self.paths, self.app_provider = paths, app_provider
        self._remaining_files = self.MAX_FILES

    def _size(self, path: Path) -> tuple[int, int, bool]:
        try:
            first = path.lstat()
        except OSError:
            return 0, 0, False
        if stat.S_ISLNK(first.st_mode):
            return 0, 0, False
        if stat.S_ISREG(first.st_mode):
            return max(0, first.st_size), 1, False
        if not stat.S_ISDIR(first.st_mode):
            return 0, 0, False
        size = files = 0
        truncated = False
        if self._remaining_files <= 0:
            return 0, 0, True
        for root, directories, names in os.walk(path, topdown=True, followlinks=False):
            directories[:] = [name for name in directories
                              if not (Path(root) / name).is_symlink()]
            for name in names:
                candidate = Path(root) / name
                try:
                    value = candidate.lstat()
                except OSError:
                    continue
                if stat.S_ISREG(value.st_mode):
                    size += max(0, value.st_size); files += 1
                    self._remaining_files -= 1
                if self._remaining_files <= 0:
                    truncated = True; break
            if truncated:
                break
        return size, files, truncated

    @staticmethod
    def _identifier(category: str, path: str, owner: str) -> str:
        return hashlib.sha256(f"{category}\0{path}\0{owner}".encode()).hexdigest()

    def _candidate(self, category: str, path: Path, owner: str, safety: str,
                   reason: str, *, display_path: str | None = None) -> dict[str, Any]:
        size, files, truncated = self._size(path)
        shown = display_path or str(path)
        return {"id": self._identifier(category, shown, owner), "category": category,
                "path": shown, "owner": owner, "estimatedSize": size,
                "fileCount": files, "estimateTruncated": truncated,
                "cleanupSafety": safety, "reason": reason,
                "exists": path.exists() and not path.is_symlink()}

    def scan(self) -> dict[str, Any]:
        self._remaining_files = self.MAX_FILES
        rows: list[dict[str, Any]] = []
        for app in self.app_provider()[:512]:
            bundle_id = str(app.get("bundleID") or "")
            bundle = app.get("bundlePath")
            container = app.get("containerPath")
            if isinstance(bundle, Path):
                rows.append(self._candidate(
                    "Applications", bundle, bundle_id, "Never Automatically Delete",
                    "Application bundles require the package/application removal workflow",
                    display_path=str(app.get("bundlePathDisplay") or bundle)))
            if isinstance(container, Path):
                rows.append(self._candidate(
                    "Application Data", container, bundle_id, "Never Automatically Delete",
                    "User documents and preferences must never be automatically deleted",
                    display_path=str(app.get("containerPathDisplay") or container)))
                cache = container / "Library/Caches"
                if cache.is_dir() and not cache.is_symlink():
                    rows.append(self._candidate(
                        "Application Caches", cache, bundle_id, "Safe",
                        "Exact MCM application cache root; app may recreate contents",
                        display_path=str(Path(str(app.get("containerPathDisplay") or container)) /
                                         "Library/Caches")))

        archive = self.paths.jailbreak("/var/cache/apt/archives")
        if archive.is_dir():
            for path in sorted(archive.iterdir())[:2048]:
                if path.is_file() and not path.is_symlink() and path.suffix == ".deb":
                    rows.append(self._candidate(
                        "Package Archives", path, "apt", "Safe",
                        "Downloaded package archive; installed dpkg state is authoritative"))

        for root, category, safety in (
            (self.paths.jailbreak("/var/log"), "Logs", "Review"),
            (self.paths.system("/var/mobile/Library/Logs/CrashReporter"),
             "Crash Reports", "Review"),
        ):
            if root.is_dir() and not root.is_symlink():
                rows.append(self._candidate(
                    category, root, "system" if category == "Crash Reports" else "0-Sky/rootless",
                    safety, "Review diagnostic retention before cleanup"))

        snapshot = self.paths.snapshot_directory
        if snapshot.is_dir():
            rows.append(self._candidate(
                "Snapshots", snapshot, "0-Sky", "Never Automatically Delete",
                "Delete snapshots only through the verified snapshot workflow"))
        state = self.paths.state_directory
        if state.is_dir():
            rows.append(self._candidate(
                "0-Sky Data", state, "0-Sky", "Never Automatically Delete",
                "Includes the database, journal, policy, and recovery evidence"))
        temporary = self.paths.temporary_directory
        if temporary.is_dir() and not temporary.is_symlink():
            cutoff = time.time() - 86400
            for path in sorted(temporary.iterdir())[:2048]:
                try:
                    value = path.lstat()
                except OSError:
                    continue
                if stat.S_ISREG(value.st_mode) and value.st_mtime <= cutoff:
                    rows.append(self._candidate(
                        "Temporary Data", path, "0-Sky/rootless", "Safe",
                        "Regular file in the exact rootless temporary root and older than 24 hours"))
                elif stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode):
                    rows.append(self._candidate(
                        "Temporary Data", path, "0-Sky/rootless", "Review",
                        "Directory requires review; no recursive cleanup is inferred from its name"))
        rows = rows[:4096]
        totals = {category: sum(row["estimatedSize"] for row in rows
                                if row["category"] == category)
                  for category in self.CATEGORIES}
        return {"generatedAt": time.time(), "candidates": rows,
                "categoryTotals": totals, "count": len(rows),
                "deletionImplemented": False,
                "message": "Classification is read-only; no candidate is automatically deleted"}
