"""Explicit build and runtime directories; none depend on the launch directory."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tempfile


@dataclass(frozen=True)
class ReleasePaths:
    project_root: Path
    build_root: Path
    staging_root: Path
    app_bundle: Path
    resources_dir: Path
    kit_root: Path
    temp_dir: Path

    @classmethod
    def from_work(cls, project_root: Path, work: Path) -> "ReleasePaths":
        project = project_root.resolve(strict=True)
        temporary = work.resolve(strict=True)
        staging = temporary / "staging"
        app = staging / "Applications/0SkyBridge.app"
        return cls(project, temporary / "derived", staging, app,
                   app / "Contents/Resources", temporary / "prepared-kit", temporary)


@dataclass(frozen=True)
class RuntimePaths:
    support_dir: Path
    cache_dir: Path
    log_dir: Path
    temp_dir: Path

    @classmethod
    def discover(cls, home: Path | None = None) -> "RuntimePaths":
        user_home = (home or Path.home()).expanduser().resolve()
        library = user_home / "Library"
        return cls(library / "Application Support/0-Sky",
                   library / "Caches/0-Sky", library / "Logs/0-Sky",
                   Path(tempfile.gettempdir()).resolve())
