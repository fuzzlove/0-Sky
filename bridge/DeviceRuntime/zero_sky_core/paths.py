"""Central rootless path resolution for 0-Sky.

All feature code receives a RootlessPaths instance.  Tests use an alternate
filesystem root without changing the device-visible paths stored in records.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class RootlessPaths:
    """Resolve fixed system and jailbreak paths below an optional fixture root."""

    root: Path = Path("/")
    root_prefix: PurePosixPath = PurePosixPath("/var/jb")

    def __post_init__(self) -> None:
        root = Path(self.root)
        if not root.is_absolute():
            raise ValueError("fixture root must be absolute")
        prefix = PurePosixPath(self.root_prefix)
        if not prefix.is_absolute() or ".." in prefix.parts:
            raise ValueError("rootless prefix must be an absolute canonical path")
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "root_prefix", prefix)

    def system(self, absolute: str | PurePosixPath) -> Path:
        """Map a device-absolute path into the selected filesystem root."""
        path = PurePosixPath(absolute)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("system path must be absolute and canonical")
        if self.root == Path("/"):
            return Path(str(path))
        return self.root.joinpath(*path.parts[1:])

    def jailbreak(self, absolute_suffix: str | PurePosixPath = "/") -> Path:
        """Resolve a path relative to the rootless jailbreak prefix."""
        suffix = PurePosixPath(absolute_suffix)
        if not suffix.is_absolute() or ".." in suffix.parts:
            raise ValueError("jailbreak path must be absolute and canonical")
        combined = self.root_prefix.joinpath(*suffix.parts[1:])
        return self.system(combined)

    @property
    def config_directory(self) -> Path:
        return self.jailbreak("/etc/0sky")

    @property
    def state_directory(self) -> Path:
        return self.jailbreak("/var/lib/0sky")

    @property
    def log_directory(self) -> Path:
        return self.jailbreak("/var/log/0sky")

    @property
    def snapshot_directory(self) -> Path:
        return self.state_directory / "snapshots"

    @property
    def database_path(self) -> Path:
        return self.state_directory / "core.sqlite3"

    @property
    def temporary_directory(self) -> Path:
        return self.jailbreak("/var/tmp/0sky")

    @property
    def provider_directory(self) -> Path:
        """Root-owned drop point for reviewed telemetry providers.

        A provider may atomically publish a bounded JSON observation here.  The
        core validates ownership, permissions, freshness and schema before the
        observation can reach the event store.  Merely creating a file does not
        make a capability supported.
        """
        return self.state_directory / "providers"

    def ensure_directories(self) -> None:
        for path in (
            self.config_directory,
            self.state_directory,
            self.log_directory,
            self.snapshot_directory,
            self.temporary_directory,
            self.provider_directory,
        ):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                path.chmod(0o700)
            except OSError:
                pass

    def as_dict(self) -> dict[str, str]:
        return {
            "rootPrefix": str(self.root_prefix),
            "configDirectory": str(self.config_directory),
            "stateDirectory": str(self.state_directory),
            "logDirectory": str(self.log_directory),
            "snapshotDirectory": str(self.snapshot_directory),
            "databasePath": str(self.database_path),
            "temporaryDirectory": str(self.temporary_directory),
            "providerDirectory": str(self.provider_directory),
        }
