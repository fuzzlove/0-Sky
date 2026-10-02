"""Runtime-discovered bootstrap paths and exact owned-path translation."""
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class RootlessPaths:
    prefix: str

    @classmethod
    def from_environment(cls, environment):
        value = environment.bootstrap_prefix
        path = PurePosixPath(value) if isinstance(value, str) else None
        if (path is None or not path.is_absolute() or str(path) in ("/", ".") or
                ".." in value.split("/") or environment.capabilities.get("var_jb") is not True):
            raise ValueError("verified rootless bootstrap prefix required")
        return cls(str(path))

    @property
    def OSKY_ROOT(self):
        return self.prefix

    @property
    def OSKY_PREFIX(self):
        return self.prefix

    @property
    def OSKY_APPLICATIONS(self):
        return self.prefix + "/Applications"

    @property
    def OSKY_LIBRARY(self):
        return self.prefix + "/Library"

    @property
    def OSKY_DAEMONS(self):
        return self.OSKY_LIBRARY + "/LaunchDaemons"

    @property
    def OSKY_PREFERENCES(self):
        return self.OSKY_LIBRARY + "/PreferenceBundles"

    @property
    def OSKY_LOGS(self):
        return self.prefix + "/var/log/0sky"

    @property
    def OSKY_STATE(self):
        return self.prefix + "/var/lib/0sky"

    def translate_owned(self, absolute: str, owned: set[str]) -> str:
        path = PurePosixPath(absolute) if isinstance(absolute, str) else None
        if path is None or not path.is_absolute() or ".." in absolute.split("/"):
            raise ValueError("absolute payload-owned path required")
        canonical = str(path)
        if canonical.startswith(self.prefix + "/"):
            return canonical
        if canonical not in owned:
            raise ValueError("path is not declared as owned by this payload")
        return self.prefix + canonical
