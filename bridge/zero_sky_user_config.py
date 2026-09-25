#!/usr/bin/env python3
"""Per-user, relocatable configuration for 0-Sky/SRDssh.

The project tree is immutable input.  Virtual environments, run state,
artifacts, identities, and generated companion files belong to the account
running the installer and therefore live below that account's home directory.
"""
from __future__ import annotations

import copy
import datetime as dt
import getpass
import json
import os
from pathlib import Path
import platform
import socket
import tempfile
from typing import Any, Mapping


SCHEMA = 1
APP_SUPPORT = Path("Library/Application Support/0-Sky")


class UserConfigError(RuntimeError):
    """The local user configuration is missing a required security property."""


def _absolute(value: str | os.PathLike[str], base: Path | None = None) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (base or Path.cwd()) / path
    return path.resolve(strict=False)


def config_path(requested: str | os.PathLike[str] | None = None,
                environment: Mapping[str, str] | None = None,
                home: Path | None = None) -> Path:
    env = os.environ if environment is None else environment
    value = requested or env.get("ZERO_SKY_CONFIG")
    if value:
        return _absolute(value)
    return (home or Path.home()) / APP_SUPPORT / "user-config.json"


def defaults(project_root: str | os.PathLike[str], home: Path | None = None) -> dict[str, Any]:
    home = (home or Path.home()).resolve()
    support = home / APP_SUPPORT
    return {
        "schema": SCHEMA,
        "profile": {
            "user": getpass.getuser(),
            "uid": os.getuid(),
            "home": str(home),
        },
        "installation": {
            "project_root": str(_absolute(project_root)),
            "host": socket.gethostname(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "paths": {
            "support": str(support),
            "state": str(support / "state"),
            "artifacts": str(support / "artifacts"),
            "ssh_identity": str(home / ".ssh/srdsh_ed25519"),
            "venv": str(support / "venv"),
        },
        "defaults": {"base_port": 2222, "sdk": "iphoneos"},
    }


def _merge(base: dict[str, Any], update: Mapping[str, Any]) -> dict[str, Any]:
    for key, value in update.items():
        if isinstance(value, Mapping) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def _validate_file(path: Path) -> None:
    if path.is_symlink():
        raise UserConfigError(f"configuration must not be a symlink: {path}")
    stat = path.stat()
    if stat.st_uid != os.getuid():
        raise UserConfigError(f"configuration is not owned by uid {os.getuid()}: {path}")
    if stat.st_mode & 0o077:
        raise UserConfigError(f"configuration permissions must be 0600: {path}")


def _normalize(config: dict[str, Any], project_root: Path) -> dict[str, Any]:
    if config.get("schema") != SCHEMA:
        raise UserConfigError(
            f"unsupported user configuration schema {config.get('schema')!r}; expected {SCHEMA}"
        )
    paths = config.get("paths")
    if not isinstance(paths, dict):
        raise UserConfigError("configuration paths must be an object")
    required = ("support", "state", "artifacts", "ssh_identity", "venv")
    for name in required:
        value = paths.get(name)
        if not isinstance(value, str) or not value.strip():
            raise UserConfigError(f"configuration path {name!r} is missing")
        paths[name] = str(_absolute(value))
    defaults_section = config.get("defaults", {})
    port = int(defaults_section.get("base_port", 2222))
    if not 1 <= port <= 65535:
        raise UserConfigError("defaults.base_port must be between 1 and 65535")
    defaults_section["base_port"] = port
    defaults_section["sdk"] = str(defaults_section.get("sdk", "iphoneos"))
    config["defaults"] = defaults_section
    # The source tree may be moved or re-cloned.  Always report the tree that
    # is actually executing rather than trusting a stale machine path.
    config.setdefault("installation", {})["project_root"] = str(project_root)
    return config


def _environment_overrides(environment: Mapping[str, str]) -> dict[str, Any]:
    paths = {
        name: environment[key]
        for name, key in (
            ("support", "ZERO_SKY_SUPPORT"), ("state", "ZERO_SKY_STATE"),
            ("artifacts", "ZERO_SKY_ARTIFACTS"),
            ("ssh_identity", "ZERO_SKY_IDENTITY"), ("venv", "ZERO_SKY_VENV"),
        ) if environment.get(key)
    }
    for name, value in paths.items():
        if not Path(value).expanduser().is_absolute():
            raise UserConfigError(f"ZERO_SKY path override {name!r} must be absolute")
    result: dict[str, Any] = {"paths": paths}
    if environment.get("ZERO_SKY_BASE_PORT"):
        result["defaults"] = {"base_port": environment["ZERO_SKY_BASE_PORT"]}
    return result


def _stored_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    _validate_file(path)
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise UserConfigError(f"cannot read configuration {path}: {error}") from error
    if not isinstance(stored, dict):
        raise UserConfigError(f"configuration must contain a JSON object: {path}")
    paths = stored.get("paths", {})
    if isinstance(paths, dict):
        for name, value in paths.items():
            if isinstance(value, str) and value.strip():
                paths[name] = str(_absolute(value, path.parent))
    return stored


def load(project_root: str | os.PathLike[str], requested: str | os.PathLike[str] | None = None,
         overrides: Mapping[str, Any] | None = None,
         environment: Mapping[str, str] | None = None,
         home: Path | None = None) -> dict[str, Any]:
    """Resolve CLI > config file > environment > discovered account > defaults."""
    root = _absolute(project_root)
    env = os.environ if environment is None else environment
    result = defaults(root, home)
    _merge(result, _environment_overrides(env))
    path = config_path(requested, env, home)
    _merge(result, _stored_config(path))
    if overrides:
        _merge(result, overrides)
    return _normalize(result, root)


def write(project_root: str | os.PathLike[str], requested: str | os.PathLike[str] | None = None,
          overrides: Mapping[str, Any] | None = None) -> tuple[Path, dict[str, Any]]:
    """Create or refresh the current account's configuration atomically."""
    root = _absolute(project_root)
    path = config_path(requested)
    result = load(root, requested, overrides)
    result["schema"] = SCHEMA
    result["profile"] = defaults(root)["profile"]
    result.setdefault("installation", {}).update(defaults(root)["installation"])
    result["installation"]["configured_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    result = _normalize(result, root)

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".user-config.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    for name in ("support", "state", "artifacts", "venv"):
        directory = Path(result["paths"][name])
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
    return path, result


def public(config: Mapping[str, Any], path: Path | None = None) -> dict[str, Any]:
    """Return a diagnostic view without user, host, or absolute source paths."""
    result = copy.deepcopy(dict(config))
    home = str(config.get("profile", {}).get("home", Path.home()))
    profile = result.get("profile", {})
    if isinstance(profile, dict):
        profile["user"] = "<local-user>"
        profile["home"] = "~"
    installation = result.get("installation", {})
    if isinstance(installation, dict):
        installation["host"] = "<local-host>"
        installation["project_root"] = "<project-root>"
    paths = result.get("paths", {})
    if isinstance(paths, dict):
        for name, value in paths.items():
            if isinstance(value, str) and value.startswith(home + os.sep):
                paths[name] = "~" + value[len(home):]
            elif isinstance(value, str) and Path(value).is_absolute():
                paths[name] = "<configured-path>"
    if path is not None:
        value = str(path)
        result["configuration_file"] = "~" + value[len(home):] if value.startswith(home + os.sep) else "<configured-path>"
    return result
