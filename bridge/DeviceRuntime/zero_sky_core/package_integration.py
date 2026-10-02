"""Resolve a package-owned rootless app before SRD Cryptex integration."""
from __future__ import annotations

from pathlib import Path
import plistlib
import re
import subprocess


PACKAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,254}\Z")


class PackageIntegrationError(ValueError):
    pass


def resolve_owner(app_path: str, *, root: Path = Path("/var/jb/Applications"),
                  dpkg_query: str = "/var/jb/usr/bin/dpkg-query") -> str:
    """Return the one installed Debian package that owns an app's Info.plist.

    The caller supplies the path from Sileo's post-apt app scan. No package
    name or arbitrary filesystem path is accepted as authority.
    """
    app = Path(app_path)
    if (not app.is_absolute() or app.parent != root or app.suffix != ".app" or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,127}\.app", app.name)):
        raise PackageIntegrationError("app is outside the rootless package directory")
    if (app.is_symlink() or not app.is_dir() or
            app.resolve() != root.resolve() / app.name):
        raise PackageIntegrationError("package app is absent or symbolic")
    info_path = app / "Info.plist"
    if info_path.is_symlink() or not info_path.is_file():
        raise PackageIntegrationError("package app Info.plist is missing or symbolic")
    if info_path.stat().st_size > 1024 * 1024:
        raise PackageIntegrationError("package app Info.plist exceeds the size limit")
    try:
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, ValueError, TypeError) as error:
        raise PackageIntegrationError("package app Info.plist is invalid") from error
    executable = info.get("CFBundleExecutable") if isinstance(info, dict) else None
    bundle_id = info.get("CFBundleIdentifier") if isinstance(info, dict) else None
    if (not isinstance(executable, str) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", executable) or
            not isinstance(bundle_id, str) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", bundle_id)):
        raise PackageIntegrationError("package app identity is invalid")
    binary = app / executable
    if binary.is_symlink() or not binary.is_file():
        raise PackageIntegrationError("package app executable is missing or symbolic")
    result = subprocess.run(
        [dpkg_query, "--search", "--", str(info_path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=15, check=False)
    if result.returncode:
        raise PackageIntegrationError("Info.plist has no installed package owner")
    owners = set()
    for line in result.stdout.splitlines():
        package, separator, owned_path = line.partition(": ")
        if separator and owned_path == str(info_path) and PACKAGE_NAME.fullmatch(package):
            owners.add(package)
    if len(owners) != 1:
        raise PackageIntegrationError("Info.plist has no unique package owner")
    package = owners.pop()
    status = subprocess.run(
        [dpkg_query, "--show", "--showformat=${db:Status-Abbrev}", package],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=15, check=False)
    if status.returncode or not status.stdout.startswith("ii"):
        raise PackageIntegrationError("app owner is not fully installed")
    return package
