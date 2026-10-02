"""Pure preflight and action policy for bundled 0-Sky Control installation."""
from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Decision:
    compatibility: str
    action: str
    code: str
    explanation: str
    backend: str | None = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _version(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
        raise ValueError("version is not a numeric dotted string")
    return tuple(int(part) for part in value.split("."))


def _supports_architecture(device: str, payload: object) -> bool:
    """arm64e devices can execute a regular arm64 application slice."""
    if not isinstance(payload, list):
        return False
    return device in payload or (device == "arm64e" and "arm64" in payload)


def decide(manifest: dict, environment: dict, installed: dict | None) -> Decision:
    """Return an explicit action; never infer health from an app directory."""
    identity = manifest.get("identity", {})
    bundle_id = identity.get("CFBundleIdentifier")
    build = identity.get("CFBundleVersion")
    if bundle_id != "com.liquidsky.CrypStore" or not build:
        return Decision("BLOCKED", "BLOCK", "PAYLOAD_IDENTITY", "Bundled Control identity is invalid")
    os_major = environment.get("os_major")
    allowed = manifest.get("supported_os", {})
    if not isinstance(os_major, int) or not (allowed.get("minimum_major", 99) <= os_major <= allowed.get("maximum_major", -1)):
        return Decision("BLOCKED", "BLOCK", "UNSUPPORTED_OS", "No reviewed Control backend supports this OS build")
    if not _supports_architecture(environment.get("architecture"), manifest.get("architectures")):
        return Decision("BLOCKED", "BLOCK", "ARCHITECTURE", "Bundled Control has no supported device slice")
    if not environment.get("srd_authorized"):
        return Decision("BLOCKED", "BLOCK", "SRD_AUTHORIZATION", "Device is not an authorized research device")
    if not environment.get("bootstrap_ready"):
        return Decision("BLOCKED", "BLOCK", "BOOTSTRAP", "Rootless bootstrap or device bridge is unavailable")
    if not environment.get("paired_mac_verified") or not environment.get("worker_connected"):
        return Decision("BLOCKED", "BLOCK", "BRIDGE_DISCONNECTED", "Connect the device to its verified 0-Sky Mac")
    # The reviewed paired worker uses native MobileInstallation registration.
    # A separate legacy appregistrard executable is not required by this backend.
    required_mb = max(128, int(environment.get("payload_mb", 0)) * 4 + 64)
    if int(environment.get("free_mb", 0)) < required_mb:
        return Decision("BLOCKED", "BLOCK", "DISK_SPACE", f"At least {required_mb} MiB free is required")
    missing = environment.get("missing_dependencies", [])
    if missing:
        return Decision("BLOCKED", "BLOCK", "DEPENDENCY_MISSING", "Missing: " + ", ".join(sorted(missing)))
    incompatibilities = environment.get("incompatible_dependencies", [])
    if incompatibilities:
        return Decision("BLOCKED", "BLOCK", "DEPENDENCY_INCOMPATIBLE", "Incompatible: " + ", ".join(sorted(incompatibilities)))
    if not environment.get("transactional_backend"):
        return Decision("BLOCKED", "BLOCK", "BACKEND_UNAVAILABLE", "Paired installer has no verified rollback adapter")
    backend = manifest.get("backend")
    if installed is None:
        return Decision("COMPATIBLE", "INSTALL", "FRESH", "Control is absent", backend)
    if installed.get("bundle_id") != bundle_id:
        return Decision("BLOCKED", "BLOCK", "INSTALLED_IDENTITY", "Existing Control identity differs from the bundle")
    try:
        existing_build = _version(str(installed.get("build", "")))
        target_build = _version(str(build))
    except ValueError:
        return Decision("BLOCKED", "BLOCK", "VERSION_UNKNOWN", "Installed Control build cannot be compared")
    if existing_build > target_build:
        return Decision("BLOCKED", "BLOCK", "NEWER_INSTALLED", "A newer Control build is installed")
    healthy = all(installed.get(name) is True for name in
                  ("executable", "resources", "signature", "entitlements", "registration",
                   "dependencies", "services", "launch", "link_communication"))
    if existing_build == target_build and healthy:
        return Decision("COMPATIBLE", "NO_ACTION", "CURRENT", "Control is installed and healthy", backend)
    if not environment.get("rollback_source_verified"):
        return Decision("BLOCKED", "BLOCK", "ROLLBACK_SOURCE", "A verified prior Control artifact is required before replacement")
    if existing_build < target_build:
        return Decision("COMPATIBLE", "UPDATE", "OLDER_INSTALLED", "A verified Control update is available", backend)
    return Decision("COMPATIBLE_WITH_ADAPTATION", "REPAIR", "DAMAGED", "Control health checks failed", backend)
