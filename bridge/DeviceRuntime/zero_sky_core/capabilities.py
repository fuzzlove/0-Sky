"""Capability-first platform detection for 0-Sky."""
from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable

from .paths import RootlessPaths


class CapabilityState(str, Enum):
    SUPPORTED = "Supported"
    MONITOR_ONLY = "MonitorOnly"
    UNSUPPORTED = "Unsupported"
    DEGRADED = "Degraded"


@dataclass(frozen=True)
class Capability:
    state: CapabilityState
    reason: str
    evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {"state": self.state.value, "reason": self.reason,
                "evidence": list(self.evidence)}


class CapabilityMatrix:
    """Detect capabilities from concrete runtime evidence, not marketing claims."""

    NAMES = (
        "rootlessRuntime", "packageDatabase", "processInspection",
        "networkObservation", "networkEnforcement", "privacyObservation",
        "privacyEnforcement", "batteryMonitoring", "thermalMonitoring",
        "deviceHealth", "chargeControl",
        "tweakEnumeration", "tweakDisable", "tweakConflictAnalysis",
        "crashObservation", "safeModeRecovery", "appSnapshot",
        "profileAutomation", "appFreeze", "storageIntelligence",
        "notificationObservation", "permissionTimeout",
    )

    def __init__(self, paths: RootlessPaths) -> None:
        self.paths = paths

    def _executable(self, candidates: Iterable[str]) -> str | None:
        for candidate in candidates:
            path = self.paths.system(candidate)
            if path.is_file() and os.access(path, os.X_OK):
                return candidate
        return None

    def detect(self) -> dict[str, Capability]:
        p = self.paths
        rootless = p.system(str(p.root_prefix)).is_dir()
        dpkg_status = p.jailbreak("/Library/dpkg/status")
        dpkg = self._executable(("/var/jb/usr/bin/dpkg", "/usr/bin/dpkg"))
        ps = self._executable(("/var/jb/usr/bin/ps", "/bin/ps"))
        localfence = self._executable(("/var/jb/usr/bin/localfencectl",))
        localfence_ready = False
        localfence_evidence: tuple[str, ...] = ()
        if localfence:
            try:
                check = subprocess.run(
                    [str(p.system(localfence)), "status"], check=False,
                    capture_output=True, text=True, timeout=3,
                    env={"PATH": "/var/jb/usr/bin:/usr/bin:/bin", "LANG": "C"})
                localfence_ready = check.returncode == 0
                localfence_evidence = (localfence, f"statusExit={check.returncode}")
            except (OSError, subprocess.TimeoutExpired):
                localfence_evidence = (localfence, "statusUnavailable")
        tweak_dirs = [p.jailbreak("/Library/MobileSubstrate/DynamicLibraries"),
                      p.jailbreak("/usr/lib/TweakInject")]
        tweaks = any(path.is_dir() for path in tweak_dirs)
        crash_dirs = (p.system("/var/mobile/Library/Logs/CrashReporter"),
                      p.system("/var/mobile/Library/Logs/DiagnosticLogs"))
        crash = any(path.is_dir() for path in crash_dirs)
        registry = p.jailbreak("/var/lib/srd-runtime/registry.json")
        recovery_controller = p.jailbreak("/usr/local/libexec/srd-runtime-manager.py")

        values: dict[str, Capability] = {}
        values["rootlessRuntime"] = Capability(
            CapabilityState.SUPPORTED if rootless else CapabilityState.UNSUPPORTED,
            "Procursus rootless prefix is present" if rootless else
            "The configured rootless prefix is absent", (str(p.root_prefix),))
        values["packageDatabase"] = Capability(
            CapabilityState.SUPPORTED if dpkg_status.is_file() and dpkg else
            CapabilityState.DEGRADED if dpkg_status.is_file() else CapabilityState.UNSUPPORTED,
            "dpkg status and command are available" if dpkg_status.is_file() and dpkg else
            "dpkg state is incomplete", tuple(x for x in (str(dpkg_status), dpkg) if x))
        values["processInspection"] = Capability(
            CapabilityState.SUPPORTED if ps else CapabilityState.UNSUPPORTED,
            "Bounded process enumeration is available" if ps else "No approved ps command", (ps,) if ps else ())
        values["deviceHealth"] = Capability(
            CapabilityState.SUPPORTED,
            "Local storage, database, uptime, and sensor-health evidence is available")
        values["tweakEnumeration"] = Capability(
            CapabilityState.SUPPORTED if tweaks and dpkg_status.is_file() else CapabilityState.DEGRADED,
            "Owned tweak directories and dpkg metadata are available" if tweaks and dpkg_status.is_file()
            else "Tweak directory or package ownership metadata is unavailable",
            tuple(str(x) for x in tweak_dirs if x.is_dir()))
        values["tweakDisable"] = Capability(
            CapabilityState.SUPPORTED if dpkg and tweaks else CapabilityState.UNSUPPORTED,
            "The existing runtime can quarantine or remove owned tweaks" if dpkg and tweaks
            else "No supported package-backed tweak mutation path")
        values["networkObservation"] = Capability(
            CapabilityState.MONITOR_ONLY if ps else CapabilityState.UNSUPPORTED,
            "Live collector health determines whether current socket evidence is available"
            if ps else "No process evidence source")
        values["networkEnforcement"] = Capability(
            CapabilityState.SUPPORTED if localfence_ready else
            CapabilityState.DEGRADED if localfence else CapabilityState.UNSUPPORTED,
            "LocalFence answered its bounded status check" if localfence_ready else
            "LocalFence is installed but its control service did not answer" if localfence else
            "No reviewed per-app enforcement provider",
            localfence_evidence)
        values["crashObservation"] = Capability(
            CapabilityState.MONITOR_ONLY if crash else CapabilityState.UNSUPPORTED,
            "Crash log directory is observable; live collector health determines attribution status" if crash else
            "No readable crash source", tuple(str(x) for x in crash_dirs if x.is_dir()))
        values["tweakConflictAnalysis"] = Capability(
            CapabilityState.MONITOR_ONLY if registry.is_file() else CapabilityState.UNSUPPORTED,
            "Runtime filters can be analyzed; selector-level evidence requires a reviewed provider"
            if registry.is_file() else "The runtime tweak registry is unavailable",
            (str(registry),) if registry.is_file() else ())
        values["safeModeRecovery"] = Capability(
            CapabilityState.SUPPORTED if registry.is_file() and recovery_controller.is_file()
            else CapabilityState.UNSUPPORTED,
            "The bounded manager request controller is available; actions are reversible and never remove packages"
            if registry.is_file() and recovery_controller.is_file() else
            "The runtime registry or bounded manager request controller is unavailable",
            tuple(str(x) for x in (registry, recovery_controller) if x.is_file()))
        # These remain explicit until a real collector/controller is integrated.
        for name, reason in {
            "privacyObservation": "No reviewed privacy event collector is installed",
            "privacyEnforcement": "No reviewed per-resource enforcement provider is installed",
            "batteryMonitoring": "No validated battery observation is available yet",
            "thermalMonitoring": "No reviewed thermal state provider is installed",
            "chargeControl": "No reviewed charging controller is installed",
            "appSnapshot": "Snapshot coordinator is not implemented",
            "profileAutomation": "Profile transaction engine is not implemented",
            "appFreeze": "No reviewed app-freeze controls are installed",
            "storageIntelligence": "Storage classification engine is not initialized",
            "notificationObservation": "Notification metadata collector is not implemented",
            "permissionTimeout": "No reviewed reversible permission controller is installed",
        }.items():
            values[name] = Capability(CapabilityState.UNSUPPORTED, reason)
        return values

    def as_dict(self) -> dict[str, dict[str, object]]:
        return {name: capability.as_dict()
                for name, capability in self.detect().items()}

    def platform_summary(self) -> dict[str, str]:
        return {"system": platform.system(), "release": platform.release(),
                "machine": platform.machine()}
