"""Shared 0-Sky core runtime used by the existing manager and broker."""
from __future__ import annotations

import json
import base64
import hashlib
import os
import plistlib
import re
import signal
import time
from pathlib import Path
from typing import Any, Callable

from .capabilities import CapabilityMatrix
from .database import EventStore, SCHEMA_VERSION
from .health import SensorState
from .ipc import IPCValidationError, response, validate_request
from .logging import StructuredLogger
from .paths import RootlessPaths
from .sensors import TelemetryCoordinator
from .sensors import PACKAGE_ID, PackageInventory
from .sensors import LibprocBackend
from .snapshots import SnapshotCoordinator, SnapshotError
from .automation import (AutomationEngine, FreezeCoordinator, PolicyError,
                         ProfileEngine)
from .intelligence import PermissionTimeoutCoordinator
from .storage import StorageScanner
from .research_toolkit_device import collect as collect_research_toolkit
from .research_toolkit import load_catalog
from .research_toolkit_runner import overall_result, run_smoke, run_uat, write_bundle

PROTECTED_QUARANTINE_PACKAGES = frozenset({
    "apt", "dpkg", "ellekit", "preferenceloader", "sileo", "org.coolstar.sileo",
    "com.liquidskysecurity.srd-runtime-manager",
})


class CoreRuntime:
    def __init__(self, root: Path = Path("/"), telemetry_owner: bool = True,
                 crane_handoff: Callable[[list[dict[str, str]]], Any] | None = None) -> None:
        self.paths = RootlessPaths(root=Path(root))
        self.logger = StructuredLogger(self.paths.log_directory / "core.jsonl")
        self.store = EventStore(self.paths.database_path)
        self.capabilities = CapabilityMatrix(self.paths)
        self.started_at = time.time()
        self._started = False
        self._telemetry_owner = telemetry_owner
        self.telemetry: TelemetryCoordinator | None = None
        self.snapshots = SnapshotCoordinator(self.paths, self.store,
                                             stop_app=self._stop_snapshot_app)
        self.freeze = FreezeCoordinator(self.paths, self.store,
                                        self.snapshots.installed_apps)
        self.profiles = ProfileEngine(self.store, self.freeze)
        self.automation = AutomationEngine(self.store, self.profiles, self.freeze,
                                           self.snapshots.create)
        self.storage = StorageScanner(self.paths, self.snapshots.installed_apps)
        self.permissions = PermissionTimeoutCoordinator(self.store)
        self._next_permission_maintenance = 0.0
        self._core_ipc_recovered = False
        self._crane_handoff = crane_handoff

    def _toolkit_evidence(self) -> dict:
        path = self.paths.state_directory / "research-toolkit/evidence.json"
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 512 * 1024:
            return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, UnicodeDecodeError) as error:
            self.logger.log("WARN", "TOOLKIT", "stored toolkit evidence unreadable",
                            error=type(error).__name__)
            return {}

    def _toolkit_snapshot(self) -> dict:
        health = self.store.package_health(time.time() - 7 * 86400)
        packages = PackageInventory(self.paths).collect(512, health=health)
        result = collect_research_toolkit(self.paths, catalog=load_catalog(),
                                        package_rows=packages,
                                        prior=self._toolkit_evidence())
        latest = self.paths.state_directory / "research-toolkit/latest.json"
        if latest.is_file() and not latest.is_symlink() and latest.stat().st_size <= 32768:
            try:
                value = json.loads(latest.read_text(encoding="utf-8"))
                result["uat_summary"] = value if isinstance(value, dict) else None
            except (OSError, ValueError, UnicodeDecodeError):
                result["uat_summary"] = None
        return result

    @staticmethod
    def _supported_tweak_target_package(value: Any) -> str:
        if value != "com.opa334.crane":
            raise IPCValidationError("INVALID_PARAMETERS",
                                     "this package has no reviewed application-target adapter")
        return value

    def _tweak_target_path(self, package: str) -> Path:
        return self.paths.jailbreak(
            f"/var/lib/srd-runtime/tweak-targets/{package}.json")

    def _read_tweak_targets(self, package: str) -> list[str]:
        path = self._tweak_target_path(package)
        try:
            info = path.lstat()
            if (path.is_symlink() or not path.is_file() or info.st_mode & 0o022 or
                    info.st_size > 64 * 1024):
                return []
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError, UnicodeError):
            return []
        if not isinstance(value, dict):
            return []
        identifiers = value.get("bundle_identifiers", [])
        if (set(value) != {"schema", "package", "bundle_identifiers", "updated_at"} or
                value.get("schema") != 1 or value.get("package") != package or
                not isinstance(value.get("updated_at"), (int, float)) or
                isinstance(value.get("updated_at"), bool) or
                not isinstance(identifiers, list) or len(identifiers) > 64 or
                len(set(identifiers)) != len(identifiers) or
                not all(isinstance(item, str) and PACKAGE_ID.fullmatch(item)
                        for item in identifiers)):
            return []
        return identifiers

    @staticmethod
    def _crane_adapter_state(app: dict[str, Any],
                             paths: RootlessPaths | None = None) -> str:
        bundle = app.get("bundleID")
        raw_path = app.get("bundlePath")
        if isinstance(raw_path, Path):
            bundle_path = raw_path
        else:
            display = app.get("bundlePathDisplay")
            if (not isinstance(display, str) or "\x00" in display or
                    not re.fullmatch(
                        r"/(?:private/)?var/containers/Bundle/Application/"
                        r"[A-Za-z0-9-]+/[^/]+\.app|"
                        r"/private/var/run/com\.apple\.security\.cryptexd/mnt/"
                        r"[^/]+/Applications/[^/]+\.app", display)):
                return "ADAPTATION_REQUIRED"
            if paths is None:
                return "ADAPTATION_REQUIRED"
            try:
                bundle_path = paths.system(display)
            except ValueError:
                return "ADAPTATION_REQUIRED"
        if not isinstance(bundle, str):
            return "ADAPTATION_REQUIRED"
        marker = bundle_path / "0SkyCraneAdapter.plist"
        try:
            if marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 16 * 1024:
                return "ADAPTATION_REQUIRED"
            value = plistlib.loads(marker.read_bytes())
        except (OSError, ValueError, plistlib.InvalidFileException):
            return "ADAPTATION_REQUIRED"
        expected = {
            "Schema": 1,
            "Adapter": "crane-pre-main-v1",
            "BundleIdentifier": bundle,
            "StateTransport": "private-data-handoff-v1",
            "Runtime": "embedded-reviewed-crane",
        }
        return "COMPATIBLE_WITH_ADAPTER" if value == expected else "ADAPTATION_REQUIRED"

    def _crane_active_container(self, bundle: str) -> str:
        preferences = self.paths.jailbreak(
            "/var/mobile/Library/Preferences/com.opa334.craneprefs.plist")
        try:
            if (preferences.is_symlink() or not preferences.is_file() or
                    preferences.stat().st_size > 4 * 1024 * 1024):
                return "DEFAULT"
            value = plistlib.loads(preferences.read_bytes())
        except (OSError, ValueError, plistlib.InvalidFileException):
            return "DEFAULT"
        settings = value.get("appSettings_" + bundle) if isinstance(value, dict) else None
        if not isinstance(settings, dict):
            return "DEFAULT"
        active = settings.get("activeContainer", "DEFAULT")
        if active == "DEFAULT":
            return active
        if (not isinstance(active, str) or not re.fullmatch(
                r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", active)):
            raise IPCValidationError("INVALID_STATE", "Crane active container is malformed")
        identifiers = {
            item.get("identifier") for item in settings.get("Containers", [])
            if isinstance(item, dict) and isinstance(item.get("identifier"), str)
        }
        if active not in identifiers:
            raise IPCValidationError("INVALID_STATE",
                                     "Crane active container is absent from its inventory")
        return active.upper()

    @staticmethod
    def _atomic_private_file(path: Path, payload: bytes | None,
                             owner: tuple[int, int]) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        os.chown(path.parent, owner[0], owner[1])
        if payload is None:
            path.unlink(missing_ok=True)
            return
        temporary = path.with_name(path.name + f".{os.getpid()}.{time.time_ns()}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, owner[0], owner[1])
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        finally:
            os.close(descriptor)
        os.replace(temporary, path)

    def _reconcile_crane_handoffs(self, selected: set[str],
                                  applications: dict[str, dict[str, Any]]) -> None:
        for bundle, app in applications.items():
            if self._crane_adapter_state(app, self.paths) != "COMPATIBLE_WITH_ADAPTER":
                continue
            container = app.get("containerPath")
            if (not isinstance(container, Path) or container.is_symlink() or
                    not container.is_dir()):
                raise IPCValidationError("INVALID_STATE",
                                         "converted application data container is unavailable")
            info = container.stat()
            handoff = container / "Library/0Sky/Crane/active-container"
            active = self._crane_active_container(bundle) if bundle in selected else "DEFAULT"
            payload = None if active == "DEFAULT" else (active + "\n").encode("ascii")
            self._atomic_private_file(handoff, payload, (info.st_uid, info.st_gid))

    def _tweak_target_apps(self, package_value: Any) -> dict[str, Any]:
        package = self._supported_tweak_target_package(package_value)
        selected = set(self._read_tweak_targets(package))
        protected = {
            "com.liquidsky.CrypStore", "codes.liquidsky.research.zerosky",
            "com.amywhile.sileo", "com.opa334.CraneApplication",
        }
        applications = []
        # Snapshot inventory requires both a readable bundle and its exact MCM
        # data container. The launchd-hosted broker can be denied traversal of
        # those directories on an SRD even though LaunchServices can still
        # prove the app registration. Merge both views for this picker only.
        inventory = {app.get("bundleID"): app
                     for app in self.snapshots.registered_apps()
                     if isinstance(app.get("bundleID"), str)}
        inventory.update({app.get("bundleID"): app
                          for app in self.snapshots.installed_apps()
                          if isinstance(app.get("bundleID"), str)})
        for app in inventory.values():
            bundle = app.get("bundleID")
            if not isinstance(bundle, str) or bundle in protected:
                continue
            applications.append({
                "bundleID": bundle,
                "name": str(app.get("name") or bundle)[:255],
                "version": str(app.get("version") or "unknown")[:128],
                "enabled": bundle in selected,
                "compatibility": self._crane_adapter_state(app, self.paths),
            })
        applications.sort(key=lambda item: (item["name"].casefold(), item["bundleID"]))
        return {"package": package, "applications": applications,
                "selected": sorted(selected), "targetCount": len(selected),
                "scope": "explicit-user-selected-third-party-applications"}

    def _set_tweak_targets(self, request: Any,
                           caller: dict[str, Any] | None) -> dict[str, Any]:
        self._require_paired(caller)
        package = self._supported_tweak_target_package(request.parameters.get("package"))
        identifiers = request.parameters.get("bundleIDs")
        if (not isinstance(identifiers, list) or len(identifiers) > 64 or
                len(set(identifiers)) != len(identifiers) or
                not all(isinstance(item, str) and PACKAGE_ID.fullmatch(item)
                        for item in identifiers)):
            raise IPCValidationError("INVALID_PARAMETERS",
                                     "bundleIDs must be a unique bounded identifier list")
        registered = {item["bundleID"]: item for item in self.snapshots.registered_apps()
                      if isinstance(item.get("bundleID"), str)}
        installed = {item["bundleID"]: item for item in self.snapshots.installed_apps()
                     if isinstance(item.get("bundleID"), str)}
        inventory = {**registered, **installed}
        available = {item["bundleID"] for item in
                     self._tweak_target_apps(package)["applications"]}
        unavailable = sorted(set(identifiers) - available)
        if unavailable:
            raise IPCValidationError("INVALID_PARAMETERS",
                                     "one or more selected applications are unavailable")
        unconverted = sorted(bundle for bundle in identifiers
                             if self._crane_adapter_state(inventory.get(bundle, {}), self.paths) !=
                             "COMPATIBLE_WITH_ADAPTER")
        if unconverted:
            raise IPCValidationError(
                "ADAPTATION_REQUIRED",
                "Crane requires a verified pre-main 0-Sky app conversion: " +
                ", ".join(unconverted[:8]))
        path = self._tweak_target_path(package)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        previous_targets = set(self._read_tweak_targets(package))
        handoff_roots = request.parameters.get("dataRoots", {})
        affected = previous_targets | set(identifiers)
        if self._crane_handoff is not None:
            if (not isinstance(handoff_roots, dict) or len(handoff_roots) > 64 or
                    not all(isinstance(key, str) and PACKAGE_ID.fullmatch(key) and
                            isinstance(value, str) and re.fullmatch(
                                r"/(?:private/)?var/mobile/Containers/Data/Application/"
                                r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}",
                                value)
                            for key, value in handoff_roots.items()) or
                    not affected.issubset(handoff_roots)):
                raise IPCValidationError(
                    "INVALID_PARAMETERS",
                    "dataRoots must map every changed Crane target to its exact MCM root")
        try:
            previous_payload = path.read_bytes() if path.is_file() and not path.is_symlink() else None
        except OSError:
            previous_payload = None
        payload = {"schema": 1, "package": package,
                   "bundle_identifiers": sorted(identifiers),
                   "updated_at": time.time()}
        temporary = path.with_name(path.name + f".{os.getpid()}.{time.time_ns()}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(descriptor, (json.dumps(payload, separators=(",", ":")) + "\n").encode())
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
        except Exception:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        try:
            if self._crane_handoff is not None:
                plans = [{
                    "bundle_id": bundle,
                    "data_root": ("/private" + handoff_roots[bundle]
                                  if handoff_roots[bundle].startswith("/var/mobile/")
                                  else handoff_roots[bundle]),
                    "active": (self._crane_active_container(bundle)
                               if bundle in identifiers else "DEFAULT"),
                } for bundle in sorted(affected)]
                self._crane_handoff(plans)
            else:
                self._reconcile_crane_handoffs(set(identifiers), installed)
        except Exception:
            self._atomic_private_file(path, previous_payload, (0, 0))
            if self._crane_handoff is None:
                try:
                    self._reconcile_crane_handoffs(previous_targets, installed)
                except Exception as rollback_error:
                    self.logger.log("ERROR", "PACKAGE",
                                    "Crane target handoff rollback failed",
                                    package=package, error=type(rollback_error).__name__)
            raise
        (self.paths.jailbreak("/var/lib/srd-runtime") / "rescan.request").touch()
        self.logger.log("INFO", "PACKAGE", "application targets updated",
                        package=package, targetCount=len(identifiers),
                        caller="authenticated-control")
        return self._tweak_target_apps(package)

    def _run_toolkit_suite(self, with_uat: bool) -> dict:
        snapshot = self._toolkit_snapshot()
        smoke = run_smoke(snapshot)
        evidence = self._toolkit_evidence()
        now = time.time()
        os_version = snapshot["environment"]["ios_version"]
        for row in snapshot["components"]:
            component = row["id"]
            test = smoke.get("component_results", {}).get(component)
            if not isinstance(test, dict):
                continue
            evidence[component] = {
                "os_version": os_version,
                "installed_version": row.get("installed_version"),
                "timestamp": now,
                "smoke": test["smoke"], "runtime": test["runtime"],
                "configured": test["configured"], "uat": "SKIP"}
        directory = self.paths.state_directory / "research-toolkit"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = directory / "evidence.json.tmp"
        temporary.write_text(json.dumps(evidence, separators=(",", ":")) + "\n",
                             encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, directory / "evidence.json")
        snapshot = self._toolkit_snapshot()
        uat = run_uat(snapshot, smoke) if with_uat else {"result": "DEGRADED",
            "counts": {"SKIP": 12}, "tests": [], "timestamp": smoke["timestamp"]}
        report = write_bundle(directory / "reports", snapshot, smoke, uat)
        overall = overall_result(smoke, uat if with_uat else None)
        latest = {"smoke": smoke["counts"], "smoke_result": smoke["result"],
                  "uat": uat["counts"], "uat_result": uat["result"],
                  "overall": overall, "report": str(report / "0sky-uat.zip"), "timestamp": now}
        temporary = directory / "latest.json.tmp"
        temporary.write_text(json.dumps(latest, separators=(",", ":")) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, directory / "latest.json")
        self.logger.log("INFO", "TOOLKIT", "research toolkit suite completed",
                        result=overall,
                        smoke=smoke["counts"], uat=uat["counts"])
        return {"smoke": smoke, "uat": uat if with_uat else None,
                "report": str(report / "0sky-uat.zip"),
                "overall": overall}

    def start(self) -> None:
        if self._started:
            return
        self.paths.ensure_directories()
        self.store.initialize()
        if self._telemetry_owner:
            self.telemetry = TelemetryCoordinator(
                self.paths, self.store,
                uptime=lambda: max(0.0, time.time() - self.started_at))
        self.store.update_sensor_health("core", SensorState.RUNNING.value, success=True)
        self.store.record_event("CORE", "CORE_STARTED", "INFO",
                                {"schemaVersion": SCHEMA_VERSION})
        self.profiles.seed()
        self.logger.log("INFO", "CORE", "0-Sky core initialized",
                        schemaVersion=SCHEMA_VERSION,
                        recoveredDatabase=bool(self.store.recovery_copy))
        self._started = True

    def tick(self) -> int:
        """Run only collectors whose deadline has elapsed.

        This method is called by the existing manager loop; it does not create
        another thread or constant polling timer.
        """
        self.start()
        count = self.telemetry.tick() if self.telemetry is not None else 0
        count += self.automation.maintain()
        moment = time.monotonic()
        if moment >= self._next_permission_maintenance:
            self._next_permission_maintenance = moment + 30.0
            count += self.permissions.maintain()
        return count

    def close(self) -> None:
        self.store.close()
        self._started = False

    def status(self) -> dict[str, Any]:
        self.start()
        return {"schemaVersion": SCHEMA_VERSION,
                "protocolVersion": 1,
                "uptimeSeconds": max(0.0, time.time() - self.started_at),
                "databaseIntegrity": self.store.integrity(),
                "databasePath": str(self.paths.database_path),
                "recoveryCopy": str(self.store.recovery_copy) if self.store.recovery_copy else None,
                "paths": self.paths.as_dict(),
                "platform": self.capabilities.platform_summary()}

    @staticmethod
    def _bounded_integer(value: Any, default: int, maximum: int) -> int:
        if value is None:
            return default
        if not isinstance(value, int) or isinstance(value, bool):
            raise IPCValidationError("INVALID_PARAMETERS", "limit must be an integer")
        return min(maximum, max(1, value))

    def capability_payload(self) -> dict[str, dict[str, object]]:
        values = self.capabilities.as_dict()
        if self.telemetry:
            for name, (state, reason) in self.telemetry.capability_states().items():
                if state == SensorState.FAILED.value:
                    state = "Degraded"
                values[name] = {"state": state, "reason": reason,
                                "evidence": []}
        # The authenticated bridge is a read-only, non-collecting CoreRuntime
        # instance. Reflect persisted manager evidence so its capability view
        # stays accurate without starting duplicate collectors.
        mapping = {"process": "processInspection", "battery": "batteryMonitoring",
                   "thermal": "thermalMonitoring", "device_health": "deviceHealth",
                   "network": "networkObservation", "privacy": "privacyObservation",
                   "crash": "crashObservation", "conflict": "tweakConflictAnalysis"}
        mapping["notification"] = "notificationObservation"
        for row in self.store.sensor_health():
            name = mapping.get(str(row.get("sensor")))
            if not name:
                continue
            state = str(row.get("state") or SensorState.DEGRADED.value)
            if state == SensorState.RUNNING.value:
                state = ("MonitorOnly" if row.get("sensor") in ("network", "privacy", "conflict")
                         else "Supported")
            elif state == SensorState.FAILED.value:
                state = "Degraded"
            values[name] = {
                "state": state,
                "reason": (str(row.get("error")) if row.get("error") else
                           "Validated live telemetry is available"),
                "evidence": [f"sensor-health:{row.get('sensor')}"]}
        # The root collector may be unable to access iOS application-only APIs
        # and can therefore report Unsupported after Control has published a
        # valid observation. A recent, exact-source database row is stronger
        # evidence than that failed fallback probe. Never keep a stale row
        # alive as current support.
        recent_sources = {
            "batteryMonitoring": ("battery_samples", "UIDevice"),
            "thermalMonitoring": ("thermal_samples", "NSProcessInfo"),
        }
        now = time.time()
        for capability_name, (table, expected_source) in recent_sources.items():
            rows = self.store.latest_rows(table, 1)
            row = rows[0] if rows else None
            stamp = row.get("timestamp") if isinstance(row, dict) else None
            if (isinstance(stamp, (int, float)) and not isinstance(stamp, bool) and
                    -30 <= now - float(stamp) <= 600 and
                    row.get("source") == expected_source):
                values[capability_name] = {
                    "state": "Supported",
                    "reason": "Validated recent public iOS API telemetry is available",
                    "evidence": [f"sample:{row.get('id')}", expected_source],
                }
        # iOS does not publish a supported charging-threshold controller to
        # third-party applications.  Once genuine battery state is available,
        # expose charging management as observation-only instead of implying
        # that 0-Sky can change a threshold it cannot verify.
        if values.get("batteryMonitoring", {}).get("state") == "Supported":
            values["chargeControl"] = {
                "state": "MonitorOnly",
                "reason": ("Validated battery, charging, and Low Power Mode telemetry is "
                           "available; iOS retains charging-threshold control"),
                "evidence": ["sensor-health:battery", "UIDevice"],
            }
        snapshot = self.snapshots.capability()
        values["appSnapshot"] = {
            "state": snapshot["state"], "reason": snapshot["reason"],
            "evidence": ["exact-mcm-container", "sha256-manifest",
                         "keychain-excluded"] if snapshot["state"] == "Supported" else []}
        automation = self.automation.capability()
        values["profileAutomation"] = {
            "state": automation["state"], "reason": automation["reason"],
            "evidence": ["structured-rule-schema", "transactional-profile-engine",
                         "no-arbitrary-shell"]}
        freeze = self.freeze.capability()
        values["appFreeze"] = {
            "state": freeze["state"], "reason": freeze["reason"],
            "evidence": ["automation-suppression", "original-policy-state"]}
        values["storageIntelligence"] = {
            "state": "Supported",
            "reason": "Bounded exact-root storage classification is available; cleanup remains explicit and read-only",
            "evidence": ["exact-mcm-containers", "no-substring-deletion", "bounded-walk"]}
        permission = self.permissions.capability()
        values["permissionTimeout"] = {
            "state": permission["state"], "reason": permission["reason"],
            "evidence": ["expiration-database", "original-policy-restore"]}
        return values

    def _stop_snapshot_app(self, app: dict[str, Any]) -> dict[str, Any]:
        """Stop only PIDs whose kernel-reported executable is the exact app."""
        executable = app.get("executablePath")
        if not isinstance(executable, Path) or not executable.is_file():
            raise SnapshotError("APP_EXECUTABLE_UNAVAILABLE",
                                "the installed application's exact executable is unavailable")
        expected = os.path.realpath(executable)
        try:
            backend = LibprocBackend()
            matches = [pid for pid in backend.pids()
                       if (value := backend.path(pid)) and os.path.realpath(value) == expected]
        except OSError as error:
            raise SnapshotError("PROCESS_INSPECTION_UNAVAILABLE",
                                "exact process inspection is unavailable") from error
        if not matches:
            return {"wasRunning": False, "stopped": True, "pids": []}
        for pid in matches:
            try:
                # Revalidate immediately before signalling to contain PID reuse.
                current = backend.path(pid)
                if not current or os.path.realpath(current) != expected:
                    raise SnapshotError("STALE_PID", "target application PID changed")
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
            except PermissionError as error:
                raise SnapshotError("APP_RUNNING", "target application could not be stopped") from error
        deadline = time.monotonic() + 5.0
        remaining = set(matches)
        while remaining and time.monotonic() < deadline:
            for pid in tuple(remaining):
                current = backend.path(pid)
                if not current or os.path.realpath(current) != expected:
                    remaining.discard(pid)
            if remaining:
                time.sleep(0.1)
        return {"wasRunning": True, "stopped": not remaining,
                "pids": matches, "remainingPIDs": sorted(remaining)}

    def _runtime_registry(self) -> dict[str, Any]:
        path = self.paths.jailbreak("/var/lib/srd-runtime/registry.json")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def _clear_tweak_quarantine(self, request: Any,
                                caller: dict[str, Any] | None) -> dict[str, Any]:
        """Queue one exact package/target retry for the authoritative manager."""
        if not caller or caller.get("paired") is not True:
            raise IPCValidationError("AUTHORIZATION_REQUIRED",
                                     "a paired authorized Mac is required to retry a tweak")
        package = request.parameters.get("package")
        target = request.parameters.get("target")
        if not isinstance(package, str) or not PACKAGE_ID.fullmatch(package):
            raise IPCValidationError("INVALID_PARAMETERS", "invalid package identifier")
        if (not isinstance(target, str) or not 1 <= len(target) <= 512 or
                "\x00" in target):
            raise IPCValidationError("INVALID_PARAMETERS", "target must be a bounded string")
        if package.lower() in PROTECTED_QUARANTINE_PACKAGES:
            raise IPCValidationError(
                "PROTECTED_PACKAGE",
                "foundational runtime packages cannot be retried from the tweak menu")
        quarantined = self._runtime_registry().get("quarantined", [])
        matches = [item for item in quarantined if isinstance(item, dict) and
                   item.get("package") == package and item.get("target") == target]
        if not matches:
            raise IPCValidationError(
                "QUARANTINE_CHANGED",
                "this exact package and target are no longer quarantined")

        request_path = self.paths.jailbreak(
            "/var/lib/srd-runtime/quarantine-clear.request.json")
        payload = {"schema": 1, "request_id": request.request_id,
                   "created_at": time.time(), "package": package, "target": target}
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        try:
            descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as error:
            raise IPCValidationError(
                "RECOVERY_BUSY", "another quarantine retry is awaiting the manager") from error
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                request_path.unlink()
            except OSError:
                pass
            raise
        self.record_change("PACKAGE", "quarantine_retry_queued", package,
                           previous_state={"target": target,
                                           "quarantinedEntries": len(matches)},
                           new_state={"queued": True}, reversible=False,
                           transaction_id=request.request_id)
        return {"queued": True, "package": package, "target": target,
                "matchingEntries": len(matches), "packageRemovalPerformed": False,
                "message": "Retry queued; the runtime will quarantine the tweak again if it fails."}

    def _recovery_episodes(self) -> list[dict[str, Any]]:
        crashes = self.store.latest_crashes(500)
        cutoff = time.time() - 600
        counts: dict[str, int] = {}
        candidates: dict[str, dict[str, int]] = {}
        for crash in crashes:
            if float(crash["timestamp"]) < cutoff:
                continue
            process = str(crash["process"])
            counts[process] = counts.get(process, 0) + 1
            for package in crash["package_candidates"]:
                candidates.setdefault(process, {})[str(package)] = (
                    candidates.setdefault(process, {}).get(str(package), 0) + 1)
        return [{"process": process, "crashCount": count,
                 "triggered": count >= 3,
                 "candidatePackages": [{"package": package,
                    "configuredCrashCount": value}
                    for package, value in sorted(candidates.get(process, {}).items(),
                                                 key=lambda item: (-item[1], item[0]))]}
                for process, count in sorted(counts.items(),
                                             key=lambda item: (-item[1], item[0]))]

    def _control_center_summary(self) -> dict[str, Any]:
        """Build one cheap, problem-first dashboard payload.

        This deliberately avoids package parsing and storage walking.  The UI
        can request those demand-only views after the user selects them.
        """
        now = time.time()
        sensors = self.store.sensor_health()
        failed = [row for row in sensors if row.get("state") == SensorState.FAILED.value]
        degraded = [row for row in sensors if row.get("state") == SensorState.DEGRADED.value]
        crashes = [row for row in self.store.latest_crashes(100)
                   if float(row.get("timestamp") or 0) >= now - 86400]
        conflicts = [row for row in self.store.current_conflicts(100)
                     if str(row.get("severity")) in {"possible conflict", "probable conflict"}]
        battery_rows = self.store.latest_rows("battery_samples", 1)
        thermal_rows = self.store.latest_rows("thermal_samples", 1)
        health = self.store.latest_health_metrics()
        metrics = {str(row.get("metric")): row for row in health}
        # Dashboard counts come directly from the indexed policy table.  The
        # full Freeze view performs MCM/app discovery only after navigation.
        frozen = self.store.frozen_apps()
        problems: list[dict[str, Any]] = []
        for row in failed[:3]:
            problems.append({"severity": "critical", "title": f"{row['sensor']} sensor failed",
                             "detail": row.get("error") or "Collector requires attention",
                             "destination": "health"})
        for row in degraded[:3]:
            problems.append({"severity": "warning", "title": f"{row['sensor']} sensor degraded",
                             "detail": row.get("error") or "Telemetry is incomplete",
                             "destination": "health"})
        if crashes:
            problems.append({"severity": "warning", "title": "Recent crashes",
                             "detail": f"{len(crashes)} validated report(s) in 24 hours",
                             "destination": "recovery"})
        if conflicts:
            problems.append({"severity": "warning", "title": "Tweak conflicts",
                             "detail": f"{len(conflicts)} possible or probable conflict(s)",
                             "destination": "recovery"})
        problems = problems[:8]
        state = "Critical" if failed else ("Attention" if problems else "Healthy")
        free = metrics.get("storage.free_bytes", {}).get("value_real")
        return {
            "generatedAt": now,
            "state": state,
            "problems": problems,
            "counts": {"failedSensors": len(failed), "degradedSensors": len(degraded),
                       "recentCrashes": len(crashes), "actionableConflicts": len(conflicts),
                       "frozenApps": sum(1 for row in frozen
                                         if row.get("state") == "Frozen")},
            "device": {"freeStorageBytes": free,
                       "coreUptimeSeconds": max(0.0, now - self.started_at),
                       "battery": battery_rows[0] if battery_rows else None,
                       "thermal": thermal_rows[0] if thermal_rows else None},
            "activeProfile": self.store.active_profile(),
            "databaseIntegrity": self.store.integrity(),
            "refreshPolicy": "on-open-or-user-request",
        }

    def _recovery_options(self) -> dict[str, Any]:
        snapshot = self.snapshots.capability()
        return {"options": [
            {"id": "daemon-disable", "state": "HostOnly",
             "reason": "Use the paired Mac companion so the service cannot terminate its own response."},
            {"id": "collector-disable", "state": "Unsupported",
             "reason": "Collectors are circuit-breaker isolated; persistent per-collector disabling is not reviewed."},
            {"id": "start-without-tweaks", "state": "Supported",
             "reason": "Exact registered targets can start with reversible tweak overrides."},
            {"id": "database-recovery", "state": "Supported",
             "reason": "Startup integrity checking preserves corrupt originals before creating a recovered store."},
            {"id": "database-reset", "state": "HostOnly",
             "reason": "A destructive reset is intentionally unavailable in app IPC and requires an explicit backup on the paired Mac."},
            {"id": "profile-rollback", "state": "Supported",
             "reason": "Profile application is transactional and rolls back automatically on failure."},
            {"id": "automation-disable", "state": "Supported",
             "reason": "Rules can be disabled individually without arbitrary command execution."},
            {"id": "snapshot-recovery", "state": snapshot["state"],
             "reason": snapshot["reason"]},
        ], "databaseIntegrity": self.store.integrity(),
            "recoveryCopy": str(self.store.recovery_copy) if self.store.recovery_copy else None}

    def _queue_recovery(self, request: Any, caller: dict[str, Any] | None) -> dict[str, Any]:
        if not caller or caller.get("paired") is not True:
            raise IPCValidationError("AUTHORIZATION_REQUIRED",
                                     "a paired authorized Mac is required for recovery actions")
        registry = self._runtime_registry()
        targets = registry.get("targets", {}) if isinstance(registry.get("targets"), dict) else {}
        process = request.parameters.get("process")
        if not isinstance(process, str) or not process or len(process) > 512:
            raise IPCValidationError("INVALID_PARAMETERS", "process must be a bounded string")
        matches = [target for target in targets.values()
                   if isinstance(target, dict) and target.get("name") == process]
        if len(matches) != 1:
            raise IPCValidationError("UNSUPPORTED_TARGET",
                                     "process is not one exact current tweak target")
        target = matches[0]
        available = {str(item.get("package")) for item in target.get("dylibs", [])
                     if isinstance(item, dict) and
                     PACKAGE_ID.fullmatch(str(item.get("package") or ""))}
        packages: list[str] = []
        if request.operation == "disableSelectedTweak":
            package = request.parameters.get("package")
            if not isinstance(package, str) or not PACKAGE_ID.fullmatch(package):
                raise IPCValidationError("INVALID_PARAMETERS", "invalid package identifier")
            if package not in available:
                raise IPCValidationError("UNSUPPORTED_TARGET",
                                         "package is not configured for this process")
            packages = [package]
        elif request.operation == "disableRecentTweaks":
            cutoff = time.time() - 7 * 86400
            packages = sorted({str(row.get("target")) for row in self.store.recent_changes(200)
                               if float(row.get("timestamp") or 0) >= cutoff and
                               row.get("component") == "PACKAGE" and
                               str(row.get("target")) in available})[:16]
            if not packages:
                raise IPCValidationError(
                    "NO_EVIDENCE", "no recently changed package is configured for this process")
        elif "package" in request.parameters or "packages" in request.parameters:
            raise IPCValidationError("INVALID_PARAMETERS",
                                     "this recovery action does not accept package parameters")

        request_path = self.paths.jailbreak("/var/lib/srd-runtime/safe-mode.request.json")
        payload = {"schema": 1, "request_id": request.request_id,
                   "created_at": time.time(), "action": request.operation,
                   "process": process, "packages": packages}
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        try:
            descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as error:
            raise IPCValidationError("RECOVERY_BUSY",
                                     "another recovery action is awaiting the manager") from error
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                request_path.unlink()
            except OSError:
                pass
            raise
        episodes = self._recovery_episodes()
        crash_count = next((int(item["crashCount"]) for item in episodes
                            if item["process"] == process), 0)
        self.store.record_safe_mode_session(
            process, crash_count, "queued", request.operation,
            {"requestId": request.request_id, "packages": packages,
             "target": target.get("path"), "paired": True})
        self.record_change("RECOVERY", request.operation, process,
                           previous_state=None,
                           new_state={"queued": True, "packages": packages},
                           reversible=True, transaction_id=request.request_id)
        return {"queued": True, "requestId": request.request_id,
                "action": request.operation, "process": process,
                "packages": packages, "packageRemovalPerformed": False,
                "reversible": True}

    @staticmethod
    def _require_paired(caller: dict[str, Any] | None) -> None:
        if not caller or caller.get("paired") is not True:
            raise IPCValidationError("AUTHORIZATION_REQUIRED",
                                     "a paired authorized Mac is required for this action")

    def _publish_power_telemetry(self, request: Any,
                                 caller: dict[str, Any] | None) -> dict[str, Any]:
        """Persist only tightly validated public-API observations from Control.

        UIDevice and NSProcessInfo are the supported iOS sources available to
        the application process.  The bridge is token-authenticated and this
        write remains pairing-gated, but every field is still treated as
        untrusted input and checked before it reaches the evidence database.
        Missing readings are omitted rather than replaced by synthetic values.
        """
        self._require_paired(caller)
        parameters = request.parameters
        observed_at = parameters.get("observedAt")
        if (not isinstance(observed_at, (int, float)) or isinstance(observed_at, bool) or
                abs(time.time() - float(observed_at)) > 60):
            raise IPCValidationError(
                "INVALID_PARAMETERS", "observedAt must be a current numeric timestamp")

        battery = parameters.get("battery")
        thermal = parameters.get("thermal")
        if battery is None and thermal is None:
            raise IPCValidationError(
                "INVALID_PARAMETERS", "at least one power observation is required")

        accepted: dict[str, Any] = {}
        if battery is not None:
            if not isinstance(battery, dict):
                raise IPCValidationError("INVALID_PARAMETERS", "battery must be an object")
            level = battery.get("levelPercent")
            charging = battery.get("charging")
            state = battery.get("state")
            low_power = battery.get("lowPowerMode")
            if (not isinstance(level, (int, float)) or isinstance(level, bool) or
                    not 0 <= float(level) <= 100):
                raise IPCValidationError(
                    "INVALID_PARAMETERS", "battery levelPercent must be between 0 and 100")
            if not isinstance(charging, bool):
                raise IPCValidationError(
                    "INVALID_PARAMETERS", "battery charging must be a boolean")
            if state not in {"Unplugged", "Charging", "Full"}:
                raise IPCValidationError(
                    "INVALID_PARAMETERS", "battery state is not recognized")
            if not isinstance(low_power, bool):
                raise IPCValidationError(
                    "INVALID_PARAMETERS", "battery lowPowerMode must be a boolean")
            if charging != (state in {"Charging", "Full"}):
                raise IPCValidationError(
                    "INVALID_PARAMETERS", "battery state and charging value disagree")
            sample = {
                "level": float(level), "charging": charging, "source": "UIDevice",
                "metadata": {"state": state, "lowPowerMode": low_power,
                             "attribution": "public-ios-api"},
            }
            sample_id = self.store.record_battery_sample(sample, float(observed_at))
            self.store.update_sensor_health("battery", SensorState.RUNNING.value,
                                            success=True)
            accepted["battery"] = {"sampleID": sample_id, "levelPercent": float(level),
                                   "charging": charging, "state": state,
                                   "lowPowerMode": low_power, "source": "UIDevice"}

        if thermal is not None:
            if not isinstance(thermal, dict):
                raise IPCValidationError("INVALID_PARAMETERS", "thermal must be an object")
            state = thermal.get("state")
            if state not in {"Nominal", "Fair", "Serious", "Critical"}:
                raise IPCValidationError(
                    "INVALID_PARAMETERS", "thermal state is not recognized")
            sample = {"state": state, "source": "NSProcessInfo",
                      "metadata": {"attribution": "public-ios-api"}}
            sample_id = self.store.record_thermal_sample(sample, float(observed_at))
            self.store.update_sensor_health("thermal", SensorState.RUNNING.value,
                                            success=True)
            accepted["thermal"] = {"sampleID": sample_id, "state": state,
                                   "source": "NSProcessInfo"}

        self.store.record_event("TELEMETRY", "POWER_OBSERVATION_ACCEPTED", "INFO",
                                {"requestId": request.request_id,
                                 "sources": sorted(accepted)})
        return {"accepted": accepted, "observedAt": float(observed_at),
                "syntheticValuesUsed": False}

    @staticmethod
    def _snapshot_id(parameters: dict[str, Any], key: str = "snapshotID") -> int:
        value = parameters.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise IPCValidationError("INVALID_PARAMETERS", f"{key} must be a positive integer")
        return value

    def _snapshot_write(self, request: Any,
                        caller: dict[str, Any] | None) -> dict[str, Any]:
        self._require_paired(caller)
        try:
            if request.operation == "createSnapshot":
                bundle_id = request.parameters.get("bundleID")
                if not isinstance(bundle_id, str):
                    raise IPCValidationError("INVALID_PARAMETERS", "bundleID must be a string")
                result = self.snapshots.create(bundle_id, "manual")
                change_id = self.record_change(
                    "SNAPSHOT", "snapshot_created", bundle_id,
                    previous_state=None,
                    new_state={"snapshotID": result["id"],
                               "stateDigest": result["stateDigest"]},
                    reversible=False, transaction_id=request.request_id,
                    result={"integrity": result["integrity"]})
                # Keep the IPC response bounded even for the maximum snapshot.
                answer = dict(result)
                answer.pop("snapshotFiles", None)
                answer.pop("hashes", None)
                answer["fileCount"] = len(result["snapshotFiles"])
                answer["changeID"] = change_id
                return answer
            if request.operation == "restoreSnapshot":
                snapshot_id = self._snapshot_id(request.parameters)
                result = self.snapshots.restore(snapshot_id)
                change_id = self.record_change(
                    "SNAPSHOT", "snapshot_restored", result["bundleID"],
                    previous_state={"safetySnapshotID": result["safetySnapshotID"]},
                    new_state={"snapshotID": snapshot_id,
                               "stateDigest": result["restoredStateDigest"]},
                    reversible=True, transaction_id=request.request_id,
                    undo_operation="restoreSnapshot",
                    undo_parameters={"snapshotID": result["safetySnapshotID"],
                                     "expectedCurrentStateDigest":
                                         result["restoredStateDigest"]},
                    result={"integrity": result["integrity"]})
                return {**result, "changeID": change_id}
            if request.operation == "deleteSnapshot":
                snapshot_id = self._snapshot_id(request.parameters)
                detail = self.snapshots.inspect(snapshot_id, verify_files=True)
                result = self.snapshots.delete(snapshot_id)
                change_id = self.record_change(
                    "SNAPSHOT", "snapshot_deleted", result["bundleID"],
                    previous_state={"snapshotID": snapshot_id,
                                    "stateDigest": detail["manifest"]["stateDigest"]},
                    new_state={"deleted": True}, reversible=False,
                    transaction_id=request.request_id)
                return {**result, "changeID": change_id}
            if request.operation == "undoChange":
                change_id = request.parameters.get("changeID")
                if not isinstance(change_id, int) or isinstance(change_id, bool) or change_id < 1:
                    raise IPCValidationError("INVALID_PARAMETERS",
                                             "changeID must be a positive integer")
                change = self.store.change(change_id)
                if (not change or not change.get("reversible") or change.get("undone_at") or
                        change.get("undo_operation") not in {"restoreSnapshot", "applyProfile"}):
                    raise IPCValidationError("UNDO_UNAVAILABLE",
                                             "change is not eligible for deterministic undo")
                parameters = change.get("undo_parameters")
                if not isinstance(parameters, dict):
                    raise IPCValidationError("UNDO_UNAVAILABLE", "undo metadata is unavailable")
                if change.get("undo_operation") == "applyProfile":
                    active = self.store.active_profile()
                    if not active or active["name"] != parameters.get("expectedActiveProfile"):
                        raise IPCValidationError(
                            "STATE_CHANGED", "active profile changed after the recorded operation")
                    try:
                        result = self.profiles.apply(parameters.get("name"))
                    except PolicyError as error:
                        raise IPCValidationError(error.code, str(error)) from error
                    self.store.mark_change_undone(change_id, result)
                    undo_id = self.record_change(
                        "RECOVERY", "profile_change_undone", str(parameters.get("name")),
                        previous_state={"changeID": change_id},
                        new_state={"profile": result["profile"]}, reversible=False,
                        transaction_id=request.request_id,
                        result={"transactionID": result["transactionID"]})
                    return {**result, "undoneChangeID": change_id, "changeID": undo_id}
                expected = parameters.get("expectedCurrentStateDigest")
                current = self.snapshots.current_state_digest(str(change["target"]))
                if current != expected:
                    raise IPCValidationError(
                        "STATE_CHANGED",
                        "application state changed after the recorded operation; undo was not applied")
                result = self.snapshots.restore(self._snapshot_id(parameters))
                self.store.mark_change_undone(change_id, result)
                undo_id = self.record_change(
                    "RECOVERY", "change_undone", str(change["target"]),
                    previous_state={"changeID": change_id},
                    new_state={"snapshotID": parameters["snapshotID"],
                               "stateDigest": result["restoredStateDigest"]},
                    reversible=False, transaction_id=request.request_id,
                    result={"integrity": result["integrity"]})
                return {**result, "undoneChangeID": change_id, "changeID": undo_id}
            raise IPCValidationError("OPERATION_NOT_APPROVED", "write operation is not approved")
        except SnapshotError as error:
            raise IPCValidationError(error.code, str(error)) from error

    def _policy_write(self, request: Any,
                      caller: dict[str, Any] | None) -> dict[str, Any]:
        self._require_paired(caller)
        try:
            if request.operation == "saveProfile":
                result = self.profiles.save(request.parameters.get("profile"))
                self.record_change("AUTOMATION", "profile_saved", result["name"],
                                   new_state=result["profile"], reversible=False,
                                   transaction_id=request.request_id)
                return {"profile": result}
            if request.operation == "applyProfile":
                previous = self.store.active_profile()
                name = request.parameters.get("name")
                result = self.profiles.apply(name)
                self.record_change(
                    "AUTOMATION", "profile_applied", str(name),
                    previous_state={"profile": previous["name"] if previous else None},
                    new_state=result["effectiveState"],
                    reversible=bool(previous and previous["name"] != name),
                    transaction_id=request.request_id,
                    undo_operation="applyProfile" if previous and previous["name"] != name else None,
                    undo_parameters={"name": previous["name"], "expectedActiveProfile": name}
                        if previous and previous["name"] != name else None,
                    result={"transactionID": result["transactionID"]})
                return result
            if request.operation == "saveAutomationRule":
                enabled = request.parameters.get("enabled", True)
                rule_id = request.parameters.get("ruleID")
                if not isinstance(enabled, bool):
                    raise IPCValidationError("INVALID_PARAMETERS", "enabled must be a boolean")
                if rule_id is not None and (not isinstance(rule_id, int) or
                                            isinstance(rule_id, bool) or rule_id < 1):
                    raise IPCValidationError("INVALID_PARAMETERS", "ruleID must be positive")
                result = self.automation.save_rule(request.parameters.get("rule"),
                                                   enabled, rule_id)
                self.record_change("AUTOMATION", "rule_saved", str(result["id"]),
                                   new_state={"enabled": result["enabled"],
                                              "name": result["name"]},
                                   reversible=False, transaction_id=request.request_id)
                return {"rule": result}
            if request.operation == "setAutomationRuleEnabled":
                rule_id = request.parameters.get("ruleID")
                enabled = request.parameters.get("enabled")
                if (not isinstance(rule_id, int) or isinstance(rule_id, bool) or rule_id < 1
                        or not isinstance(enabled, bool)):
                    raise IPCValidationError("INVALID_PARAMETERS", "ruleID and enabled are required")
                previous = self.store.automation_rule(rule_id)
                if not previous:
                    raise IPCValidationError("RULE_NOT_FOUND", "automation rule does not exist")
                self.store.set_rule_enabled(rule_id, enabled)
                return {"rule": self.store.automation_rule(rule_id)}
            if request.operation == "emitAutomationEvent":
                event = request.parameters.get("event")
                result = self.automation.emit(event)
                if isinstance(event, dict) and event.get("type") in {"applicationExit", "screenLock"}:
                    result["expiredPermissionTimeouts"] = self.permissions.maintain(event=event)
                return result
            if request.operation in {"freezeApp", "temporarilyActivateApp", "unfreezeApp"}:
                bundle_id = request.parameters.get("bundleID")
                if request.operation == "freezeApp":
                    result = self.freeze.freeze(bundle_id)
                    action = "app_frozen"
                elif request.operation == "temporarilyActivateApp":
                    result = self.freeze.temporarily_activate(
                        bundle_id, request.parameters.get("durationSeconds"))
                    action = "app_temporarily_active"
                else:
                    result = self.freeze.unfreeze(bundle_id)
                    action = "app_unfrozen"
                self.record_change("AUTOMATION", action, str(bundle_id),
                                   new_state=result, reversible=request.operation != "unfreezeApp",
                                   transaction_id=request.request_id)
                return result
            if request.operation == "setTemporaryPermission":
                result = self.permissions.create(
                    request.parameters.get("bundleID"), request.parameters.get("resource"),
                    request.parameters.get("policy"), request.parameters.get("duration"))
                self.record_change("PRIVACY", "temporary_permission_applied",
                                   str(result["bundleID"]),
                                   previous_state={"resource": result["resource"],
                                                   "policy": result["previousPolicy"]},
                                   new_state=result, reversible=True,
                                   transaction_id=request.request_id)
                return result
            if request.operation == "revertPermissionTimeout":
                timeout_id = request.parameters.get("timeoutID")
                if not isinstance(timeout_id, int) or isinstance(timeout_id, bool) or timeout_id < 1:
                    raise IPCValidationError("INVALID_PARAMETERS", "timeoutID must be positive")
                result = self.permissions.revert(timeout_id)
                self.record_change("PRIVACY", "temporary_permission_reverted",
                                   result["bundleID"], new_state=result,
                                   reversible=False, transaction_id=request.request_id)
                return result
            raise IPCValidationError("OPERATION_NOT_APPROVED", "write operation is not approved")
        except PolicyError as error:
            raise IPCValidationError(error.code, str(error)) from error
        except ValueError as error:
            raise IPCValidationError("INVALID_PARAMETERS", str(error)) from error

    def record_change(self, component: str, action: str, target: str,
                      previous_state: Any = None, new_state: Any = None,
                      reversible: bool = False, transaction_id: str | None = None,
                      undo_operation: str | None = None,
                      undo_parameters: Any = None, result: Any = None) -> int:
        self.start()
        value = self.store.record_change(component, action, target, previous_state,
                                         new_state, reversible, transaction_id,
                                         undo_operation, undo_parameters, result)
        self.logger.log("INFO", "PACKAGE" if component == "PACKAGE" else "CORE",
                        "change journal entry", action=action, target=target,
                        reversible=reversible, transactionId=transaction_id)
        return value

    def sensor_success(self, sensor: str) -> None:
        self.start()
        self.store.update_sensor_health(sensor, SensorState.RUNNING.value, success=True)

    def sensor_failure(self, sensor: str, error: str, failed: bool = False) -> None:
        self.start()
        state = SensorState.FAILED if failed else SensorState.DEGRADED
        self.store.update_sensor_health(sensor, state.value, error=str(error)[:2048])
        self.logger.log("ERROR" if failed else "WARN", "CORE",
                        "subsystem failure", sensor=sensor, error=str(error))

    def _ipc_success(self, request_id: str, result: Any) -> dict[str, Any]:
        if not self._core_ipc_recovered:
            self.sensor_success("core_ipc")
            self._core_ipc_recovered = True
        return response(request_id, True, result=result)

    def handle_ipc(self, payload: Any, caller: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = payload.get("requestId", "invalid") if isinstance(payload, dict) else "invalid"
        try:
            request = validate_request(payload)
            if request.operation in ("restoreSnapshot", "undoChange", "applyProfile",
                                     "temporarilyActivateApp", "unfreezeApp", "emitAutomationEvent",
                                     "setAutomationRuleEnabled"):
                from zero_sky_compat.integration import CompatibilityBlocked, block_legacy_mutation
                try:
                    block_legacy_mutation(request.operation)
                except CompatibilityBlocked as error:
                    raise IPCValidationError("COMPATIBILITY_BLOCKED", str(error)) from error
            self.start()
            self.logger.log("DEBUG", "IPC", "core request",
                            requestId=request.request_id, operation=request.operation,
                            access=request.access, caller=caller or {})
            if request.operation == "getCompatibilityAdmission":
                from zero_sky_compat.integration import existing_admission
                component = request.parameters.get("component")
                action = request.parameters.get("action")
                if not isinstance(component, str) or not component or len(component) > 255 or action != "launch":
                    raise IPCValidationError("INVALID_PARAMETERS", "bounded component and supported action required")
                return self._ipc_success(request.request_id, existing_admission(component, action))
            if request.operation == "getCompatibilityDetail":
                from zero_sky_compat.integration import registry_detail
                try:
                    detail = registry_detail(request.parameters.get("registryKey"),
                                             self.paths.state_directory / "compatibility")
                except ValueError as error:
                    raise IPCValidationError("INVALID_PARAMETERS", str(error)) from error
                return self._ipc_success(request.request_id, {"component": detail})
            if request.operation == "analyzeCompatibility":
                from zero_sky_compat.integration import analyze_registry_entry
                try:
                    detail = analyze_registry_entry(
                        request.parameters.get("registryKey"),
                        self.paths.state_directory / "compatibility")
                except ValueError as error:
                    raise IPCValidationError("INVALID_PARAMETERS", str(error)) from error
                return self._ipc_success(request.request_id, {"component": detail})
            if request.operation == "getCompatibility":
                from zero_sky_compat.integration import registry_view
                return self._ipc_success(request.request_id,
                                         registry_view(self.paths.state_directory / "compatibility"))
            if request.operation in ("runToolkitSmoke", "runToolkitUAT"):
                return self._ipc_success(request.request_id,
                                         self._run_toolkit_suite(request.operation == "runToolkitUAT"))
            if request.access == "write":
                if request.operation == "publishPowerTelemetry":
                    result = self._publish_power_telemetry(request, caller)
                elif request.operation == "setTweakTargets":
                    result = self._set_tweak_targets(request, caller)
                elif request.operation == "clearTweakQuarantine":
                    result = self._clear_tweak_quarantine(request, caller)
                elif request.operation in {"restartNormally", "disableRecentTweaks",
                                         "disableSelectedTweak", "startWithoutTweaks"}:
                    result = self._queue_recovery(request, caller)
                elif request.operation in {"saveProfile", "applyProfile",
                                           "saveAutomationRule", "setAutomationRuleEnabled",
                                           "emitAutomationEvent", "freezeApp",
                                           "temporarilyActivateApp", "unfreezeApp",
                                           "setTemporaryPermission", "revertPermissionTimeout"}:
                    result = self._policy_write(request, caller)
                else:
                    result = self._snapshot_write(request, caller)
            elif request.operation == "getStatus":
                result = self.status()
            elif request.operation == "getCapabilities":
                result = {"capabilities": self.capability_payload()}
            elif request.operation == "getResearchToolkit":
                result = self._toolkit_snapshot()
            elif request.operation == "getToolkitReport":
                latest = self._toolkit_snapshot().get("uat_summary") or {}
                report = latest.get("report")
                path = Path(report) if isinstance(report, str) else None
                directory = self.paths.state_directory / "research-toolkit/reports"
                if (path is None or path.is_symlink() or not path.is_file() or
                        not path.resolve().is_relative_to(directory.resolve()) or
                        path.stat().st_size > 4 * 1024 * 1024):
                    raise IPCValidationError("REPORT_UNAVAILABLE", "No bounded toolkit report is available")
                contents = path.read_bytes()
                result = {"filename": "0sky-uat.zip",
                          "base64": base64.b64encode(contents).decode("ascii"),
                          "sha256": hashlib.sha256(contents).hexdigest()}
            elif request.operation == "getSensorHealth":
                result = {"sensors": self.store.sensor_health()}
            elif request.operation == "getControlCenterSummary":
                result = self._control_center_summary()
            elif request.operation == "getHealthTimeline":
                days = request.parameters.get("days", 1)
                if (not isinstance(days, int) or isinstance(days, bool) or
                        days not in {1, 7, 30}):
                    raise IPCValidationError("INVALID_PARAMETERS",
                                             "days must be 1, 7, or 30")
                result = self.store.health_timeline(time.time() - days * 86400)
                result["days"] = days
                result["sensors"] = self.store.sensor_health()
                result["databaseIntegrity"] = self.store.integrity()
            elif request.operation == "getRecoveryOptions":
                result = self._recovery_options()
            elif request.operation == "getRecentChanges":
                limit = request.parameters.get("limit", 50)
                if not isinstance(limit, int) or isinstance(limit, bool):
                    raise IPCValidationError("INVALID_PARAMETERS", "limit must be an integer")
                result = {"changes": self.store.recent_changes(limit)}
            elif request.operation == "getProcesses":
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 512)
                rows = self.store.latest_process_snapshot(limit)
                result = {"available": bool(rows), "processes": rows,
                          "message": None if rows else "No process sample is available yet"}
            elif request.operation == "getBatteryState":
                rows = self.store.latest_rows("battery_samples", 1)
                result = {"available": bool(rows), "sample": rows[0] if rows else None,
                          "message": None if rows else "Battery monitoring is unsupported or awaiting validated evidence"}
            elif request.operation == "getThermalState":
                rows = self.store.latest_rows("thermal_samples", 1)
                result = {"available": bool(rows), "sample": rows[0] if rows else None,
                          "message": None if rows else "Thermal monitoring is unsupported or awaiting a reviewed provider"}
            elif request.operation == "getDeviceHealth":
                result = {"metrics": self.store.latest_health_metrics(),
                          "sensors": self.store.sensor_health()}
            elif request.operation == "getTelemetryHistory":
                kind = request.parameters.get("kind")
                tables = {"process": "process_samples", "battery": "battery_samples",
                          "thermal": "thermal_samples", "health": "health_samples",
                          "network": "network_events", "privacy": "privacy_events"}
                if kind not in tables:
                    raise IPCValidationError("INVALID_PARAMETERS", "kind is not telemetry-readable")
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 1000)
                result = {"kind": kind, "samples": self.store.latest_rows(tables[kind], limit)}
            elif request.operation == "getConnections":
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 512)
                stamp = self.store.latest_timestamp("network_snapshots")
                rows = self.store.latest_network_snapshot(limit)
                result = {"available": stamp is not None, "sampledAt": stamp,
                          "connections": rows,
                          "scope": "current-observed-sockets",
                          "message": None if stamp is not None else
                          "Network observation is unsupported or awaiting its first snapshot"}
            elif request.operation == "getPrivacyEvents":
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 500)
                rows = self.store.latest_rows("privacy_events", limit)
                result = {"available": bool(rows), "events": rows,
                          "message": None if rows else
                          "Privacy observation is unsupported or no reviewed events are available"}
            elif request.operation == "getPrivacySummary":
                hours = request.parameters.get("hours", 24)
                if (not isinstance(hours, int) or isinstance(hours, bool) or
                        not 1 <= hours <= 24 * 30):
                    raise IPCValidationError("INVALID_PARAMETERS", "hours must be between 1 and 720")
                result = {"hours": hours,
                          "resources": self.store.privacy_summary(time.time() - hours * 3600)}
            elif request.operation == "getPackages":
                limit = self._bounded_integer(request.parameters.get("limit"), 200, 512)
                query = request.parameters.get("query")
                if query is not None and (not isinstance(query, str) or len(query) > 128):
                    raise IPCValidationError("INVALID_PARAMETERS", "query must be a bounded string")
                health = self.store.package_health(time.time() - 7 * 86400)
                packages = PackageInventory(self.paths).collect(limit, query, health)
                result = {"packages": packages, "authoritativeSource":
                          str(self.paths.jailbreak("/Library/dpkg/status"))}
            elif request.operation == "getPackageDetail":
                package = request.parameters.get("package")
                if not isinstance(package, str) or not PACKAGE_ID.fullmatch(package):
                    raise IPCValidationError("INVALID_PARAMETERS", "invalid package identifier")
                health = self.store.package_health(time.time() - 7 * 86400)
                detail = PackageInventory(self.paths).detail(package, health)
                result = {"available": detail is not None, "package": detail,
                          "authoritativeSource": str(self.paths.jailbreak("/Library/dpkg/status"))}
            elif request.operation == "getQuarantinedTweaks":
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 256)
                rows = PackageInventory(self.paths).quarantines(limit)
                result = {"quarantines": rows, "count": len(rows),
                          "automaticProtection": True}
            elif request.operation == "getCrashes":
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 500)
                process = request.parameters.get("process")
                if process is not None and (not isinstance(process, str) or not process or len(process) > 512):
                    raise IPCValidationError("INVALID_PARAMETERS", "process must be a bounded string")
                result = {"crashes": self.store.latest_crashes(limit, process),
                          "scope": "validated-apple-crash-metadata"}
            elif request.operation == "getConflicts":
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 500)
                result = {"conflicts": self.store.current_conflicts(limit),
                          "classificationPolicy": "evidence-based-not-all-duplicates"}
            elif request.operation == "getTweakHooks":
                limit = self._bounded_integer(request.parameters.get("limit"), 200, 1000)
                result = {"hooks": self.store.current_hooks(limit)}
            elif request.operation == "getTweakTargetApps":
                result = self._tweak_target_apps(request.parameters.get("package"))
            elif request.operation == "getRecoveryStatus":
                registry = self._runtime_registry()
                safe_mode: dict[str, Any] = {}
                last_result: dict[str, Any] | None = None
                try:
                    safe_mode = json.loads(self.paths.jailbreak(
                        "/var/lib/srd-runtime/safe-mode-overrides.json").read_text())
                except (OSError, ValueError, TypeError):
                    pass
                try:
                    value = json.loads(self.paths.jailbreak(
                        "/var/lib/srd-runtime/safe-mode.result.json").read_text())
                    last_result = value if isinstance(value, dict) else None
                except (OSError, ValueError, TypeError):
                    pass
                recovery_targets = []
                for target in registry.get("targets", {}).values() if isinstance(
                        registry.get("targets"), dict) else ():
                    if not isinstance(target, dict) or not isinstance(target.get("name"), str):
                        continue
                    packages = sorted({str(item.get("package"))
                        for item in target.get("dylibs", []) if isinstance(item, dict) and
                        PACKAGE_ID.fullmatch(str(item.get("package") or ""))})
                    recovery_targets.append({"process": target["name"],
                                             "kind": target.get("kind"),
                                             "packages": packages,
                                             "packageCount": len(packages)})
                recovery_targets.sort(key=lambda item: str(item["process"]).casefold())
                result = {"injectionPaused": self.paths.system(
                              "/var/mobile/pl/srd-runtime-paused").exists(),
                          "quarantined": registry.get("quarantined", [])
                              if isinstance(registry, dict) else [],
                          "safeMode": safe_mode,
                          "requestPending": self.paths.jailbreak(
                              "/var/lib/srd-runtime/safe-mode.request.json").exists(),
                          "lastResult": last_result,
                          "sessions": self.store.latest_safe_mode_sessions(50),
                          "episodes": self._recovery_episodes(),
                          "targets": recovery_targets,
                          "actionsAvailable": bool(registry.get("targets")),
                          "message": ("Bounded reversible recovery actions are available"
                                      if registry.get("targets") else
                                      "No exact current tweak target is available for recovery")}
            elif request.operation == "getSnapshotCapability":
                result = self.snapshots.capability()
            elif request.operation == "getSnapshotApps":
                apps = self.snapshots.installed_apps()
                result = {"applications": [{
                    "bundleID": app["bundleID"], "name": app["name"],
                    "version": app["version"],
                    "bundlePath": app["bundlePathDisplay"],
                    "containerPath": app["containerPathDisplay"]}
                    for app in apps], "count": len(apps)}
            elif request.operation == "getSnapshots":
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 500)
                bundle_id = request.parameters.get("bundleID")
                if bundle_id is not None and (not isinstance(bundle_id, str) or
                                              not bundle_id or len(bundle_id) > 255):
                    raise IPCValidationError("INVALID_PARAMETERS",
                                             "bundleID must be a bounded string")
                result = {"snapshots": self.snapshots.list(bundle_id, limit)}
            elif request.operation == "getSnapshotDetail":
                snapshot_id = self._snapshot_id(request.parameters)
                verify = request.parameters.get("verify", True)
                if not isinstance(verify, bool):
                    raise IPCValidationError("INVALID_PARAMETERS", "verify must be a boolean")
                try:
                    detail = self.snapshots.inspect(snapshot_id, verify_files=verify)
                except SnapshotError as error:
                    raise IPCValidationError(error.code, str(error)) from error
                # Do not return a potentially huge per-file manifest over IPC.
                summary = dict(detail)
                manifest = dict(summary.pop("manifest"))
                manifest.pop("snapshotFiles", None)
                manifest.pop("hashes", None)
                manifest["fileCount"] = detail["verifiedFiles"]
                summary["manifest"] = manifest
                result = {"snapshot": summary}
            elif request.operation == "getProfileCapability":
                result = self.automation.capability()
                result["freeze"] = self.freeze.capability()
                result["transactional"] = True
            elif request.operation == "getProfiles":
                result = {"profiles": self.profiles.list(),
                          "active": self.store.active_profile()}
            elif request.operation == "getProfileTransactions":
                limit = self._bounded_integer(request.parameters.get("limit"), 50, 500)
                result = {"transactions": self.store.profile_transactions(limit)}
            elif request.operation == "getAutomationRules":
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 500)
                result = {"rules": self.store.automation_rules(limit=limit)}
            elif request.operation == "getAutomationHistory":
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 500)
                result = {"runs": self.store.automation_runs(limit)}
            elif request.operation == "getFreezeCapability":
                result = self.freeze.capability()
            elif request.operation == "getFrozenApps":
                result = {"applications": self.freeze.list()}
            elif request.operation == "getStorageIntelligence":
                result = self.storage.scan()
            elif request.operation == "getNotificationAnalytics":
                now = time.time()
                hourly = self.store.notification_summary(now - 3600, 200)
                daily = self.store.notification_summary(now - 86400, 200)
                hour_by_app = {row["bundle_id"]: row for row in hourly}
                result = {"available": bool(hourly or daily),
                          "notificationsPerHour": sum(int(row["count"]) for row in hourly),
                          "notificationsPerDay": sum(int(row["count"]) for row in daily),
                          "mostFrequentApps": daily,
                          "quietAppSuggestions": [{
                              "bundleID": row["bundle_id"], "dayCount": row["count"],
                              "hourCount": hour_by_app.get(row["bundle_id"], {}).get("count", 0),
                              "classification": "local-frequency-heuristic"}
                              for row in daily if int(row["count"]) >= 30 or
                              int(hour_by_app.get(row["bundle_id"], {}).get("count", 0)) >= 8],
                          "contentStored": False,
                          "message": None if (hourly or daily) else
                          "Notification metadata is unsupported or no reviewed events are available"}
            elif request.operation == "getNotificationEvents":
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 500)
                bundle_id = request.parameters.get("bundleID")
                if bundle_id is not None and (not isinstance(bundle_id, str) or
                                              not bundle_id or len(bundle_id) > 255):
                    raise IPCValidationError("INVALID_PARAMETERS", "bundleID must be bounded")
                result = {"events": self.store.notification_events(limit, bundle_id),
                          "contentStored": False}
            elif request.operation == "getPermissionTimeoutCapability":
                result = self.permissions.capability()
            elif request.operation == "getPermissionTimeouts":
                active = request.parameters.get("activeOnly", False)
                if not isinstance(active, bool):
                    raise IPCValidationError("INVALID_PARAMETERS", "activeOnly must be boolean")
                limit = self._bounded_integer(request.parameters.get("limit"), 100, 500)
                result = {"timeouts": self.store.permission_timeouts(active, limit),
                          "capability": self.permissions.capability()}
            else:  # Defensive: validation already rejects unknown operations.
                raise IPCValidationError("OPERATION_NOT_APPROVED", "operation is not approved")
            return self._ipc_success(request.request_id, result)
        except IPCValidationError as error:
            operation = payload.get("operation") if isinstance(payload, dict) else None
            self.logger.log("WARN", "IPC", "core request rejected",
                            requestId=str(request_id)[:128], operation=operation,
                            errorCode=error.code, errorMessage=str(error)[:512])
            return response(str(request_id)[:128], False, error_code=error.code,
                            error_message=str(error))
        except Exception as error:
            self._core_ipc_recovered = False
            self.sensor_failure("core_ipc", repr(error))
            return response(str(request_id)[:128], False, error_code="INTERNAL_ERROR",
                            error_message="The core service could not complete the request")
