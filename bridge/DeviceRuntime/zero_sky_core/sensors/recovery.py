"""Package, crash and tweak-conflict evidence for 0-Sky Phase 4.

The installed dpkg database and the existing runtime registry remain the source
of truth.  This module builds bounded views and crash/conflict evidence; it does
not duplicate package state, hook processes, or disable packages on its own.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import plistlib
import re
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from ..health import SensorState
from ..paths import RootlessPaths
from .telemetry import SensorResult

PACKAGE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:-]{0,254}$")
MAX_STATUS_BYTES = 16 * 1024 * 1024
MAX_PACKAGES = 4096
MAX_FILES_PER_PACKAGE = 8192
MAX_CRASH_FILES = 128
MAX_CRASH_BYTES = 4 * 1024 * 1024
MAX_HOOKS = 2048


def _read_json(path: Path, default: Any) -> Any:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value
    except (OSError, ValueError, TypeError):
        return default


def _parse_control(path: Path) -> dict[str, dict[str, str]]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_STATUS_BYTES:
            return {}
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    result: dict[str, dict[str, str]] = {}
    for stanza in raw.split("\n\n")[:MAX_PACKAGES * 2]:
        fields: dict[str, str] = {}
        current: str | None = None
        for line in stanza.splitlines()[:256]:
            if line[:1].isspace() and current:
                fields[current] = (fields[current] + " " + line.strip())[:8192]
            elif ":" in line:
                key, value = line.split(":", 1)
                if key and len(key) <= 64:
                    current = key
                    fields[key] = value.strip()[:8192]
        package = fields.get("Package")
        if (package and PACKAGE_ID.fullmatch(package) and
                fields.get("Status") == "install ok installed"):
            result[package.split(":", 1)[0]] = fields
            if len(result) >= MAX_PACKAGES:
                break
    return result


def _dependency_groups(raw: str | None) -> list[list[str]]:
    groups: list[list[str]] = []
    if not raw:
        return groups
    for group in raw.split(",")[:256]:
        alternatives: list[str] = []
        for item in group.split("|")[:16]:
            name = re.split(r"\s|\(", item.strip(), 1)[0].split(":", 1)[0]
            if PACKAGE_ID.fullmatch(name) and name not in alternatives:
                alternatives.append(name)
        if alternatives:
            groups.append(alternatives)
    return groups


class PackageInventory:
    """Build an on-demand view from authoritative dpkg and runtime files."""
    def __init__(self, paths: RootlessPaths) -> None:
        self.paths = paths
        self.status = paths.jailbreak("/Library/dpkg/status")
        self.info = paths.jailbreak("/Library/dpkg/info")
        self.registry = paths.jailbreak("/var/lib/srd-runtime/registry.json")
        self.safe_mode = paths.jailbreak("/var/lib/srd-runtime/safe-mode-overrides.json")
        self.pause = paths.system("/var/mobile/pl/srd-runtime-paused")

    def _files(self, package: str) -> tuple[list[str], bool, float | None]:
        candidates = (self.info / f"{package}.list", self.info / f"{package}:iphoneos-arm.list",
                      self.info / f"{package}:iphoneos-arm64.list")
        listing = next((p for p in candidates if p.is_file()), None)
        if listing is None:
            # Architecture suffixes vary; never accept an unvalidated glob key.
            listing = next(iter(sorted(self.info.glob(package + ":*.list"))), None)
        if listing is None:
            return [], False, None
        try:
            lines = [x.rstrip("/") or "/" for x in
                     listing.read_text(errors="replace").splitlines()
                     if x.startswith("/")]
            return lines[:MAX_FILES_PER_PACKAGE], len(lines) > MAX_FILES_PER_PACKAGE, listing.stat().st_mtime
        except OSError:
            return [], False, None

    @staticmethod
    def _registry_maps(registry: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]],
                                                           dict[str, list[dict[str, Any]]]]:
        tweaks: dict[str, list[dict[str, Any]]] = {}
        quarantined: dict[str, list[dict[str, Any]]] = {}
        for item in registry.get("tweaks", [])[:MAX_HOOKS]:
            if isinstance(item, dict) and PACKAGE_ID.fullmatch(str(item.get("package") or "")):
                tweaks.setdefault(item["package"], []).append(item)
        for item in registry.get("quarantined", [])[:MAX_HOOKS]:
            if isinstance(item, dict) and PACKAGE_ID.fullmatch(str(item.get("package") or "")):
                quarantined.setdefault(item["package"], []).append(item)
        return tweaks, quarantined

    def collect(self, limit: int = 512, query: str | None = None,
                health: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        packages = _parse_control(self.status)
        registry = _read_json(self.registry, {})
        if not isinstance(registry, dict):
            registry = {}
        tweaks, quarantined = self._registry_maps(registry)
        safe_mode = _read_json(self.safe_mode, {})
        safe_targets = safe_mode.get("targets", {}) if isinstance(safe_mode, dict) else {}
        safe_packages: set[str] = set()
        all_disabled_targets: set[str] = set()
        if isinstance(safe_targets, dict):
            for target, entry in safe_targets.items():
                if not isinstance(target, str) or not isinstance(entry, dict):
                    continue
                if entry.get("all"):
                    all_disabled_targets.add(target)
                for package in entry.get("packages", [])[:16] if isinstance(entry.get("packages"), list) else ():
                    if isinstance(package, str) and PACKAGE_ID.fullmatch(package):
                        safe_packages.add(package)
        target_packages: dict[str, set[str]] = {}
        for target in registry.get("targets", {}).values() if isinstance(registry.get("targets"), dict) else ():
            if not isinstance(target, dict) or not isinstance(target.get("name"), str):
                continue
            target_packages[target["name"]] = {
                str(item.get("package")) for item in target.get("dylibs", [])
                if isinstance(item, dict) and PACKAGE_ID.fullmatch(str(item.get("package") or ""))
            }
        for target in all_disabled_targets:
            safe_packages.update(target_packages.get(target, ()))
        installed = set(packages)
        reverse: dict[str, set[str]] = {}
        dependency_map: dict[str, list[list[str]]] = {}
        for package, fields in packages.items():
            groups = _dependency_groups(fields.get("Depends"))
            dependency_map[package] = groups
            for alternatives in groups:
                for dependency in alternatives:
                    reverse.setdefault(dependency, set()).add(package)
        needle = (query or "").strip().casefold()[:128]
        rows: list[dict[str, Any]] = []
        for package in sorted(packages, key=str.casefold):
            fields = packages[package]
            title = fields.get("Name") or package
            if needle and needle not in package.casefold() and needle not in title.casefold():
                continue
            files, truncated, installed_at = self._files(package)
            services = [x for x in files if ("/LaunchDaemons/" in x or
                        "/LaunchAgents/" in x) and x.endswith(".plist")][:128]
            groups = dependency_map.get(package, [])
            missing = [group for group in groups if not any(x in installed for x in group)]
            package_health = (health or {}).get(package, {})
            conflicts = int(package_health.get("conflicts") or 0)
            crashes = int(package_health.get("crashes") or 0)
            disabled = bool(quarantined.get(package)) and len(quarantined[package]) >= len(tweaks.get(package, []))
            if package in safe_packages:
                disabled = True
            if self.pause.exists() and tweaks.get(package):
                disabled = True
            status = ("Crashing" if crashes else "Conflict" if conflicts else
                      "Disabled" if disabled else "Warning" if missing else "Healthy")
            rows.append({"package": package, "name": title[:256],
                         "version": fields.get("Version", "")[:256],
                         "architecture": fields.get("Architecture", "")[:128],
                         "description": fields.get("Description", "")[:1024],
                         "dependencies": groups, "missingDependencies": missing,
                         "reverseDependencies": sorted(reverse.get(package, ()))[:512],
                         "fileCount": len(files), "filesTruncated": truncated,
                         "serviceCount": len(services), "tweakCount": len(tweaks.get(package, [])),
                         "quarantinedCount": len(quarantined.get(package, [])),
                         "installedEvidenceTimestamp": installed_at,
                         "health": status, "recentCrashCount": crashes,
                         "conflictCount": conflicts})
            if len(rows) >= min(MAX_PACKAGES, max(1, int(limit))):
                break
        return rows

    def detail(self, package: str, health: dict[str, dict[str, Any]] | None = None) -> dict[str, Any] | None:
        if not isinstance(package, str) or not PACKAGE_ID.fullmatch(package):
            raise ValueError("invalid package identifier")
        fields = _parse_control(self.status).get(package)
        if fields is None:
            return None
        rows = self.collect(MAX_PACKAGES, health=health)
        summary = next((x for x in rows if x["package"] == package), None)
        files, truncated, _ = self._files(package)
        registry = _read_json(self.registry, {})
        tweaks, quarantined = self._registry_maps(registry if isinstance(registry, dict) else {})
        services: list[dict[str, Any]] = []
        for raw in files:
            if not (("/LaunchDaemons/" in raw or "/LaunchAgents/" in raw) and raw.endswith(".plist")):
                continue
            path = self.paths.system(raw)
            label = None
            try:
                value = plistlib.loads(path.read_bytes())
                label = value.get("Label") if isinstance(value, dict) else None
            except (OSError, ValueError, plistlib.InvalidFileException):
                pass
            services.append({"path": raw, "label": str(label)[:256] if label else None})
        return {**(summary or {"package": package}), "control": {
                    key: fields[key] for key in ("Maintainer", "Section", "Priority", "Homepage")
                    if key in fields},
                "files": files[:2048], "filesTruncated": truncated or len(files) > 2048,
                "services": services[:128], "tweaks": tweaks.get(package, [])[:128],
                "quarantine": quarantined.get(package, [])[:128]}


def _timestamp(value: Any, fallback: float) -> float:
    if not isinstance(value, str):
        return fallback
    try:
        return dt.datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f %z").timestamp()
    except ValueError:
        return fallback


class CrashSensor:
    """Parse bounded Apple `.ips` metadata without copying crash contents."""
    def __init__(self, paths: RootlessPaths) -> None:
        self.paths = paths
        self.roots = (paths.system("/var/mobile/Library/Logs/CrashReporter"),
                      paths.system("/var/mobile/Library/Logs/DiagnosticLogs"))
        self.registry = paths.jailbreak("/var/lib/srd-runtime/registry.json")
        self._seen: set[tuple[str, int, int]] = set()

    def collect(self) -> SensorResult:
        roots = [x for x in self.roots if x.is_dir()]
        if not roots:
            return SensorResult(SensorState.UNSUPPORTED, reason="No readable crash source")
        candidates: list[tuple[int, int, Path]] = []
        for root in roots:
            try:
                resolved_root = root.resolve()
                for path in root.rglob("*.ips"):
                    try:
                        resolved = path.resolve()
                        if resolved_root not in resolved.parents:
                            continue
                        stat = resolved.stat()
                        if 1 < stat.st_size <= MAX_CRASH_BYTES:
                            candidates.append((stat.st_mtime_ns, stat.st_size, resolved))
                    except OSError:
                        continue
            except OSError:
                continue
        candidates.sort(reverse=True)
        registry = _read_json(self.registry, {})
        targets = registry.get("targets", {}) if isinstance(registry, dict) else {}
        rows: list[dict[str, Any]] = []
        rejected = 0
        for mtime_ns, size, path in candidates[:MAX_CRASH_FILES]:
            identity = (str(path), mtime_ns, size)
            if identity in self._seen:
                continue
            self._seen.add(identity)
            if len(self._seen) > MAX_CRASH_FILES * 4:
                # Keep memory bounded; the newest candidate identities are
                # re-established naturally on the next pass.
                self._seen = set(sorted(self._seen, key=lambda x: x[1], reverse=True)
                                 [:MAX_CRASH_FILES * 2])
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
                line, _, body_raw = raw.partition("\n")
                header = json.loads(line)
                if not isinstance(header, dict):
                    raise ValueError("header is not an object")
                bug_type = str(header.get("bug_type") or "")[:32]
                if bug_type != "309":
                    continue  # Resource and analytics reports are not crashes.
                body = json.loads(body_raw) if body_raw.lstrip().startswith("{") else {}
                if not isinstance(body, dict):
                    body = {}
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                rejected += 1
                continue
            process = str(body.get("procName") or header.get("app_name") or header.get("name") or "unknown")[:256]
            code_id = str(body.get("codeSigningID") or "")[:256]
            stamp = _timestamp(body.get("captureTime") or header.get("timestamp"), mtime_ns / 1e9)
            incident = str(body.get("incident") or header.get("incident_id") or "")[:128]
            exception = body.get("exception") if isinstance(body.get("exception"), dict) else {}
            termination = body.get("termination") if isinstance(body.get("termination"), dict) else {}
            configured: list[dict[str, Any]] = []
            for target in targets.values() if isinstance(targets, dict) else ():
                if not isinstance(target, dict):
                    continue
                target_name = str(target.get("name") or "")
                target_path = str(target.get("path") or "")
                if (target_name == code_id or Path(target_path).name == process or
                        target_name.rsplit(".", 1)[-1].casefold() == process.casefold()):
                    configured.extend(x for x in target.get("dylibs", []) if isinstance(x, dict))
            used: list[str] = []
            names = {Path(str(x.get("path") or "")).name for x in configured}
            for image in body.get("usedImages", [])[:4096] if isinstance(body.get("usedImages"), list) else ():
                if not isinstance(image, dict):
                    continue
                image_path = str(image.get("path") or image.get("name") or "")[:4096]
                if image_path.startswith("/var/jb/") or Path(image_path).name in names:
                    used.append(image_path)
                    if len(used) >= 128:
                        break
            providers = sorted({str(x.get("package")) for x in configured
                                if PACKAGE_ID.fullmatch(str(x.get("package") or ""))})
            fingerprint = hashlib.sha256(
                f"{path}\0{mtime_ns}\0{size}\0{incident}".encode()).hexdigest()
            rows.append({"fingerprint": fingerprint, "timestamp": stamp,
                         "process": process, "bundle_id": code_id or None,
                         "report_path": str(path), "kind": "crash",
                         "incident_id": incident or None,
                         "signal": str(exception.get("signal") or "")[:128] or None,
                         "reason": str(termination.get("indicator") or
                                       exception.get("type") or "")[:512] or None,
                         "package_candidates": providers,
                         "evidence": {"bugType": bug_type,
                                      "configuredTweaks": configured[:128],
                                      "observedTweakImages": used,
                                      "attribution": ("observed-image" if used else
                                                      "configured-for-process-not-proof"),
                                      "consecutiveCrashCount": body.get("consecutiveCrashCount"),
                                      "faultingThread": body.get("faultingThread")}})
        return SensorResult(SensorState.RUNNING, tuple(rows),
                            reason="Apple crash metadata is observable; contributor ranking is evidence-based",
                            evidence=tuple(str(x) for x in roots) + (f"rejected={rejected}",))


class ConflictSensor:
    """Classify only conflicts supported by registry/provider evidence."""
    def __init__(self, paths: RootlessPaths, wall_clock: Callable[[], float] = time.time) -> None:
        self.paths, self.wall_clock = paths, wall_clock
        self.registry = paths.jailbreak("/var/lib/srd-runtime/registry.json")
        self.provider = paths.provider_directory / "tweak-hooks.json"

    def _provider_hooks(self) -> list[dict[str, Any]]:
        try:
            stat = self.provider.stat()
        except FileNotFoundError:
            return []
        expected_uid = 0 if self.paths.root == Path("/") else os.geteuid()
        if stat.st_uid != expected_uid or stat.st_mode & 0o022 or not 1 < stat.st_size <= 512 * 1024:
            raise ValueError("hook provider evidence has unsafe ownership, permissions, or size")
        payload = json.loads(self.provider.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("hooks"), list):
            raise ValueError("hook provider schema is invalid")
        stamp = payload.get("timestamp")
        if (not isinstance(stamp, (int, float)) or isinstance(stamp, bool) or
                not -30 <= self.wall_clock() - float(stamp) <= 600):
            raise ValueError("hook provider evidence is stale")
        result: list[dict[str, Any]] = []
        for item in payload["hooks"][:MAX_HOOKS]:
            if not isinstance(item, dict):
                continue
            process, package = item.get("process"), item.get("package")
            symbol = item.get("selector") or item.get("symbol")
            mechanism = item.get("mechanism")
            disposition = item.get("disposition", "unknown")
            if (not isinstance(process, str) or not process or len(process) > 512 or
                    not isinstance(package, str) or not PACKAGE_ID.fullmatch(package) or
                    not isinstance(symbol, str) or not symbol or len(symbol) > 512 or
                    mechanism not in ("method-hook", "interpose", "symbol-hook") or
                    disposition not in ("observe", "around", "replace", "unknown")):
                continue
            row = {"kind": "hook", "process": process, "package": package,
                   "image": str(item.get("image") or "")[:4096] or None,
                   "library": str(item.get("library") or "")[:4096] or None,
                   "class_name": str(item.get("class") or "")[:512] or None,
                   "symbol": symbol, "implementation": str(item.get("implementation") or "")[:512] or None,
                   "mechanism": mechanism, "disposition": disposition,
                   "loaded": bool(item.get("loaded")),
                   "evidence": {"provider": str(payload.get("provider") or "reviewed-json")[:128]}}
            row["fingerprint"] = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
            result.append(row)
        return result

    def collect(self) -> SensorResult:
        registry = _read_json(self.registry, {})
        if not isinstance(registry, dict):
            return SensorResult(SensorState.UNSUPPORTED,
                                reason="The existing runtime registry is unavailable")
        samples: list[dict[str, Any]] = []
        targets = registry.get("targets", {})
        if isinstance(targets, dict):
            for target in targets.values():
                if not isinstance(target, dict):
                    continue
                dylibs = [x for x in target.get("dylibs", []) if isinstance(x, dict)]
                providers = sorted({str(x.get("package")) for x in dylibs
                                    if PACKAGE_ID.fullmatch(str(x.get("package") or ""))})
                if len(providers) < 2:
                    continue
                evidence = {"type": "shared-process-filter", "providers": providers,
                            "dylibs": [x.get("path") for x in dylibs[:128]],
                            "note": "Shared process targeting alone is not proof of a hook conflict"}
                row = {"kind": "conflict", "classification": "informational",
                       "process": str(target.get("name") or target.get("path") or "")[:512],
                       "target": "process-filter", "providers": providers,
                       "evidence": evidence}
                row["fingerprint"] = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
                samples.append(row)
        for item in registry.get("quarantined", [])[:MAX_HOOKS]:
            if not isinstance(item, dict) or not PACKAGE_ID.fullmatch(str(item.get("package") or "")):
                continue
            row = {"kind": "conflict", "classification": "probable conflict",
                   "process": str(item.get("target") or "")[:512],
                   "target": str(item.get("dylib") or "")[:4096],
                   "providers": [item["package"]],
                   "evidence": {"type": "target-terminated-during-injection",
                                "reason": item.get("reason"), "sha256": item.get("sha256"),
                                "time": item.get("time")}}
            row["fingerprint"] = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
            samples.append(row)
        hooks = self._provider_hooks()
        samples.extend(hooks)
        grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for hook in hooks:
            grouped.setdefault((hook["process"], hook.get("class_name") or "", hook["symbol"]), []).append(hook)
        for (process, class_name, symbol), items in grouped.items():
            providers = sorted({x["package"] for x in items})
            if len(providers) < 2:
                continue
            mutating = [x for x in items if x["disposition"] in ("around", "replace")]
            classification = ("probable conflict" if len(mutating) >= 2 and all(x["loaded"] for x in mutating)
                              else "possible conflict" if mutating else "informational")
            row = {"kind": "conflict", "classification": classification,
                   "process": process, "target": f"{class_name}:{symbol}" if class_name else symbol,
                   "providers": providers,
                   "evidence": {"type": "same-hook-target", "hooks": items,
                                "note": "Classification uses reviewed hook evidence, not filenames"}}
            row["fingerprint"] = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
            samples.append(row)
        return SensorResult(SensorState.RUNNING, tuple(samples),
                            reason=("Reviewed hook evidence and runtime registry were analyzed" if hooks else
                                    "Runtime filters/quarantine were analyzed; selector-level provider is absent"),
                            evidence=(str(self.registry),) + ((str(self.provider),) if hooks else ()))
