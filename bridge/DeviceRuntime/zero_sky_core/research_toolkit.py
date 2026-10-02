"""Canonical source catalog and evidence-gated Security Research Toolkit model."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


CATALOG = Path(__file__).with_name("research_toolkit_manifest.json")
TRUST = frozenset({"OFFICIAL", "VERIFIED_COMMUNITY", "LOCAL_0SKY", "UNVERIFIED", "BLOCKED"})
COMPATIBILITY = frozenset({
    "UNKNOWN", "ANALYZING", "NATIVE_COMPATIBLE", "ADAPTATION_REQUIRED",
    "ADAPTING", "BUILD_REQUIRED", "TESTING", "COMPATIBLE",
    "COMPATIBLE_WITH_ADAPTER", "PARTIALLY_COMPATIBLE",
    "BLOCKED_BY_DEPENDENCY", "BLOCKED_BY_PLATFORM",
    "BLOCKED_BY_ENTITLEMENT", "BLOCKED_BY_ARCHITECTURE",
    "BROKEN_UPSTREAM", "UNSAFE_TO_ADAPT",
})
# Version-one manifests are accepted during migration, but live evaluation
# always returns a v2 state.
LEGACY_COMPATIBILITY = frozenset({"COMPATIBLE_WITH_WORKAROUND", "DEGRADED",
                                  "UNVERIFIED", "INCOMPATIBLE", "BLOCKED"})
RESULTS = frozenset({"PASS", "FAIL", "DEGRADED", "SKIP", "BLOCKED"})
CATEGORIES = frozenset({"Apps/Security Research", "Tweaks/Security Research",
                        "Research Tools/Instrumentation", "Research Tools/Command Line",
                        "Host Security Tools"})
KINDS = frozenset({"APP", "TWEAK", "DEPENDENCY", "FRAMEWORK", "RUNTIME",
                   "LIBRARY", "INSTRUMENTATION", "CLI", "HOST_TOOL"})
SCOPES = frozenset({"DEVICE", "HOST", "DEVICE_AND_HOST"})
REQUIRED_FIELDS = frozenset({"id", "display_name", "category", "type", "scope",
    "upstream_project", "package_repository", "package_identifier", "release_channel",
    "architectures", "root_models", "minimum_ios", "maximum_tested_ios",
    "dependencies", "conflicts", "license", "sha256", "signature_state",
    "last_checked", "trust_state", "compatibility_state", "package_source_trust",
    "management", "actions", "runtime_tests", "declared_supported",
    "zero_sky_verified", "tested_os_versions"})
ID = re.compile(r"[a-z][a-z0-9_]{1,63}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
IOS_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,2}\Z")


class ManifestError(ValueError):
    pass


def _https_url(value: str | None, field: str) -> None:
    if value is None:
        return
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.fragment):
        raise ManifestError(field + " must be an HTTPS project or repository URL")


def load_catalog(path: Path = CATALOG) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024:
        raise ManifestError("toolkit catalog is absent or unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ManifestError("unsupported toolkit catalog schema")
    rows = value.get("components")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 128:
        raise ManifestError("toolkit catalog component count is invalid")
    seen = set()
    identity_owners: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or REQUIRED_FIELDS - set(row):
            raise ManifestError("toolkit component is missing required source metadata")
        name = row["id"]
        if not isinstance(name, str) or not ID.fullmatch(name) or name in seen:
            raise ManifestError("toolkit component ID is invalid or duplicated")
        seen.add(name)
        for field in ("package_ids", "bundle_ids"):
            identifiers = row.get(field, [])
            if not isinstance(identifiers, list):
                raise ManifestError("invalid toolkit package identity list: " + name)
            for identifier in identifiers:
                if (not isinstance(identifier, str) or
                        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]{1,199}", identifier)):
                    raise ManifestError("invalid toolkit package identity: " + name)
                key = identifier.lower()
                if key in identity_owners and identity_owners[key] != name:
                    raise ManifestError("duplicate toolkit package identity: " + identifier)
                identity_owners[key] = name
        if (row["category"] not in CATEGORIES or row["type"] not in KINDS or
                row["scope"] not in SCOPES):
            raise ManifestError("toolkit classification is invalid: " + name)
        if row["trust_state"] not in TRUST or row["package_source_trust"] not in TRUST:
            raise ManifestError("toolkit source trust is invalid: " + name)
        if row["compatibility_state"] not in COMPATIBILITY | LEGACY_COMPATIBILITY:
            raise ManifestError("toolkit compatibility state is invalid: " + name)
        _https_url(row["upstream_project"], "upstream_project")
        _https_url(row["package_repository"], "package_repository")
        _https_url(row.get("source_mirror"), "source_mirror")
        source_git = row.get("source_git")
        if source_git is not None and source_git != "git://git.saurik.com/ldid.git":
            raise ManifestError("unapproved Git transport source: " + name)
        if source_git is not None and name != "ldid":
            raise ManifestError("Git transport source belongs to a different component: " + name)
        git_revision = row.get("source_git_revision")
        if git_revision is not None and (source_git is None or
                                         not isinstance(git_revision, str) or
                                         not re.fullmatch(r"[0-9a-f]{40}", git_revision)):
            raise ManifestError("invalid Git source revision: " + name)
        source_revision = row.get("source_revision")
        if source_revision is not None and (not isinstance(source_revision, str) or
                                            not re.fullmatch(r"[0-9a-f]{40}", source_revision)):
            raise ManifestError("invalid source revision: " + name)
        source_release = row.get("source_release")
        if source_release is not None and (not isinstance(source_release, str) or
                                           not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", source_release)):
            raise ManifestError("invalid source release: " + name)
        adaptation_patch = row.get("adaptation_patch")
        adaptation_hash = row.get("adaptation_patch_sha256")
        if adaptation_patch is not None and (not isinstance(adaptation_patch, str) or
                                             not re.fullmatch(r"tools/patches/[A-Za-z0-9_.-]+\.patch", adaptation_patch) or
                                             not isinstance(adaptation_hash, str) or
                                             not SHA256.fullmatch(adaptation_hash) or
                                             row["trust_state"] != "LOCAL_0SKY"):
            raise ManifestError("invalid 0-Sky adaptation provenance: " + name)
        revision = row.get("source_mirror_revision")
        if revision is not None and (not isinstance(revision, str) or
                                     not re.fullmatch(r"[0-9a-f]{40}", revision) or
                                     row.get("source_mirror") is None):
            raise ManifestError("invalid source mirror revision: " + name)
        if row["sha256"] is not None and (not isinstance(row["sha256"], str) or
                                            not SHA256.fullmatch(row["sha256"])):
            raise ManifestError("invalid artifact hash: " + name)
        variants = row.get("adapted_variants", [])
        if not isinstance(variants, list) or len(variants) > 4:
            raise ManifestError("invalid adapted variant list: " + name)
        for variant in variants:
            if (row["type"] != "TWEAK" or not isinstance(variant, dict) or
                    set(variant) != {"package_version", "dylib_path", "dylib_sha256",
                                     "verified_targets", "receipt_path", "target_process"} or
                    not isinstance(variant["package_version"], str) or
                    not re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]{0,127}", variant["package_version"]) or
                    not isinstance(variant["dylib_path"], str) or
                    not re.fullmatch(r"/Library/MobileSubstrate/DynamicLibraries/[A-Za-z0-9_.-]+\.dylib",
                                     variant["dylib_path"]) or
                    not isinstance(variant["dylib_sha256"], str) or
                    not SHA256.fullmatch(variant["dylib_sha256"]) or
                    not isinstance(variant["verified_targets"], list) or
                    not 1 <= len(variant["verified_targets"]) <= 8 or
                    any(not isinstance(target, dict) or
                        set(target) != {"model", "ios_build"} or
                        not isinstance(target["model"], str) or
                        not re.fullmatch(r"iPhone[0-9]{1,2},[0-9]{1,2}", target["model"]) or
                        not isinstance(target["ios_build"], str) or
                        not re.fullmatch(r"[0-9]{2}[A-Z][A-Za-z0-9]{2,15}", target["ios_build"])
                        for target in variant["verified_targets"]) or
                    variant["receipt_path"] !=
                    "/var/mobile/Library/Preferences/com.0sky." + name + "-uat.plist" or
                    variant["target_process"] != "SpringBoard"):
                raise ManifestError("invalid adapted variant provenance: " + name)
        for field in ("minimum_ios", "maximum_ios", "maximum_tested_ios"):
            version = row.get(field)
            if version is not None and (not isinstance(version, str) or
                                        not IOS_VERSION.fullmatch(version)):
                raise ManifestError("invalid " + field + ": " + name)
        if (row.get("minimum_ios") and row.get("maximum_ios") and
                _ios_tuple(row["minimum_ios"]) > _ios_tuple(row["maximum_ios"])):
            raise ManifestError("inverted declared OS range: " + name)
        if not isinstance(row["dependencies"], list) or not isinstance(row["conflicts"], list):
            raise ManifestError("invalid dependency metadata: " + name)
        if row["type"] == "APP" and row["category"] != "Apps/Security Research":
            raise ManifestError("launchable app is in the wrong section: " + name)
        if row["type"] in {"DEPENDENCY", "FRAMEWORK", "RUNTIME"} and row["category"] == "Apps/Security Research":
            raise ManifestError("runtime component is misclassified as an app: " + name)
        if name == "objection" and (row["scope"] != "HOST" or row["type"] != "HOST_TOOL"):
            raise ManifestError("Objection must be a host tool")
    for row in rows:
        missing = set(row["dependencies"]) - seen
        if missing:
            raise ManifestError("unknown toolkit dependency: " + row["id"] + ": " + ",".join(sorted(missing)))
    dependency_order(rows)
    return value


def dependency_order(rows: list[dict]) -> list[str]:
    graph = {row["id"]: list(row["dependencies"]) for row in rows}
    state: dict[str, int] = {}
    ordered: list[str] = []

    def visit(component: str) -> None:
        if state.get(component) == 1:
            raise ManifestError("circular toolkit dependency: " + component)
        if state.get(component) == 2:
            return
        state[component] = 1
        for dependency in graph[component]:
            if dependency not in graph:
                raise ManifestError("missing toolkit dependency: " + dependency)
            visit(dependency)
        state[component] = 2
        ordered.append(component)

    for component in graph:
        visit(component)
    return ordered


def verify_artifact(path: Path, expected_sha256: str | None) -> dict:
    """An upstream URL never verifies local bytes; a pinned hash does."""
    if expected_sha256 is None:
        return {"result": "UNVERIFIED", "reason": "No reviewed artifact hash is pinned"}
    if not SHA256.fullmatch(expected_sha256):
        raise ManifestError("invalid pinned artifact hash")
    if path.is_symlink() or not path.is_file():
        return {"result": "BLOCKED", "reason": "Artifact is absent or a symbolic link"}
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    observed = digest.hexdigest()
    return {"result": "PASS" if observed == expected_sha256 else "BLOCKED",
            "reason": "SHA-256 matches reviewed provenance" if observed == expected_sha256
                      else "Artifact SHA-256 differs from reviewed provenance",
            "sha256": observed}


def _ios_tuple(value: str) -> tuple[int, int, int]:
    parts = [int(part) for part in value.split(".")]
    return tuple((parts + [0, 0])[:3])


def compatibility_for(row: dict, *, ios_version: str, architecture: str,
                      root_model: str, runtime_evidence: dict | None = None) -> dict:
    """Declared support is never silently upgraded to iOS 27 verification."""
    if row["scope"] == "HOST":
        return {"result": "NATIVE_COMPATIBLE", "reason":
                "Host tool has no device OS constraint; runtime validation is still required"}
    if architecture == "unknown":
        return {"result": "UNKNOWN", "reason": "CPU architecture could not be verified on this device"}
    if architecture not in ("arm64", "arm64e"):
        return {"result": "BLOCKED_BY_ARCHITECTURE", "reason":
                "Measured CPU architecture is unsupported: " + architecture}
    available_slices = {architecture} | ({"arm64"} if architecture == "arm64e" else set())
    if not available_slices.intersection(row["architectures"]):
        return {"result": "ADAPTATION_REQUIRED", "reason":
                "No declared CPU slice for " + architecture + "; evaluate a source rebuild"}
    if root_model not in row["root_models"]:
        return {"result": "ADAPTATION_REQUIRED", "reason":
                "Package layout targets a different bootstrap model; evaluate the 0-Sky filesystem adapter"}
    if not IOS_VERSION.fullmatch(ios_version):
        return {"result": "UNKNOWN", "reason": "Device OS version is unavailable"}
    minimum = row.get("minimum_ios")
    maximum = row.get("maximum_ios")
    if minimum and _ios_tuple(ios_version) < _ios_tuple(minimum):
        return {"result": "BLOCKED_BY_PLATFORM", "reason":
                "Upstream declares a minimum iOS version of " + minimum}
    if maximum and _ios_tuple(ios_version) > _ios_tuple(maximum):
        return {"result": "ADAPTATION_REQUIRED", "reason":
                "Upstream tested range ends at iOS " + maximum +
                "; analyze APIs and rebuild for iOS " + ios_version}
    if ios_version in row["zero_sky_verified"]:
        return {"result": "COMPATIBLE", "reason": "Exact OS build has 0-Sky validation evidence"}
    evidence = runtime_evidence or {}
    if evidence.get("os_version") == ios_version and evidence.get("result") == "PASS":
        return {"result": "COMPATIBLE_WITH_ADAPTER" if evidence.get("adapted") else "COMPATIBLE",
                "reason": "Exact device and OS runtime validation passed"}
    return {"result": "UNKNOWN", "reason":
            "No 0-Sky runtime evidence exists for this artifact and iOS " + ios_version}


def resolve_dependencies(row: dict, observations: dict[str, dict]) -> dict:
    missing = [name for name in row["dependencies"]
               if observations.get(name, {}).get("installation") != "INSTALLED"]
    conflicts = [name for name in row["conflicts"]
                 if observations.get(name, {}).get("installation") == "INSTALLED"]
    return {"result": "BLOCKED" if missing or conflicts else "PASS",
            "missing": missing, "conflicts": conflicts}


STAGES = ("DISCOVER", "SOURCE_VERIFIED", "COMPATIBILITY_CHECKED",
          "DEPENDENCIES_RESOLVED", "INSTALLED", "CONFIGURED", "RUNTIME_VERIFIED",
          "SMOKE_TESTED", "UAT_VERIFIED", "READY")


def transition(current: str, following: str) -> str:
    if current not in STAGES or following not in STAGES or STAGES.index(following) != STAGES.index(current) + 1:
        raise ValueError("illegal toolkit lifecycle transition: " + current + " -> " + following)
    return following


def classify(row: dict, observation: dict, dependencies: dict) -> dict:
    """Show the first unsatisfied lifecycle stage and retain independent facets."""
    source = observation.get("source", "UNVERIFIED")
    compatibility = observation.get("compatibility", "UNKNOWN")
    installation = observation.get("installation", "NOT_INSTALLED")
    runtime = observation.get("runtime", "UNTESTED")
    smoke = observation.get("smoke", "SKIP")
    uat = observation.get("uat", "SKIP")
    configured = observation.get("configured", False) is True
    facets = {"source": source, "compatibility": compatibility,
              "dependencies": dependencies["result"], "installation": installation,
              "configured": configured, "runtime": runtime, "smoke": smoke, "uat": uat}
    blockers = {"BLOCKED_BY_DEPENDENCY", "BLOCKED_BY_PLATFORM",
                "BLOCKED_BY_ENTITLEMENT", "BLOCKED_BY_ARCHITECTURE",
                "BROKEN_UPSTREAM", "UNSAFE_TO_ADAPT"}
    if source == "BLOCKED":
        badge, stage = "BLOCKED — SOURCE", "SOURCE_VERIFIED"
    elif compatibility in blockers:
        badge, stage = "BLOCKED — " + compatibility.removeprefix("BLOCKED_BY_").replace("_", " "), "COMPATIBILITY_CHECKED"
    elif compatibility == "ANALYZING":
        badge, stage = "ANALYZING…", "COMPATIBILITY_CHECKED"
    elif compatibility == "ADAPTATION_REQUIRED":
        badge, stage = "ADAPTATION REQUIRED", "COMPATIBILITY_CHECKED"
    elif compatibility == "ADAPTING":
        badge, stage = "ADAPTING FOR 0-SKY…", "COMPATIBILITY_CHECKED"
    elif compatibility == "BUILD_REQUIRED":
        badge, stage = "BUILD REQUIRED", "COMPATIBILITY_CHECKED"
    elif compatibility == "TESTING":
        badge, stage = "TESTING…", "RUNTIME_VERIFIED"
    elif dependencies["result"] == "BLOCKED":
        badge, stage = "MISSING DEPENDENCY", "DEPENDENCIES_RESOLVED"
    elif installation == "PARTIAL":
        badge, stage = "REPAIR REQUIRED", "INSTALLED"
    elif installation == "UNKNOWN":
        badge, stage = "UNTESTED", "DISCOVER"
    elif installation != "INSTALLED":
        badge, stage = (("SOURCE UNAVAILABLE", "DISCOVER") if source != "PASS" else
                        ("UNTESTED", "DEPENDENCIES_RESOLVED"))
    elif runtime == "FAIL":
        badge, stage = "REPAIR REQUIRED", "RUNTIME_VERIFIED"
    elif smoke == "FAIL" or uat == "FAIL":
        badge, stage = "FAILED", "SMOKE_TESTED" if smoke == "FAIL" else "UAT_VERIFIED"
    elif compatibility == "UNKNOWN":
        badge, stage = "COMPATIBILITY UNKNOWN", "COMPATIBILITY_CHECKED"
    elif any(value in {"DEGRADED", "PARTIALLY_COMPATIBLE"}
             for value in (compatibility, runtime, smoke, uat)):
        badge, stage = "DEGRADED", "RUNTIME_VERIFIED"
    elif (source == "PASS" and compatibility in {"COMPATIBLE", "COMPATIBLE_WITH_ADAPTER"}
          and configured and runtime == "PASS" and smoke == "PASS" and uat == "PASS"):
        badge, stage = "READY", "READY"
    else:
        badge, stage = "INSTALLED" if installation == "INSTALLED" else "UNTESTED", "VERIFYING"
    requested = set(row["actions"])
    allowed = {"verify", "test", "view_source", "view_logs"} & requested
    if compatibility == "UNKNOWN":
        allowed.add("analyze_compatibility")
    if compatibility in {"ADAPTATION_REQUIRED", "BUILD_REQUIRED"}:
        allowed.add("make_compatible")
    if compatibility in {"PARTIALLY_COMPATIBLE"} or runtime == "FAIL":
        allowed.add("repair_compatibility")
    if (source == "PASS" and compatibility in {"COMPATIBLE", "COMPATIBLE_WITH_ADAPTER"}
            and dependencies["result"] == "PASS" and observation.get("installer_ready") is True):
        allowed.update({"install", "update", "repair"} & requested)
    if (installation == "INSTALLED" and observation.get("installer_ready") is True
            and row["management"] not in {
            "PROTECTED_RUNTIME", "USER_MANAGED_PROPRIETARY"}):
        allowed.update({"remove"} & requested)
    return {"id": row["id"], "name": row["display_name"], "category": row["category"],
            "type": row["type"], "scope": row["scope"], "badge": badge,
            "lifecycle_stage": stage, "facets": facets,
            "installed_version": observation.get("installed_version"),
            "available_version": observation.get("available_version"),
            "command": observation.get("command"),
            "architectures": row["architectures"],
            "compatibility_reason": observation.get("compatibility_reason"),
            "runtime_reason": observation.get("runtime_reason"),
            "last_tested": observation.get("last_tested"),
            "source_trust": row["trust_state"],
            "package_source_trust": row["package_source_trust"],
            "missing_dependencies": dependencies["missing"],
            "conflicts": dependencies["conflicts"],
            "upstream_project": row["upstream_project"],
            "source_mirror": row.get("source_mirror"),
            "source_mirror_revision": row.get("source_mirror_revision"),
            "source_git": row.get("source_git"),
            "source_git_revision": row.get("source_git_revision"),
            "source_revision": row.get("source_revision"),
            "source_release": row.get("source_release"),
            "adaptation_patch": row.get("adaptation_patch"),
            "adaptation_patch_sha256": row.get("adaptation_patch_sha256"),
            "package_repository": row["package_repository"],
            "management": row["management"], "actions": sorted(allowed),
            "unavailable_actions": sorted(requested - allowed),
            "timestamp": datetime.now(timezone.utc).isoformat()}


def evaluate(catalog: dict, observations: dict[str, dict]) -> dict:
    components = catalog["components"]
    rows = []
    counts = defaultdict(int)
    for row in components:
        result = classify(row, observations.get(row["id"], {}),
                          resolve_dependencies(row, observations))
        rows.append(result)
        counts[result["badge"]] += 1
    return {"schema": 1, "components": rows, "counts": dict(counts),
            "overall": "PASS" if counts.get("READY") == len(rows) else
                       "BLOCKED" if counts.get("BLOCKED") else "DEGRADED",
            "evaluated_at": datetime.now(timezone.utc).isoformat()}
