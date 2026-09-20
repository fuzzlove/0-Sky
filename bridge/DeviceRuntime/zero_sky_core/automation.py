"""Transactional profiles, structured automation, and logical app freeze.

The module deliberately controls only facilities for which 0-Sky has a
reviewed provider.  In particular, it never treats a row in SQLite as proof
that iOS background execution or networking was blocked.
"""
from __future__ import annotations

import copy
import datetime as dt
import re
import threading
import time
from typing import Any, Callable

from .database import EventStore
from .paths import RootlessPaths


PROFILE_NAMES = ("Normal", "Work", "Travel", "Privacy", "Battery", "Gaming", "Research")
TRIGGER_TYPES = frozenset({
    "time", "applicationLaunch", "applicationExit", "wifiSSID",
    "bluetoothConnection", "batteryThreshold", "chargingState",
    "thermalState", "screenLock", "screenUnlock", "profileChange",
})
ACTION_TYPES = frozenset({
    "applyProfile", "modifyFirewallRule", "freezeApp", "unfreezeApp",
    "createSnapshot", "showNotification", "enablePrivacyProfile",
})
BUNDLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$")
RULE_NAME = re.compile(r"^[^\x00-\x1f]{1,80}$")


class PolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _bounded_object(value: Any, name: str, maximum: int = 64) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > maximum:
        raise PolicyError("INVALID_POLICY", f"{name} must be a bounded object")
    return copy.deepcopy(value)


def validate_profile(value: Any) -> dict[str, Any]:
    """Return a normalized, versioned profile or fail closed."""
    profile = _bounded_object(value, "profile", 16)
    unknown = set(profile) - {
        "version", "name", "firewallPolicy", "privacyPolicy", "dnsPolicy",
        "vpnPreference", "automationRules", "freezePolicy",
        "notificationPolicy", "systemSettings",
    }
    if unknown:
        raise PolicyError("INVALID_POLICY", "unknown profile field: " + sorted(unknown)[0])
    if profile.get("version", 1) != 1:
        raise PolicyError("INVALID_POLICY", "unsupported profile version")
    name = profile.get("name")
    if not isinstance(name, str) or not RULE_NAME.fullmatch(name):
        raise PolicyError("INVALID_POLICY", "profile name is invalid")
    normalized: dict[str, Any] = {"version": 1, "name": name}
    for key in ("firewallPolicy", "privacyPolicy", "dnsPolicy", "vpnPreference",
                "freezePolicy", "notificationPolicy", "systemSettings"):
        normalized[key] = _bounded_object(profile.get(key, {}), key)
    rules = profile.get("automationRules", [])
    if (not isinstance(rules, list) or len(rules) > 128 or
            any(not isinstance(item, int) or isinstance(item, bool) or item < 1
                for item in rules)):
        raise PolicyError("INVALID_POLICY", "automationRules must contain bounded rule IDs")
    normalized["automationRules"] = list(dict.fromkeys(rules))
    freeze_apps = normalized["freezePolicy"].get("frozenApps", [])
    if (not isinstance(freeze_apps, list) or len(freeze_apps) > 128 or
            any(not isinstance(item, str) or not BUNDLE_ID.fullmatch(item)
                for item in freeze_apps)):
        raise PolicyError("INVALID_POLICY", "freezePolicy.frozenApps is invalid")
    normalized["freezePolicy"]["frozenApps"] = sorted(set(freeze_apps))
    return normalized


def validate_rule(value: Any) -> dict[str, Any]:
    """Validate structured rules; strings can never become shell commands."""
    rule = _bounded_object(value, "rule", 8)
    if set(rule) - {"version", "name", "trigger", "conditions", "actions"}:
        raise PolicyError("INVALID_RULE", "rule contains an unknown field")
    if rule.get("version", 1) != 1:
        raise PolicyError("INVALID_RULE", "unsupported rule version")
    name = rule.get("name")
    if not isinstance(name, str) or not RULE_NAME.fullmatch(name):
        raise PolicyError("INVALID_RULE", "rule name is invalid")
    trigger = _bounded_object(rule.get("trigger"), "trigger", 6)
    trigger_type = trigger.get("type")
    if trigger_type not in TRIGGER_TYPES:
        raise PolicyError("INVALID_RULE", "trigger type is not approved")
    conditions = rule.get("conditions", [])
    if not isinstance(conditions, list) or len(conditions) > 16:
        raise PolicyError("INVALID_RULE", "conditions must be a bounded list")
    clean_conditions = []
    for condition in conditions:
        item = _bounded_object(condition, "condition", 4)
        if set(item) != {"field", "operator", "value"}:
            raise PolicyError("INVALID_RULE", "condition shape is invalid")
        if item["operator"] not in {"equals", "notEquals", "lessThan", "greaterThan", "contains"}:
            raise PolicyError("INVALID_RULE", "condition operator is not approved")
        if not isinstance(item["field"], str) or len(item["field"]) > 64:
            raise PolicyError("INVALID_RULE", "condition field is invalid")
        if isinstance(item["value"], (dict, list)) or item["value"] is None:
            raise PolicyError("INVALID_RULE", "condition value must be scalar")
        clean_conditions.append(item)
    actions = rule.get("actions")
    if not isinstance(actions, list) or not 1 <= len(actions) <= 16:
        raise PolicyError("INVALID_RULE", "actions must be a non-empty bounded list")
    clean_actions = []
    for action in actions:
        item = _bounded_object(action, "action", 4)
        if set(item) - {"type", "parameters"} or item.get("type") not in ACTION_TYPES:
            raise PolicyError("INVALID_RULE", "action type is not approved")
        parameters = _bounded_object(item.get("parameters", {}), "action parameters", 12)
        # Explicitly reject command-like escape hatches even as inert metadata.
        if any(key.casefold() in {"command", "shell", "script", "executable", "argv"}
               for key in parameters):
            raise PolicyError("INVALID_RULE", "arbitrary command parameters are prohibited")
        clean_actions.append({"type": item["type"], "parameters": parameters})
    return {"version": 1, "name": name, "trigger": trigger,
            "conditions": clean_conditions, "actions": clean_actions}


def builtin_profiles() -> list[dict[str, Any]]:
    profiles = []
    for name in PROFILE_NAMES:
        profile = validate_profile({"version": 1, "name": name})
        # These are conservative presets.  They make no unsupported system
        # mutation and become useful as the user adds explicit policies.
        profile["notificationPolicy"] = {"mode": "normal"}
        if name == "Privacy":
            profile["privacyPolicy"] = {"mode": "strictWhenSupported"}
        elif name == "Battery":
            profile["systemSettings"] = {"preference": "batteryConscious"}
        elif name == "Travel":
            profile["vpnPreference"] = {"preference": "connectWhenAvailable"}
        profiles.append(profile)
    return profiles


class FreezeCoordinator:
    """Apply only 0-Sky-owned logical controls; never mutate app data."""
    def __init__(self, paths: RootlessPaths, store: EventStore,
                 app_provider: Callable[[], list[dict[str, Any]]]) -> None:
        self.paths, self.store, self.app_provider = paths, store, app_provider
        self._lock = threading.RLock()

    @staticmethod
    def capability() -> dict[str, Any]:
        return {"state": "MonitorOnly",
                "reason": "0-Sky automation suppression is available; iOS background, launch, and network blocking have no reviewed provider",
                "controls": {"automation": "Supported", "background": "Unsupported",
                             "networking": "Unsupported", "launch": "Unsupported"}}

    def _app(self, bundle_id: str) -> dict[str, Any]:
        if not isinstance(bundle_id, str) or not BUNDLE_ID.fullmatch(bundle_id):
            raise PolicyError("INVALID_BUNDLE_ID", "bundleID is invalid")
        matches = [app for app in self.app_provider() if app.get("bundleID") == bundle_id]
        if len(matches) != 1:
            raise PolicyError("APP_NOT_FOUND", "exact installed third-party application was not found")
        return matches[0]

    def list(self) -> list[dict[str, Any]]:
        apps = {app["bundleID"]: app for app in self.app_provider()}
        frozen = {row["bundle_id"]: row for row in self.store.frozen_apps()}
        result = []
        for bundle_id, app in sorted(apps.items(), key=lambda item: str(item[1].get("name", item[0])).casefold()):
            row = frozen.get(bundle_id)
            result.append({"bundleID": bundle_id, "name": app.get("name") or bundle_id,
                           "version": app.get("version"),
                           "state": row["state"] if row else "Active",
                           "expiresAt": row.get("expires_at") if row else None,
                           "appliedControls": row.get("applied_controls", {}) if row else {},
                           "lastError": row.get("last_error") if row else None})
        return result

    def freeze(self, bundle_id: str, profile_name: str | None = None) -> dict[str, Any]:
        app = self._app(bundle_id)
        with self._lock:
            previous = self.store.frozen_app(bundle_id)
            original = (previous or {}).get("original_state") or {
                "state": "Active", "automationSuppressed": False}
            controls = {"automation": True, "background": False,
                        "networking": False, "launch": False}
            self.store.set_frozen_app(bundle_id, "Frozen", original, controls,
                                      expires_at=None, profile_name=profile_name)
        return {"bundleID": bundle_id, "name": app.get("name"), "state": "Frozen",
                "appliedControls": controls,
                "limitations": ["background", "networking", "launch"],
                "dataModified": False, "reversible": True}

    def temporarily_activate(self, bundle_id: str, duration: int) -> dict[str, Any]:
        if not isinstance(duration, int) or isinstance(duration, bool) or not 60 <= duration <= 86400:
            raise PolicyError("INVALID_DURATION", "duration must be between 60 and 86400 seconds")
        self._app(bundle_id)
        with self._lock:
            current = self.store.frozen_app(bundle_id)
            if not current or current["state"] != "Frozen":
                raise PolicyError("NOT_FROZEN", "application is not currently frozen")
            expires = time.time() + duration
            controls = dict(current["applied_controls"])
            controls["automation"] = False
            self.store.set_frozen_app(bundle_id, "Temporarily Active",
                                      current["original_state"], controls,
                                      expires_at=expires,
                                      profile_name=current.get("profile_name"))
        return {"bundleID": bundle_id, "state": "Temporarily Active",
                "expiresAt": expires, "appliedControls": controls,
                "dataModified": False, "reversible": True}

    def unfreeze(self, bundle_id: str) -> dict[str, Any]:
        self._app(bundle_id)
        with self._lock:
            current = self.store.frozen_app(bundle_id)
            if not current:
                return {"bundleID": bundle_id, "state": "Active",
                        "restored": False, "dataModified": False}
            original = current["original_state"]
            self.store.delete_frozen_app(bundle_id)
        return {"bundleID": bundle_id, "state": "Active", "restored": True,
                "restoredPolicy": original, "dataModified": False}

    def maintain(self, now: float | None = None) -> int:
        stamp = time.time() if now is None else float(now)
        count = 0
        for row in self.store.frozen_apps():
            if (row["state"] == "Temporarily Active" and row.get("expires_at") is not None
                    and float(row["expires_at"]) <= stamp):
                self.store.set_frozen_app(row["bundle_id"], "Frozen",
                                          row["original_state"],
                                          {**row["applied_controls"], "automation": True},
                                          profile_name=row.get("profile_name"))
                count += 1
        return count

    def automation_suppressed(self, bundle_id: str) -> bool:
        row = self.store.frozen_app(bundle_id)
        return bool(row and row["state"] == "Frozen" and
                    row["applied_controls"].get("automation"))


class ProfileEngine:
    """Validate -> snapshot -> apply -> verify -> commit, or rollback."""
    def __init__(self, store: EventStore, freeze: FreezeCoordinator) -> None:
        self.store, self.freeze = store, freeze
        self._lock = threading.RLock()

    def seed(self) -> None:
        for profile in builtin_profiles():
            self.store.upsert_profile(profile["name"], profile, built_in=True)
        if self.store.active_profile() is None:
            self.store.set_active_profile("Normal", effective_state={"freezePolicy": {"frozenApps": []}})

    def list(self) -> list[dict[str, Any]]:
        self.seed()
        return self.store.profiles()

    def save(self, profile: Any) -> dict[str, Any]:
        value = validate_profile(profile)
        if value["name"] in PROFILE_NAMES:
            raise PolicyError("BUILTIN_IMMUTABLE", "built-in profiles cannot be overwritten")
        self.store.upsert_profile(value["name"], value, built_in=False)
        return self.store.profile(value["name"]) or {}

    def apply(self, name: str) -> dict[str, Any]:
        if not isinstance(name, str) or not RULE_NAME.fullmatch(name):
            raise PolicyError("INVALID_POLICY", "profile name is invalid")
        self.seed()
        target = self.store.profile(name)
        if not target:
            raise PolicyError("PROFILE_NOT_FOUND", "profile does not exist")
        requested = validate_profile(target["profile"])
        # Without reviewed providers, non-empty enforcement policies are not
        # silently accepted as if they had changed iOS.
        unsupported = [key for key in ("firewallPolicy", "privacyPolicy", "dnsPolicy", "systemSettings")
                       if requested[key] and set(requested[key]) - {"mode", "preference"}]
        if unsupported:
            raise PolicyError("UNSUPPORTED_POLICY", "no reviewed provider for " + unsupported[0])
        with self._lock:
            previous_profile = self.store.active_profile()
            previous_frozen = self.store.frozen_apps()
            transaction = self.store.begin_profile_transaction(
                name, previous_profile["name"] if previous_profile else None,
                {"frozenApps": previous_frozen}, requested)
            try:
                desired = set(requested["freezePolicy"].get("frozenApps", []))
                profile_owned = {row["bundle_id"] for row in previous_frozen
                                 if row.get("profile_name")}
                for bundle_id in sorted(profile_owned - desired):
                    self.freeze.unfreeze(bundle_id)
                for bundle_id in sorted(desired):
                    self.freeze.freeze(bundle_id, profile_name=name)
                effective = {"freezePolicy": {"frozenApps": sorted(desired)},
                             "metadataOnly": {
                                 "vpnPreference": requested["vpnPreference"],
                                 "notificationPolicy": requested["notificationPolicy"],
                                 "privacyPolicy": requested["privacyPolicy"],
                                 "systemSettings": requested["systemSettings"]}}
                self.store.set_active_profile(name, effective)
                current = self.store.active_profile()
                actual = {row["bundle_id"] for row in self.store.frozen_apps()
                          if row.get("profile_name") == name and row["state"] == "Frozen"}
                if not current or current["name"] != name or actual != desired:
                    raise PolicyError("VERIFY_FAILED", "profile verification did not match requested state")
                self.store.finish_profile_transaction(transaction, "Committed", effective)
                return {"transactionID": transaction, "profile": name,
                        "state": "Committed", "effectiveState": effective,
                        "rolledBack": False}
            except Exception as error:
                # Restore 0-Sky-owned logical policy exactly.  No app files are
                # involved in profile rollback.
                for row in self.store.frozen_apps():
                    self.store.delete_frozen_app(row["bundle_id"])
                for row in previous_frozen:
                    self.store.set_frozen_app(row["bundle_id"], row["state"],
                                              row["original_state"], row["applied_controls"],
                                              row.get("expires_at"), row.get("profile_name"),
                                              row.get("last_error"))
                if previous_profile:
                    self.store.set_active_profile(previous_profile["name"],
                                                  previous_profile.get("effective_state", {}))
                self.store.finish_profile_transaction(transaction, "RolledBack", {}, str(error))
                if isinstance(error, PolicyError):
                    raise
                raise PolicyError("PROFILE_APPLY_FAILED", "profile apply failed and was rolled back") from error


class AutomationEngine:
    """Event-driven evaluator for approved structured actions only."""
    def __init__(self, store: EventStore, profiles: ProfileEngine,
                 freeze: FreezeCoordinator,
                 create_snapshot: Callable[[str, str], dict[str, Any]]) -> None:
        self.store, self.profiles, self.freeze = store, profiles, freeze
        self.create_snapshot = create_snapshot
        self._lock = threading.RLock()
        self._last_time_minute: int | None = None
        self._next_maintenance = 0.0

    @staticmethod
    def capability() -> dict[str, Any]:
        return {"state": "Supported",
                "reason": "Structured event rules and transactional profile actions are available; unsupported actions fail visibly",
                "arbitraryShell": False,
                "triggers": sorted(TRIGGER_TYPES), "actions": sorted(ACTION_TYPES)}

    def save_rule(self, rule: Any, enabled: bool = True,
                  rule_id: int | None = None) -> dict[str, Any]:
        clean = validate_rule(rule)
        identifier = self.store.upsert_automation_rule(clean["name"], clean,
                                                       bool(enabled), rule_id)
        return self.store.automation_rule(identifier) or {}

    def _condition(self, condition: dict[str, Any], event: dict[str, Any]) -> bool:
        current: Any = event
        for part in condition["field"].split("."):
            if not isinstance(current, dict) or part not in current:
                return False
            current = current[part]
        expected, operator = condition["value"], condition["operator"]
        try:
            return {"equals": current == expected, "notEquals": current != expected,
                    "lessThan": current < expected, "greaterThan": current > expected,
                    "contains": expected in current}[operator]
        except (TypeError, KeyError):
            return False

    @staticmethod
    def _trigger_matches(trigger: dict[str, Any], event: dict[str, Any]) -> bool:
        if trigger.get("type") != event.get("type"):
            return False
        for key, value in trigger.items():
            if key != "type" and event.get(key) != value:
                return False
        return True

    def _action(self, action: dict[str, Any]) -> dict[str, Any]:
        kind, parameters = action["type"], action["parameters"]
        if kind == "applyProfile":
            return self.profiles.apply(parameters.get("name"))
        if kind == "enablePrivacyProfile":
            return self.profiles.apply("Privacy")
        if kind == "freezeApp":
            return self.freeze.freeze(parameters.get("bundleID"))
        if kind == "unfreezeApp":
            return self.freeze.unfreeze(parameters.get("bundleID"))
        if kind == "createSnapshot":
            bundle_id = parameters.get("bundleID")
            if not isinstance(bundle_id, str):
                raise PolicyError("INVALID_ACTION", "createSnapshot requires bundleID")
            value = self.create_snapshot(bundle_id, "automation")
            return {key: value[key] for key in ("id", "bundleID", "stateDigest", "integrity")
                    if key in value}
        if kind == "modifyFirewallRule":
            raise PolicyError("UNSUPPORTED_ACTION", "no reviewed firewall mutation provider is installed")
        if kind == "showNotification":
            raise PolicyError("UNSUPPORTED_ACTION", "no reviewed local-notification provider is installed")
        raise PolicyError("INVALID_ACTION", "action is not approved")

    def emit(self, event: Any) -> dict[str, Any]:
        value = _bounded_object(event, "event", 16)
        kind = value.get("type")
        if kind not in TRIGGER_TYPES:
            raise PolicyError("INVALID_EVENT", "event trigger type is not approved")
        self.store.record_automation_event(kind, value.get("bundleID"), value)
        runs = []
        with self._lock:
            for row in self.store.automation_rules(enabled_only=True):
                rule = validate_rule(row["rule"])
                if not self._trigger_matches(rule["trigger"], value):
                    continue
                if not all(self._condition(item, value) for item in rule["conditions"]):
                    continue
                bundle_id = value.get("bundleID")
                if isinstance(bundle_id, str) and self.freeze.automation_suppressed(bundle_id):
                    result = {"state": "Skipped", "reason": "application automation is frozen"}
                    self.store.record_automation_run(row["id"], False, result,
                                                     error="application automation is frozen")
                    runs.append({"ruleID": row["id"], **result})
                    continue
                action_results, error = [], None
                try:
                    for action in rule["actions"]:
                        action_results.append(self._action(action))
                    result = {"state": "Completed", "actions": action_results}
                    success = True
                except PolicyError as failure:
                    error = f"{failure.code}: {failure}"
                    result = {"state": "Failed", "actions": action_results,
                              "errorCode": failure.code, "message": str(failure)}
                    success = False
                self.store.record_automation_run(row["id"], success, result, error=error)
                runs.append({"ruleID": row["id"], **result})
        return {"event": value, "matchedRules": len(runs), "runs": runs}

    def maintain(self, now: float | None = None) -> int:
        stamp = time.time() if now is None else float(now)
        if stamp < self._next_maintenance:
            return 0
        self._next_maintenance = stamp + 30.0
        transitions = self.freeze.maintain(stamp)
        minute = int(stamp // 60)
        time_rules = [row for row in self.store.automation_rules(enabled_only=True)
                      if isinstance(row.get("rule"), dict) and
                      row["rule"].get("trigger", {}).get("type") == "time"]
        if time_rules and self._last_time_minute != minute:
            self._last_time_minute = minute
            moment = dt.datetime.fromtimestamp(stamp).astimezone()
            self.emit({"type": "time", "hour": moment.hour,
                       "minute": moment.minute, "weekday": moment.weekday()})
            transitions += 1
        return transitions
