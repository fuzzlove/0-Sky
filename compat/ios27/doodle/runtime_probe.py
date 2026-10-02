#!/usr/bin/env python3
"""Read-only Doodle API survey in a separate process on an authorized SRD.

This loads the frameworks into this probe process and inspects Objective-C
metadata. It never attaches to SpringBoard, invokes a lock-screen method, or
changes a preference. Presence alone does not establish safe hook behavior.
"""
from __future__ import annotations

import ctypes
import json
from pathlib import Path
import plistlib


FRAMEWORKS = ("CoverSheet", "SpringBoard", "SpringBoardFoundation",
              "BulletinBoard", "UserNotificationsUIKit")
METHODS = {
    "CSPasscodeViewController": {
        "showProudLock": "B16@0:8",
        "viewDidLoad": "v16@0:8",
    },
    "SBLockScreenManager": {
        "_attemptUnlockWithPasscode:mesa:finishUIUnlock:completion:": "B40@0:8@16B24B28@?32",
        "_isPasscodeVisible": "B16@0:8",
        "setPasscodeVisible:animated:": "v24@0:8B16B20",
    },
    "SBFUserAuthenticationController": {
        "_evaluateAuthenticationAttempt:outError:": "q32@0:8@16^@24",
    },
}
IVARS = {"CSPasscodeViewController": ("_passcodeLockView", '@"UIView<SBUIPasscodeLockView_Private>"')}

# Every non-UIKit legacy Logos hook. Presence is only an ABI survey, not a
# statement that its old implementation is safe or that the hook can run.
HOOK_SURFACE = {
    "SBIconController": ("viewDidAppear:",),
    "SBLockScreenBiometricAuthenticationCoordinator": ("isEnabled",),
    "SBBootDefaults": ("setDontLockAfterCrash:", "dontLockAfterCrash"),
    "SBLockScreenManager": ("_handleBacklightLevelWillChange:",),
    "CSPasscodeViewController": ("showProudLock", "viewDidLoad",
                                   "viewWillAppear:", "viewDidLayoutSubviews",
                                   "viewWillTransitionToSize:withTransitionCoordinator:"),
    "SBFUserAuthenticationController": ("_evaluateAuthenticationAttempt:outError:",),
    "BBServer": ("initWithQueue:",),
    "NCNotificationShortLookViewController": ("_handleTapOnView:",),
    "NCBadgedIconView": ("iconView",),
    "NCNotificationShortLookView": ("layoutSubviews",),
    "PLPlatterHeaderContentView": ("iconButtons",),
    "SBDeviceApplicationSceneHandle": ("backgroundStyle", "translucent"),
    "SBDeviceApplicationSceneView": ("_sceneHandleDidUpdateSettingsWithDiff:previousSettings:",),
}


def classify(classes: dict) -> dict:
    missing = []
    mismatched = []
    for name, methods in METHODS.items():
        entry = classes.get(name, {})
        if not entry.get("class_present"):
            missing.append(name)
            continue
        for selector, expected in methods.items():
            observed = entry.get("methods", {}).get(selector)
            if observed is None:
                missing.append(name + "." + selector)
            elif observed != expected:
                mismatched.append({"api": name + "." + selector,
                                   "expected": expected, "observed": observed})
    for name, (ivar, expected) in IVARS.items():
        observed = classes.get(name, {}).get("ivars", {}).get(ivar)
        if observed is None:
            missing.append(name + "." + ivar)
        elif observed != expected:
            mismatched.append({"api": name + "." + ivar,
                               "expected": expected, "observed": observed})
    return {"result": "BLOCKED" if missing or mismatched else "API_SIGNATURES_PRESENT_UNVERIFIED_RUNTIME",
            "missing": missing, "mismatched": mismatched}


def classify_hook_surface(surface: dict) -> dict:
    missing = []
    present = 0
    for name, selectors in HOOK_SURFACE.items():
        entry = surface.get(name, {})
        if not entry.get("class_present"):
            missing.append(name)
            continue
        for selector in selectors:
            if entry.get("methods", {}).get(selector):
                present += 1
            else:
                missing.append(name + "." + selector)
    return {"result": "BLOCKED_MISSING_LEGACY_API" if missing else
            "LEGACY_API_METADATA_PRESENT_UNVERIFIED_RUNTIME",
            "present_methods": present, "missing": missing}


def survey() -> dict:
    info = plistlib.loads(Path("/System/Library/CoreServices/SystemVersion.plist").read_bytes())
    objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
    objc.objc_getClass.argtypes = [ctypes.c_char_p]
    objc.objc_getClass.restype = ctypes.c_void_p
    objc.sel_registerName.argtypes = [ctypes.c_char_p]
    objc.sel_registerName.restype = ctypes.c_void_p
    objc.class_getInstanceMethod.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    objc.class_getInstanceMethod.restype = ctypes.c_void_p
    objc.method_getTypeEncoding.argtypes = [ctypes.c_void_p]
    objc.method_getTypeEncoding.restype = ctypes.c_char_p
    objc.class_getInstanceVariable.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    objc.class_getInstanceVariable.restype = ctypes.c_void_p
    objc.ivar_getTypeEncoding.argtypes = [ctypes.c_void_p]
    objc.ivar_getTypeEncoding.restype = ctypes.c_char_p
    loaded = []
    for name in FRAMEWORKS:
        try:
            ctypes.CDLL("/System/Library/PrivateFrameworks/" + name + ".framework/" + name)
            loaded.append({"framework": name, "result": "LOADED"})
        except OSError as error:
            loaded.append({"framework": name, "result": "FAILED", "reason": str(error)[:160]})
    classes = {}
    for name, selectors in METHODS.items():
        pointer = objc.objc_getClass(name.encode("ascii"))
        entry = {"class_present": bool(pointer), "methods": {}, "ivars": {}}
        if pointer:
            for selector in selectors:
                method = objc.class_getInstanceMethod(
                    pointer, objc.sel_registerName(selector.encode("ascii")))
                encoding = objc.method_getTypeEncoding(method) if method else None
                entry["methods"][selector] = encoding.decode("ascii") if encoding else None
            if name in IVARS:
                ivar_name = IVARS[name][0]
                ivar = objc.class_getInstanceVariable(pointer, ivar_name.encode("ascii"))
                encoding = objc.ivar_getTypeEncoding(ivar) if ivar else None
                entry["ivars"][ivar_name] = encoding.decode("ascii") if encoding else None
        classes[name] = entry
    surface = {}
    for name, selectors in HOOK_SURFACE.items():
        pointer = objc.objc_getClass(name.encode("ascii"))
        methods = {}
        if pointer:
            for selector in selectors:
                method = objc.class_getInstanceMethod(
                    pointer, objc.sel_registerName(selector.encode("ascii")))
                encoding = objc.method_getTypeEncoding(method) if method else None
                methods[selector] = encoding.decode("ascii") if encoding else None
        surface[name] = {"class_present": bool(pointer), "methods": methods}
    return {"schema": 1, "component": "com.nahtedetihw.doodle",
            "ios_version": str(info.get("ProductVersion", "UNKNOWN")),
            "ios_build": str(info.get("ProductBuildVersion", info.get("BuildVersion", "UNKNOWN"))),
            "loaded": loaded, "classes": classes, "compatibility": classify(classes),
            "legacy_hook_surface": surface,
            "legacy_hook_compatibility": classify_hook_surface(surface),
            "note": "Metadata presence does not prove safe lock-screen hooks or Doodle functionality"}


if __name__ == "__main__":
    print(json.dumps(survey(), sort_keys=True))
