"""Admission analysis for an exact, verified Debian tweak artifact.

Upstream jailbreak support declarations are deliberately not an admission
input.  The decision is based on the artifact and the measured SRD profile.
Installation and runtime verification remain separate transaction stages.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import plistlib
import re
import struct
import subprocess
import tempfile

from .analysis import metadata
from .classification import legacy_status
from .engine import Engine
from .environment import detect
from .integration import default_state
from . import macho


INJECTION_ROOTS = (
    "var/jb/Library/MobileSubstrate/DynamicLibraries/",
    "var/jb/usr/lib/TweakInject/",
)
CRANE_PACKAGES = {"com.opa334.crane", "com.opa334.cranelite"}
CRANE_SCRIPT_HASHES = {
    "postinst": {
        "df0f5daebeedfb7b94c34abcde8b6a72f49e008cb188f8e549332412c25312e8",
        "8cc9ddbd5c9f5a0d05fdec8d68be64088ad15f577258d29cde220865f572687c",
    },
    "prerm": {
        "59ecec5cbfdf2a6cf32a34c006578c32b4b9c25dd01265c4dde35fa6e35e1f09",
    },
    "postrm": {
        "958a35406916c6dacc75094db77418ef8ddd522ae314b4a5c6698771f2961c39",
        "8f05488c666bbf6b144755121155094a4dbabc14052c56253258c8e4b229d079",
    },
}
CRANE_SERVICE = {
    "label": "com.opa334.cranehelperd",
    "program": "/var/jb/usr/local/libexec/cranehelperd",
    "plist": "/var/jb/Library/LaunchDaemons/com.opa334.cranehelperd.plist",
    "mach_services": [
        "com.opa334.cranehelperd.preferences.xpc",
        "com.opa334.cranehelperd.xpc",
    ],
}
CRANE_RUNTIME_DYLIB_ROOT = "/var/jb/Library/MobileSubstrate/DynamicLibraries"
CRANE_CONTROL_ALLOWLIST = (
    "/var/jb/var/lib/srd-runtime/tweak-targets/com.opa334.crane.json"
)
CRANE_STARTER_PATH = "/var/jb/usr/local/bin/cranehelperd_start"
# CraneSB launches this exact path during SpringBoard startup.  The upstream
# binary calls libjailbreak and legacy launchctl, neither of which represents
# the SRD service lifecycle.  The transactional package bridge starts and
# verifies cranehelperd through its sealed companion and launchctl-srd
# adapter.  Keep this small compatibility entry point so CraneSB's NSTask does
# not throw while that managed service is being activated.  It deliberately
# performs no privileged operation of its own.
CRANE_STARTER_ADAPTER = (
    b"#!/bin/sh\n"
    b"# 0-Sky crane-family-v2: cranehelperd is managed by the SRD service backend.\n"
    b"exit 0\n"
)
# ZIP, used by the SRD application registration path for mixed tweak/app
# packages, cannot represent timestamps before 1980-01-01 in local time. Use
# the project's deterministic ZIP epoch (2000-01-01 UTC), which remains valid
# in every supported host time zone while keeping derivative DEBs reproducible.
REPRODUCIBLE_ARCHIVE_EPOCH = 946684800

# Crane 1.3.9 tail-calls LHHookFunctions after resolving
# __CFPrefsGetPathForTriplet from the iOS shared cache.  ElleKit 1.2 implements
# that C-function hook by changing the signed CoreFoundation page to RW and
# writing a branch into it.  iOS 27 refuses to make the modified page
# executable again and kills cfprefsd on its next preferences request.  Keep
# Crane's Objective-C and XPC hooks, but skip this one unsafe shared-cache
# function hook.  The offsets below are relative to their thin Mach-O slices;
# every byte, branch target and whole-file hash is verified before mutation.
CRANE_IOS27_SUPPORT_PATCHES = {
    "91f1d8969ad16051645e8dd34c4e67b749e2b80e23a9eb83b15e79323d5ca5f1": {
        0: {"offset": 0x9724, "target": 0xF334},       # arm64
        2: {"offset": 0xCD5C, "target": 0x13150},     # arm64e
    },
}
# Crane 1.3.9 implements ``CRSubtitleMenu.subtitle`` with an associated
# object.  UIKit on the measured iOS 27 build now copies and renders menu
# subtitles from UIMenuElement's native state, bypassing Crane's legacy copy
# paths.  Remove only the two subclass overrides by retargeting their compact
# Objective-C method-list selectors to otherwise unrelated, existing Crane
# selectors.  Calls to ``subtitle`` and ``setSubtitle:`` then resolve to the
# inherited UIMenuElement implementation while Crane's four copy overrides
# remain intact.  The offsets and signed relative-selector values are
# identical in the reviewed arm64 and arm64e slices and are checked before
# mutation.
CRANE_IOS27_SPRINGBOARD_SUBTITLE_PATCHES = {
    "2448ee43ab7ebe53322f117d1335171048337f127d9f1a3139b2c48e15badc30": {
        0: (
            {"offset": 0x1DEE0, "expected": 0xBC00, "replacement": 0xB370},
            {"offset": 0x1DEEC, "expected": 0xBB54, "replacement": 0xBA54},
        ),
        2: (
            {"offset": 0x1DEE0, "expected": 0xBC00, "replacement": 0xB370},
            {"offset": 0x1DEEC, "expected": 0xBB54, "replacement": 0xBA54},
        ),
    },
}
CRANE_IOS27_LIBCRANE_SOURCE_SHA256 = (
    "c367a60abdd759bc8682521ccc5bdec6bfee1869673b822b85fe31f298d2f058"
)
CRANE_IOS27_LIBCRANE_SIGNED_SHA256 = (
    "a5a10059a4d9af20d03676d525e8d2cffbe37185227ae0090a9c54ffa7ccd595"
)
CRANE_IOS27_LIBCRANE_IDENTIFIER = (
    "codes.openai.research.support." + CRANE_IOS27_LIBCRANE_SOURCE_SHA256[:20]
)
CRANE_IOS27_SPRINGBOARD_COMPAT_SOURCE_SHA256 = (
    "eda48d25c8699521386c327746ba52ecdbb0130c01dd209cd6a033ee0e3987c5"
)
CRANE_IOS27_SPRINGBOARD_COMPAT_SHA256 = (
    "420b7efc5b0efb8776c08959506e96e80243fb065f656e1c9f51c1e65732b8a9"
)
CRANE_IOS27_SPRINGBOARD_COMPAT_FILTER_SHA256 = (
    "e7dc57a8e03d8bfbdcc532669806e91849452e5974645aad9dffde2d6e2a90d5"
)
ARM64_CPU_TYPE = 0x0100000C
ARM64_SUBTYPE_MASK = 0x00FFFFFF
ARM64_RET = b"\xc0\x03\x5f\xd6"


def _crane_runtime_contract(package: str) -> dict:
    """Describe Crane targets which cannot be inferred from its legacy filters.

    ``com.apple.Foundation`` historically meant "every Objective-C app" to
    Substrate.  Expanding that filter on an SRD would inject an unreviewed
    package into arbitrary applications.  Crane Lite already records the one
    application selected by the user, so the runtime adapter can narrow the
    target to that exact bundle.  Full Crane requires an explicit 0-Sky
    allowlist because its configuration can contain several applications.
    """
    root = CRANE_RUNTIME_DYLIB_ROOT
    target_source = ({
        "kind": "plist-string",
        "path": "/var/mobile/Library/Preferences/com.opa334.craneliteprefs.plist",
        "key": "selectedApplication",
    } if package == "com.opa334.cranelite" else {
        "kind": "control-app-allowlist",
        "path": CRANE_CONTROL_ALLOWLIST,
    })
    required_dylibs = [root + "/CraneSB.dylib", root + "/CraneSupport.dylib"]
    process_selectors = [{
        "dylib": root + "/CraneSB.dylib",
        "executable": "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
        "sandbox_dependencies": [
            "/var/jb/usr/lib/libcrane.dylib",
            "/var/jb/usr/lib/libsandy.dylib",
            "/var/jb/usr/lib/libellekit.dylib",
        ],
    }]
    if package == "com.opa334.crane":
        required_dylibs.insert(1, root + "/CraneSBCompat.dylib")
        process_selectors.append({
            "dylib": root + "/CraneSBCompat.dylib",
            "executable": "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
        })
    process_selectors.append({
        "dylib": root + "/CraneSupport.dylib",
        "executable": "/usr/sbin/cfprefsd",
        "environment": {
            "XPC_SERVICE_NAME": "com.apple.cfprefsd.xpc.daemon",
        },
        "sandbox_dependencies": [
            "/var/jb/usr/lib/libcrane.dylib",
            "/var/jb/usr/lib/libsandy.dylib",
            "/var/jb/usr/lib/libellekit.dylib",
        ],
    })
    return {
        "required_dylibs": required_dylibs,
        "configuration_dependent": [{
            "dylib": root + "/ Crane.dylib",
            "legacy_filter": "com.apple.Foundation",
            "target_source": target_source,
            "sandbox_dependencies": [
                "/var/jb/usr/lib/libcrane.dylib",
                "/var/jb/usr/lib/libsandy.dylib",
                "/var/jb/usr/lib/libellekit.dylib",
            ],
        }],
        "process_selectors": process_selectors,
    }
DEPENDENCY_ALIASES = {
    "mobilesubstrate": ("ellekit", "cydiasubstrate"),
    "cydiasubstrate": ("ellekit",),
}
HARD_BLOCKERS = {
    "ARCHITECTURE_MISMATCH": "BLOCKED_BY_ARCHITECTURE",
    "MACHO_INVALID": "BROKEN_UPSTREAM",
    "INVALID_PACKAGE_METADATA": "BROKEN_UPSTREAM",
    "UNSUPPORTED_PLATFORM": "BLOCKED_BY_PLATFORM",
    "UNSUPPORTED_API": "BLOCKED_BY_PLATFORM",
    "MISSING_ENTITLEMENT": "BLOCKED_BY_ENTITLEMENT",
    "UNSUPPORTED_SECURITY_ASSUMPTION": "UNSAFE_TO_ADAPT",
}
_DEPENDENCY = re.compile(
    r"\s*([a-z0-9][a-z0-9+.-]+)(?::[a-z0-9-]+)?"
    r"\s*(?:\((?:<<|<=|=|>=|>>)\s*[^()]+\))?\s*\Z"
)


def _installed(env, name: str) -> bool:
    value = env.packages.get(name)
    if isinstance(value, dict) and value.get("installed") is True:
        return True
    return any(
        isinstance(item, dict) and item.get("installed") is True and
        name in item.get("provides", [])
        for item in env.packages.values()
    )


def _dependency_groups(value: str) -> list[list[str]]:
    groups = []
    for raw_group in value.split(","):
        if not raw_group.strip():
            continue
        group = []
        for raw_choice in raw_group.split("|"):
            match = _DEPENDENCY.fullmatch(raw_choice)
            if not match:
                raise ValueError("unsupported dependency expression")
            group.append(match.group(1))
        groups.append(group)
    return groups


def _dependency_available(env, name: str) -> tuple[bool, str | None]:
    if _installed(env, name):
        return True, None
    for provider in DEPENDENCY_ALIASES.get(name, ()):
        if _installed(env, provider):
            return True, f"{name}->{provider}"
    return False, None


def _filter(path: Path) -> dict:
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        raise ValueError("invalid tweak filter plist") from error
    rule = value.get("Filter") if isinstance(value, dict) else None
    if not isinstance(rule, dict):
        raise ValueError("tweak filter is missing")
    scope = {}
    for key in ("Bundles", "Executables", "Classes"):
        entries = rule.get(key)
        if entries is None:
            continue
        if (not isinstance(entries, list) or not entries or
                any(not isinstance(item, str) or not item or len(item) > 255
                    for item in entries)):
            raise ValueError("tweak filter has an invalid " + key + " scope")
        scope[key] = entries
    if not scope:
        raise ValueError("unscoped tweak injection is not admitted")
    return scope


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _adapt_crane_support_ios27(root: Path, package: str) -> list[dict]:
    """Disable one evidenced unsafe shared-cache hook in exact Crane builds.

    This is deliberately not a generic byte replacement.  It parses the fat
    container, requires both expected ARM64 slices, decodes each branch, and
    verifies the destination is the slice's HCHookFunctions implementation.
    Any new upstream binary remains unmodified and requires analysis.
    """
    if package != "com.opa334.crane":
        return []
    relative = Path("var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSupport.dylib")
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise ValueError("paid Crane has no regular CraneSupport.dylib")
    original_hash = _sha256(path)
    specification = CRANE_IOS27_SUPPORT_PATCHES.get(original_hash)
    if specification is None:
        raise ValueError("paid CraneSupport differs from the reviewed iOS 27 hook adapter")

    payload = bytearray(path.read_bytes())
    if len(payload) < 8 or struct.unpack_from(">I", payload)[0] != 0xCAFEBABE:
        raise ValueError("reviewed CraneSupport is not the expected fat Mach-O")
    slice_count = struct.unpack_from(">I", payload, 4)[0]
    if slice_count != len(specification):
        raise ValueError("reviewed CraneSupport slice count changed")
    observed = set()
    for index in range(slice_count):
        header = 8 + index * 20
        if header + 20 > len(payload):
            raise ValueError("truncated CraneSupport fat header")
        cpu_type, cpu_subtype, slice_offset, slice_size, _ = struct.unpack_from(
            ">iiIII", payload, header)
        subtype = cpu_subtype & ARM64_SUBTYPE_MASK
        rule = specification.get(subtype)
        if cpu_type != ARM64_CPU_TYPE or rule is None or subtype in observed:
            raise ValueError("unexpected CraneSupport architecture")
        observed.add(subtype)
        patch_offset = rule["offset"]
        absolute = slice_offset + patch_offset
        if (patch_offset + 4 > slice_size or absolute + 4 > len(payload)):
            raise ValueError("CraneSupport patch location is outside its slice")
        instruction = struct.unpack_from("<I", payload, absolute)[0]
        if instruction >> 26 != 0b000101:
            raise ValueError("CraneSupport hook tail call is no longer an ARM64 branch")
        displacement = instruction & 0x03FFFFFF
        if displacement & 0x02000000:
            displacement -= 0x04000000
        destination = patch_offset + displacement * 4
        if destination != rule["target"]:
            raise ValueError("CraneSupport hook tail call target changed")
        payload[absolute:absolute + 4] = ARM64_RET
    if observed != set(specification):
        raise ValueError("CraneSupport is missing a reviewed architecture")
    path.write_bytes(payload)
    path.chmod(0o755)
    return [{
        "adapter": "ios27-shared-cache-hook-v1",
        "path": "/" + relative.as_posix(),
        "original_sha256": original_hash,
        "adapted_sha256": _sha256(path),
        "change": "defer __CFPrefsGetPathForTriplet direct hook",
        "reason": "iOS 27 rejects executable restoration of modified signed shared-cache pages",
    }]


def _adapt_crane_springboard_subtitles_ios27(root: Path, package: str) -> list[dict]:
    """Use UIKit's native menu-subtitle state for an exact CraneSB build."""
    if package != "com.opa334.crane":
        return []
    relative = Path(
        "var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSB.dylib")
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise ValueError("paid Crane has no regular CraneSB.dylib")
    original_hash = _sha256(path)
    specification = CRANE_IOS27_SPRINGBOARD_SUBTITLE_PATCHES.get(original_hash)
    if specification is None:
        raise ValueError(
            "paid CraneSB differs from the reviewed iOS 27 menu-subtitle adapter")

    payload = bytearray(path.read_bytes())
    if len(payload) < 8 or struct.unpack_from(">I", payload)[0] != 0xCAFEBABE:
        raise ValueError("reviewed CraneSB is not the expected fat Mach-O")
    slice_count = struct.unpack_from(">I", payload, 4)[0]
    if slice_count != len(specification):
        raise ValueError("reviewed CraneSB slice count changed")
    observed = set()
    for index in range(slice_count):
        header = 8 + index * 20
        if header + 20 > len(payload):
            raise ValueError("truncated CraneSB fat header")
        cpu_type, cpu_subtype, slice_offset, slice_size, _ = struct.unpack_from(
            ">iiIII", payload, header)
        subtype = cpu_subtype & ARM64_SUBTYPE_MASK
        rules = specification.get(subtype)
        if cpu_type != ARM64_CPU_TYPE or rules is None or subtype in observed:
            raise ValueError("unexpected CraneSB architecture")
        observed.add(subtype)
        for rule in rules:
            patch_offset = rule["offset"]
            absolute = slice_offset + patch_offset
            if patch_offset + 4 > slice_size or absolute + 4 > len(payload):
                raise ValueError("CraneSB subtitle patch is outside its slice")
            current = struct.unpack_from("<I", payload, absolute)[0]
            if current != rule["expected"]:
                raise ValueError("CraneSB subtitle method-list selector changed")
            struct.pack_into("<I", payload, absolute, rule["replacement"])
    if observed != set(specification):
        raise ValueError("CraneSB is missing a reviewed architecture")
    path.write_bytes(payload)
    path.chmod(0o755)
    adapted_hash = _sha256(path)
    if adapted_hash != "fced01a6d7bf59a1a5ac90842f1e7cb0e8e83ae66e5e7612f6faf12115c83e1f":
        raise ValueError("CraneSB menu-subtitle adaptation differs from reviewed bytes")
    return [{
        "adapter": "ios27-native-menu-subtitle-v1",
        "path": "/" + relative.as_posix(),
        "original_sha256": original_hash,
        "adapted_sha256": adapted_hash,
        "change": "use inherited UIMenuElement subtitle storage for CRSubtitleMenu",
        "reason": ("iOS 27 renders copied context-menu subtitles from UIKit's "
                   "native menu-element state"),
    }]


def _sign_crane_library_ios27(root: Path, package: str) -> list[dict]:
    """Produce the exact trust-cached libcrane bytes used by iOS 27 SRDs.

    Sandboxed injection into cfprefsd requires the on-disk dependency and the
    sealed runtime manifest to name the same CodeDirectory bytes. Reinstalling
    upstream Crane used to restore its unsigned library after runtime creation,
    making the otherwise valid CraneSupport injection fail closed. The command
    below is deterministic for this exact reviewed input and uses no identity or
    timestamp.
    """
    if package != "com.opa334.crane":
        return []
    relative = Path("var/jb/usr/lib/libcrane.dylib")
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise ValueError("paid Crane has no regular libcrane.dylib")
    original_hash = _sha256(path)
    if original_hash != CRANE_IOS27_LIBCRANE_SOURCE_SHA256:
        raise ValueError("paid libcrane differs from the reviewed iOS 27 signing adapter")
    completed = subprocess.run(
        ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
         "--identifier", CRANE_IOS27_LIBCRANE_IDENTIFIER, str(path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False,
    )
    if completed.returncode:
        raise ValueError("paid libcrane deterministic signing failed: " +
                         completed.stderr.decode("utf-8", "replace")[-500:])
    adapted_hash = _sha256(path)
    if adapted_hash != CRANE_IOS27_LIBCRANE_SIGNED_SHA256:
        raise ValueError("paid libcrane signing output differs from the reviewed bytes")
    verified = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False,
    )
    if verified.returncode:
        raise ValueError("paid libcrane signed output did not verify")
    return [{
        "adapter": "ios27-rootless-support-signing-v1",
        "path": "/" + relative.as_posix(),
        "original_sha256": original_hash,
        "adapted_sha256": adapted_hash,
        "change": "deterministic ad-hoc signature for the rootless support library",
        "reason": ("sandboxed iOS 27 daemon injection requires the dependency bytes "
                   "to match the active SRD trust-cache generation"),
    }]


def _build_crane_springboard_compat_ios27(root: Path, package: str) -> list[dict]:
    """Build the exact iOS 27 menu diagnostic companion for paid Crane."""
    if package != "com.opa334.crane":
        return []
    source = Path(__file__).with_name("shims") / "crane_springboard_ios27.m"
    if (not source.is_file() or source.is_symlink() or
            _sha256(source) != CRANE_IOS27_SPRINGBOARD_COMPAT_SOURCE_SHA256):
        raise ValueError("Crane SpringBoard compatibility source differs")
    destination = (root / "var/jb/Library/MobileSubstrate/DynamicLibraries/"
                   "CraneSBCompat.dylib")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="0sky-crane-sb-", dir=root) as temporary:
        work = Path(temporary)
        sdk_result = subprocess.run(
            ["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30, check=False)
        if sdk_result.returncode:
            raise ValueError("Xcode iPhoneOS SDK is required for Crane adaptation")
        sdk = sdk_result.stdout.decode("utf-8", "strict").strip()
        slices = []
        for architecture in ("arm64", "arm64e"):
            output = work / ("CraneSBCompat." + architecture + ".dylib")
            completed = subprocess.run([
                "/usr/bin/xcrun", "--sdk", "iphoneos", "clang",
                "-arch", architecture, "-isysroot", sdk,
                "-miphoneos-version-min=15.0", "-Os", "-fobjc-arc",
                "-fvisibility=hidden", "-dynamiclib", "-Wl,-dead_strip",
                "-install_name",
                ("/var/jb/Library/MobileSubstrate/DynamicLibraries/"
                 "CraneSBCompat.dylib"),
                "-framework", "Foundation", str(source), "-o", str(output),
            ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE, timeout=120, check=False)
            if completed.returncode:
                raise ValueError("Crane SpringBoard compatibility build failed: " +
                                 completed.stderr.decode("utf-8", "replace")[-500:])
            slices.append(output)
        combined = work / "CraneSBCompat.dylib"
        completed = subprocess.run(
            ["/usr/bin/xcrun", "lipo", "-create", *(str(item) for item in slices),
             "-output", str(combined)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30, check=False)
        if completed.returncode:
            raise ValueError("Crane SpringBoard compatibility lipo failed")
        completed = subprocess.run([
            "/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
            "--identifier", "codes.openai.research.crane-springboard-compat",
            str(combined),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
           stderr=subprocess.PIPE, timeout=30, check=False)
        if completed.returncode:
            raise ValueError("Crane SpringBoard compatibility signing failed")
        try:
            slices = macho.parse(combined)
        except (OSError, ValueError) as error:
            raise ValueError("Crane SpringBoard compatibility Mach-O is invalid") from error
        if ({item.get("architecture") for item in slices} != {"arm64", "arm64e"}
                or any(not item.get("uuid") for item in slices)):
            raise ValueError(
                "Crane SpringBoard compatibility requires UUID-bearing arm64 slices")
        if _sha256(combined) != CRANE_IOS27_SPRINGBOARD_COMPAT_SHA256:
            raise ValueError("Crane SpringBoard compatibility output differs")
        destination.write_bytes(combined.read_bytes())
    destination.chmod(0o755)
    filter_path = destination.with_suffix(".plist")
    filter_path.write_bytes(plistlib.dumps(
        {"Filter": {"Bundles": ["com.apple.springboard"]}},
        fmt=plistlib.FMT_XML, sort_keys=True))
    filter_path.chmod(0o644)
    if _sha256(filter_path) != CRANE_IOS27_SPRINGBOARD_COMPAT_FILTER_SHA256:
        raise ValueError("Crane SpringBoard compatibility filter differs")
    return [{
        "adapter": "ios27-springboard-menu-children-v6",
        "path": "/var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSBCompat.dylib",
        "source_sha256": CRANE_IOS27_SPRINGBOARD_COMPAT_SOURCE_SHA256,
        "adapted_sha256": CRANE_IOS27_SPRINGBOARD_COMPAT_SHA256,
        "filter_sha256": CRANE_IOS27_SPRINGBOARD_COMPAT_FILTER_SHA256,
        "change": "replace the sentinel in UIMenu children using Crane's reviewed menu builder",
        "reason": ("iOS 27 bypasses Crane's legacy private menu-construction hooks "
                   "after producing a title-based container-selection sentinel"),
    }]


def _package_name(root: Path) -> str:
    try:
        _, _, fields = metadata(root)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return ""
    return str(fields.get("Package", ""))


def _reviewed_maintainer_adapter(root: Path, package: str) -> tuple[list[dict], list[str]]:
    control = root / "DEBIAN"
    if not control.is_dir():
        return [], []
    scripts = sorted(path for path in control.iterdir() if path.name != "control")
    if not scripts:
        return [], []
    if package not in CRANE_PACKAGES:
        return [], ["maintainer scripts require a reviewed typed adapter: " +
                    ", ".join(path.name for path in scripts)]
    expected_names = {"postinst", "prerm", "postrm"}
    if {path.name for path in scripts} != expected_names:
        return [], ["Crane maintainer-script set differs from the reviewed adapter"]
    records = []
    for path in scripts:
        digest = _sha256(path)
        if digest not in CRANE_SCRIPT_HASHES.get(path.name, set()):
            return [], ["Crane " + path.name +
                        " differs from every reviewed typed-script fingerprint"]
        records.append({"name": path.name, "sha256": digest})
    return records, []


def _reviewed_crane_service(root: Path, package: str) -> tuple[list[dict], list[str]]:
    services = sorted(path for path in root.rglob("*.plist")
                      if "/LaunchDaemons/" in "/" + path.relative_to(root).as_posix())
    if not services:
        return [], []
    if package not in CRANE_PACKAGES or len(services) != 1:
        return [], ["daemon-backed tweak requires a service adapter: " +
                    ", ".join(path.relative_to(root).as_posix() for path in services)]
    path = services[0]
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, ValueError, plistlib.InvalidFileException):
        return [], ["Crane service definition is invalid"]
    program = value.get("Program")
    mach_services = value.get("MachServices")
    if (value.get("Label") != CRANE_SERVICE["label"] or
            program != CRANE_SERVICE["program"] or
            value.get("UserName") != "root" or
            value.get("RunAtLoad") is not True or
            value.get("KeepAlive") is not True or
            not isinstance(mach_services, dict) or
            sorted(name for name, enabled in mach_services.items() if enabled is True) !=
            CRANE_SERVICE["mach_services"]):
        return [], ["Crane service definition differs from the reviewed service adapter"]
    program_path = root / program.lstrip("/")
    if (not program_path.is_file() or program_path.is_symlink() or
            not program_path.stat().st_mode & 0o111):
        return [], ["Crane service executable is absent or not executable"]
    return [{"label": CRANE_SERVICE["label"], "program": program,
             "plist": "/" + path.relative_to(root).as_posix(),
             "mach_services": CRANE_SERVICE["mach_services"]}], []


def _shape(root: Path) -> tuple[list[dict], list[str]]:
    dylibs = []
    blockers = []
    package = _package_name(root)
    _, script_blockers = _reviewed_maintainer_adapter(root, package)
    _, service_blockers = _reviewed_crane_service(root, package)
    blockers.extend(script_blockers)
    blockers.extend(service_blockers)
    for path in root.rglob("*"):
        if path.is_symlink():
            blockers.append("symbolic package payload requires a reviewed adapter: " +
                            path.relative_to(root).as_posix())
            continue
        relative = path.relative_to(root).as_posix()
        if not (path.is_file() and path.suffix.lower() == ".dylib"):
            continue
        if not relative.startswith(INJECTION_ROOTS):
            if (relative.startswith("var/jb/usr/lib/") and
                    "/" not in relative.removeprefix("var/jb/usr/lib/")):
                # A package-owned support library is trust-cached with the
                # entry-point tweaks by the runtime synchronizer.
                continue
            blockers.append("tweak dylib is outside the measured rootless injection layout: " +
                            relative)
            continue
        filter_path = path.with_suffix(".plist")
        if not filter_path.is_file() or filter_path.is_symlink():
            blockers.append("tweak dylib has no adjacent filter plist: " + relative)
            continue
        try:
            scope = _filter(filter_path)
        except ValueError as error:
            blockers.append(relative + ": " + str(error))
            continue
        dylibs.append({"path": relative,
                       "filter": filter_path.relative_to(root).as_posix(),
                       "scope": scope})
    if not dylibs:
        blockers.append("no scoped rootless tweak dylib was found")
    return dylibs, blockers


def adapt_verified_deb(source, destination_directory, *,
                       dpkg_deb="/var/jb/usr/bin/dpkg-deb") -> dict:
    """Build a derivative DEB for a reviewed typed adapter.

    The upstream archive remains byte-for-byte unchanged.  Crane's legacy
    shell lifecycle is replaced by a declarative manifest consumed by the
    transactional Bridge after code authorization.  An unfamiliar script or
    service definition fails closed before a derivative is built.
    """
    source = Path(source)
    destination_directory = Path(destination_directory)
    with tempfile.TemporaryDirectory(prefix="0sky-tweak-adapt-",
                                     dir=destination_directory) as temporary:
        root = Path(temporary) / "root"
        completed = subprocess.run(
            [dpkg_deb, "--raw-extract", str(source), str(root)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=120, check=False)
        if completed.returncode:
            raise RuntimeError("unable to extract verified package for adaptation")
        package = _package_name(root)
        scripts, script_blockers = _reviewed_maintainer_adapter(root, package)
        services, service_blockers = _reviewed_crane_service(root, package)
        blockers = script_blockers + service_blockers
        if blockers or not scripts or not services:
            raise ValueError("; ".join(blockers or
                             ["package has no reviewed transformation plan"]))
        original_hash = _sha256(source)
        control = root / "DEBIAN/control"
        fields = control.read_text(encoding="utf-8")
        if "X-0-Sky-" in fields:
            raise ValueError("package already contains untrusted 0-Sky adaptation metadata")
        control.write_text(fields.rstrip() +
            "\nX-0-Sky-Adapter: crane-family-v2\n" +
            "X-0-Sky-Original-SHA256: " + original_hash + "\n",
            encoding="utf-8")
        for record in scripts:
            path = root / "DEBIAN" / record["name"]
            path.write_text("#!/bin/sh\n# Lifecycle translated by 0-Sky crane-family-v2.\nexit 0\n",
                            encoding="utf-8")
            path.chmod(0o755)
        legacy_starter = root / "var/jb/usr/local/bin/cranehelperd_start"
        if (legacy_starter.is_symlink() or not legacy_starter.is_file()
                or not os.access(legacy_starter, os.X_OK)):
            raise ValueError("Crane legacy helper launcher differs from the reviewed adapter")
        original_starter_hash = _sha256(legacy_starter)
        legacy_starter.write_bytes(CRANE_STARTER_ADAPTER)
        legacy_starter.chmod(0o755)
        compatibility_components = [{
            "path": CRANE_STARTER_PATH,
            "original_sha256": original_starter_hash,
            "adapted_sha256": _sha256(legacy_starter),
            "adapter": "srd-service-starter-v1",
            "behavior": "defer-to-transactional-service-backend",
        }]
        binary_transformations = (_adapt_crane_springboard_subtitles_ios27(root, package) +
                                  _adapt_crane_support_ios27(root, package) +
                                  _sign_crane_library_ios27(root, package) +
                                  _build_crane_springboard_compat_ios27(root, package))
        manifest_path = root / "var/jb/usr/share/0-sky/package-adapters" / (package + ".json")
        manifest_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        manifest = {
            "schema": 1,
            "adapter": "crane-family-v2",
            "package": package,
            "original_sha256": original_hash,
            "suppressed_scripts": scripts,
            "compatibility_components": compatibility_components,
            "binary_transformations": binary_transformations,
            "applications": ([{
                "path": "/var/jb/Applications/CraneApplication.app",
                "bundle_identifier": "com.opa334.CraneApplication",
                "role": "hidden-companion",
                "launch_validation": "controlled-exit-v1",
                "original_executable_sha256": (
                    "485210d727140983493be0b7fc9cbcc724b8c696dc5becd86af9d6b2bb5289e6"
                ),
            }] if package == "com.opa334.crane" else []),
            "permissions": [
                {"path": "/var/jb/usr/local/libexec/cranehelperd",
                 "uid": 0, "gid": 0, "mode": "0755"},
                {"path": CRANE_STARTER_PATH,
                 "uid": 0, "gid": 0, "mode": "0755"},
            ],
            "services": services,
            "runtime": _crane_runtime_contract(package),
        }
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n",
                                 encoding="utf-8")
        manifest_path.chmod(0o644)
        fd, output_name = tempfile.mkstemp(prefix=".0sky-adapted-", suffix=".deb",
                                           dir=destination_directory)
        os.close(fd)
        output = Path(output_name)
        output.unlink()
        try:
            build_environment = os.environ.copy()
            # dpkg-deb otherwise records the current time in the ar and tar
            # members.  The transformed payload is content-addressed, so the
            # same verified input and adapter revision must produce the same
            # derivative bytes on every run.
            build_environment["SOURCE_DATE_EPOCH"] = str(REPRODUCIBLE_ARCHIVE_EPOCH)
            built = subprocess.run(
                [dpkg_deb, "--build", "--root-owner-group", str(root), str(output)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=180, check=False,
                env=build_environment)
            if built.returncode or not output.is_file():
                raise RuntimeError("unable to build reviewed package adaptation")
            output.chmod(0o600)
            return {"path": output, "original_sha256": original_hash,
                    "adapted_sha256": _sha256(output), "manifest": manifest}
        except Exception:
            output.unlink(missing_ok=True)
            raise


def analyze_verified_deb(source, *, state=None, environment=None,
                         dpkg_deb="/var/jb/usr/bin/dpkg-deb") -> dict:
    """Analyze and admit a verified tweak for transactional install and test.

    The result authorizes only the next bounded transaction stage.  It never
    claims runtime compatibility before injection evidence exists.
    """
    env = environment or detect()
    engine = Engine(Path(state) if state else default_state(), env)
    report, root, work = engine.evaluate(source, dpkg_deb=dpkg_deb)
    try:
        _, _, fields = metadata(root)
    except (OSError, ValueError, plistlib.InvalidFileException):
        fields = {}
    section = str(fields.get("Section", "")).lower()
    dependencies = str(fields.get("Pre-Depends", "")) + "," + str(fields.get("Depends", ""))
    dependency_names = {name for group in _dependency_groups(dependencies) for name in group}
    is_tweak = section.startswith("tweak") or bool(
        dependency_names & {"mobilesubstrate", "cydiasubstrate", "ellekit",
                            "substitute", "libhooker"})
    if not is_tweak:
        return {"is_tweak": False, "admission": "NOT_APPLICABLE",
                "registry_key": report.key,
                "compatibility_state": report.compatibility_state}

    dylibs, blockers = _shape(root)
    package_name = str(fields.get("Package", ""))
    script_adapter, _ = _reviewed_maintainer_adapter(root, package_name)
    service_adapter, _ = _reviewed_crane_service(root, package_name)
    issue_codes = {item["code"] for item in report.issues
                   if item.get("severity") == "mandatory"}
    hard = next((code for code in HARD_BLOCKERS if code in issue_codes), None)
    if hard:
        blockers.append("static analysis: " + hard)

    aliases = []
    missing = []
    for group in _dependency_groups(dependencies):
        choices = [_dependency_available(env, name) for name in group]
        if not any(item[0] for item in choices):
            # Signed APT planning may install ordinary dependencies, but an
            # injection provider must already be measured before tweak install.
            if any(name in DEPENDENCY_ALIASES or name in
                   {"ellekit", "substitute", "libhooker"} for name in group):
                missing.append(" | ".join(group))
        aliases.extend(item[1] for item in choices if item[1])
    if missing:
        blockers.append("missing measured injection dependency: " + ", ".join(missing))

    if blockers:
        state_value = HARD_BLOCKERS.get(hard, "BLOCKED_BY_DEPENDENCY"
                                        if missing else "ADAPTATION_REQUIRED")
        report.set_compatibility(state_value, "CLASSIFY",
                                 "; ".join(blockers)[:2048])
        report.status = legacy_status(state_value)
        for detail in blockers:
            report.add("TWEAK_ADMISSION_BLOCKED", "", detail,
                       "mandatory" if state_value.startswith("BLOCKED_BY_") else "unknown")
        engine.save(report, work)
        return {"is_tweak": True, "admission": "BLOCKED",
                "registry_key": report.key, "source_hash": report.source_hash,
                "compatibility_state": state_value, "blockers": blockers,
                "dylibs": dylibs, "adapters": sorted(set(aliases))}

    adapters = aliases + ["srd-runtime-signing", "rootless-tweak-v1"]
    if script_adapter:
        adapters.append("maintainer-script-translation-v1")
    if service_adapter:
        adapters.append("srd-service-backend-v1")
    adapters = sorted(set(adapters))
    report.adaptations.extend({"adapter": name, "source": "measured-srd-profile"}
                              for name in adapters)
    report.set_compatibility("TESTING", "INSTALL",
                             "static admission passed; runtime injection and rollback remain mandatory")
    report.status = "UNKNOWN"
    engine.save(report, work)
    return {"is_tweak": True, "admission": "INSTALL_AND_TEST",
            "registry_key": report.key, "source_hash": report.source_hash,
            "compatibility_state": "TESTING", "blockers": [],
            "dylibs": dylibs, "adapters": adapters,
            "requires_transformation": bool(script_adapter),
            "services": service_adapter}
