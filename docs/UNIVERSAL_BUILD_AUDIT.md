# Universal 2 release audit

## Scope and baseline

The distributable Mac product is the Swift/SwiftUI `0SkyBridge.app` built by
`bridge/0SkyBridge.xcodeproj` for macOS 15+. It includes a Swift service and a
LaunchServices helper, Python and shell resources, the versioned EULA, and an
externally supplied, manifest-verified research-device kit. `link/` and
`control/` build iOS applications; their device binaries are not Mac code.
The repo has Swift Package tests, Python tools/tests, Objective-C device code,
and one source-audit CI workflow. No public-ready signing, notarization, or
installer entry point existed at this audit baseline.

The observed unsigned local app under `.build/portable-app` contains 29
regular Mach-O files plus one device-side symlink to a Mach-O. The five
**Mac** files all report `x86_64 arm64` via `lipo`:

| Required Mac component | Location in app | Architecture |
| --- | --- | --- |
| Bridge GUI | `Contents/MacOS/0SkyBridge` | x86_64 arm64 |
| Bridge service | `Contents/MacOS/0SkyBridgeService` | x86_64 arm64 |
| LaunchServices helper | `Contents/Library/LaunchServices/0SkyBridgeHelper` | x86_64 arm64 |
| Bluetooth tunnel | `Contents/Resources/Kit/host-mac/zero-sky-bluetooth-tunnel` | x86_64 arm64 |
| Device bridge supervisor | `Contents/Resources/Kit/automation/CrypStoreAutomation/device_bridge_supervisor` | x86_64 arm64 |

The remaining 24 regular Mach-O files and one symlink are under device payload directories
(`frida/`, `srdssh/`, and `automation/PreferenceLoader/`) and contain arm64,
arm64e, or both. They target iOS/SRD and must not be relabeled as missing Intel
Mac slices. The host wheelhouse contains 117 wheels; its pinned requirements
select architecture-specific variants where necessary (including different
`cryptography` versions for Intel and Apple silicon). The verifier checks
lockfile coverage for both CPUs and the architecture/platform of 147 selected
native wheel members. A release verifier must enumerate *all* native files,
classify their platform, and fail any unexpected Mac-only architecture.

## Existing build and security behavior

`build.sh` builds with `ARCHS="arm64 x86_64"`, verifies only the GUI and one
Mac kit helper, strips the unsigned GUI's debug symbols, and scans its app.
`tools/prepare_release_kit.py` stages a checksum-verified external kit,
applies versioned script overrides, rebuilds Link, and runs a PII scan.
`tools/verify_eula.py` compares the bundled legal resources with the canonical
`bridge/0SkyBridge/Resources/Legal/` files. The app, helper, and service have
separate entitlement files; the helper and service currently have empty
entitlements. `CODE_SIGNING_ALLOWED=NO` makes `build.sh` an unsigned build, not
a public release. No notarization credentials are committed.

The updated build passes Swift/Clang source-prefix maps and strips debug
symbols from all three unsigned Mac targets before signing. An isolated Xcode
probe compiled the GUI with both `x86_64` and `arm64` slices; its kit embed
phase then failed at the expected PII gate. Copies of the GUI, service, and
helper passed the binary-string scan after `strip -S`. This is compile and
sanitization evidence, not a signed release build.

The external kit is outside Git and is admitted only through its checksum and
release manifests. Its upstream payloads retain build/debug strings and public
test fixtures. These are reported as advisories rather than confused with
runtime dependency paths or user secrets. The verifier reads Mach-O load
commands directly and blocks a real nonportable dependency/RPATH. Public test
keys are accepted only for an exact archive SHA-256, category, and member
prefix; changed bytes fail closed. A source-tree-only scan still cannot certify
the package, so the staged app and expanded installer are always scanned.

## Environment findings

| Finding | Classification | Disposition |
| --- | --- | --- |
| EULA text/version and public bundle IDs | REQUIRED_PUBLIC_METADATA | Preserve; validate copied resources. |
| Developer ID application/installer identities and notary profile | BUILD_CONFIGURATION / SECRET | Caller-supplied; never log credentials. |
| Xcode, SDK, `lipo`, `codesign`, packaging tools | RUNTIME_DISCOVERY | Resolve through PATH/`xcrun`; preflight each. |
| DerivedData, output directory, repository absolute path | DEVELOPMENT_ARTIFACT | Use explicit staging paths and audit final bytes. |
| Home paths in signed external device binaries | UPSTREAM_BUILD_ADVISORY | Preserve signatures; inspect actual load commands structurally and rebuild only if runtime portability fails. |
| Test fixture UDIDs, addresses, home paths | DEVELOPMENT_ARTIFACT | Keep out of release allowlist. |
| Device ID, SSH endpoint, local support paths | RUNTIME_DISCOVERY | Discover per device and store outside app bundle. |
| Standard `/usr/bin` Apple tools and `/var/jb` device paths | REQUIRED_PUBLIC_METADATA | Platform paths, not a developer prefix. |
| Homebrew prefix fallback candidates in setup code | RUNTIME_DISCOVERY | Validate selected tool at runtime; do not package host paths. |
| Ignored local DMGs, DerivedData, venv and external kit | DEVELOPMENT_ARTIFACT | Never package by directory glob. |

The audit is a baseline, not a certification of the ignored kit, old releases,
or untested Intel hardware. The release pipeline must fail closed until its
actual staged app and extracted package pass the gates.

## Current distribution evidence

The canonical distribution pipeline subsequently produced a four-file
Universal 2 release set. Developer ID application and installer signatures,
hardened runtime, entitlements, Gatekeeper, notary acceptance, staple
validation, embedded-kit integrity, offline wheel coverage, structural runtime
paths, and the blocking privacy scan passed. A second package-only verification
expanded the installer independently and ended `FINAL_RESULT=PASS`, including
staple validation. Runtime execution on physical Intel hardware, a clean
account install/upgrade/uninstall rehearsal, and live SRD matrix testing remain
`NOT_EXECUTED`; slice inspection is not relabeled as those hardware tests.
