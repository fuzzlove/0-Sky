# Portability audit result

| Requirement | Result |
| --- | --- |
| Hard-coded paths removed | Named host fallback, fixed Xcode probe paths, and fixed `idevicepair` diagnostic paths removed. Remaining `/opt/homebrew` and `/usr/local` locations are discovery candidates. |
| Developer identifiers removed | Tracked source and new source-only files pass `tools/pii_audit.py`. The external kit still contains 12 signed binaries with home-directory build paths. |
| Machine-specific assumptions removed | Repo/bundle roots derive from file location; user support paths derive from the active account; active Xcode is resolved with `xcrun`. |
| Device-specific assumptions removed | Exact UDID selection and per-device state are required; Cryptex helper scripts no longer pick the only attached device. |
| Secrets detected | No tracked-source secrets found by the automated audit. The release gate checks staged files and embedded IPA text. |
| Secrets remediated | No private key or password was copied into source. Local kit and generated credentials are ignored by Git. |
| Configuration centralized | `bridge/zero_sky_user_config.py` is the authoritative per-user reader, with CLI > file > environment > discovery > default precedence. |
| Runtime discovery implemented | Read-only `tools/environment_preflight.py` reports host, architecture/Rosetta, kit, toolchain, configuration, device selection, and signing input. |
| Tool discovery implemented | PATH and bounded version checks on host; Xcode tools via the active `xcrun`. |
| Capability detection implemented | Required and optional dependencies have distinct failure/degraded states; exact-device CoreDevice probe is bounded. |
| Release sanitization implemented | Manifest-verified staging, source-controlled installer overrides, nested IPA and binary-string scanning, custom deny patterns, and an app-wide fail-closed gate. |
| Clean-build test | Build from an unrelated working directory succeeded before the deeper binary gate. With the complete gate, the supplied external kit is correctly rejected. A source-only checkout reports the missing kit explicitly. |
| Regression tests | 34 Python tool tests, 22 Python host-tool tests, and 33 Swift BridgeCore tests passed; shell/Python syntax and source PII checks passed. |
| Remaining exceptions | A clean checkout cannot produce a full SRD installer without authorized external kit, Apple assets, and publisher signing. The current external kit must replace 12 signed payloads; Intel execution and the iOS 17–27+ device matrix remain untested here. |

**Final status: PARTIAL.** First failing release transition:
`RELEASE_KIT_SANITIZATION → fixed-home-path in signed external Frida/PreferenceLoader binaries`.
The gate emits only file basenames and categories. No device/bootstrap changes
were made during this portability pass.
