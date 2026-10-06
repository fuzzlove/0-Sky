# 0-Sky iOS 26 Compatibility and Rebuild Notes

Last validated: 2026-10-04

## Validated device matrix

| Role | Hardware | OS | Build | Darwin | Stable 0-Sky baseline |
| --- | --- | --- | --- | --- | --- |
| iOS 26 target | iPhone 15 (`iPhone15,4`) | 26.0 | `23A341` | 25 | Control 3.5.36, Link 1.9.0 (48), Runtime Manager 2.4.20, ElleKit 1.2, PreferenceLoader 2.4.3-1+debug, CatVNC 0.0.2 |
| Behavioral reference | iPhone 12 | 27.0 | `24A5390f` | 26 | Control 3.5.36, Link 1.9.0 (48), Runtime Manager 2.4.20, ElleKit 1.2, PreferenceLoader 2.4.3-1+debug, CatVNC 0.0.2 |

Match application and manager versions where their interfaces are shared. Do **not** copy exact-build system binaries, hooks, offsets, or iOS 27 runtime payloads onto iOS 26 merely to make the version table match.

## App registration on iOS 26.0

- An app registered directly from a randomized Cryptex mount can leave an icon-only placeholder or a stale LaunchServices URL after a same-identifier replacement.
- A stable installation needs an MCM-backed path under `/private/var/containers/Bundle/Application/<UUID>/...`, not a persisted randomized Cryptex suffix.
- iOS 26.0 uses the legacy CoreServices MCM-copy path reliably when InstallCoordination is disabled. The working registrar environment was:
  - `APPREGISTRARD_DISABLE_INSTALLCOORDINATION=1`
  - `APPREGISTRARD_RESCAN_ON_START=1`
- When an exact `23A341` `srdinstalld`/hook set is unavailable, use the daemon-only registrar built for a minimum OS of 26.0. Do not inject `srdinstalld` or AppRegistrar hooks taken from `23H24`, `24A437`, or `24A5390f`.
- iOS 27 can use the newer InstallCoordination/User registration path; that behavior should not be assumed on iOS 26.0.
- After replacing an app Cryptex, treat the first `uicache -i` result as provisional. Retry for a bounded interval, require the returned path to exist, and compare the executable/package hashes before declaring success. A 45-second bounded retry fixed the observed iOS 26 stale-URL race.
- Never store or compile the randomized suffix from `/private/var/run/com.apple.security.cryptexd/mnt/<identifier>.<random>`.

## Personalization, nonce, and transport

- Use the complete `install_cryptex_native.py` flow with `--transport auto`.
- Personalize against the exact UDID and a fresh domain-3 research nonce, and obtain a live TSS ticket for each replacement when the nonce changes.
- `img4_chip_rsch=0` is not a blocker. This session successfully authorized and installed with the research identifier present and value `0`.
- The verified authorization basis was `exact-udid+fresh-domain3-nonce+live-tss-ticket`.
- Intel macOS may fail to establish the preferred native `remoted` route. The userspace USB fallback worked and must remain available.
- The current installer selects the GenericDmg image index by OS family: index 9 for iOS 26.0 through 26.3 and index 10 beginning with iOS 26.4. Re-check the local Apple manifest before changing this rule.

## Runtime and tweak compatibility

- Keep `normalize_ios27_preference_cells=false` on iOS 26.0.
- Filter safe executable and system-bundle maps to paths present on the target build. Do not assume an iOS 27 process path exists on iOS 26.
- Rebuild and replace the runtime Cryptex whenever the installed tweak/package set changes. The inventory alone does not make new dylibs, executables, or preference files part of the sealed generation.
- Preserve iOS-specific ElleKit, PreferenceLoader, companion libraries, and trust-cache inputs. Shared package version numbers do not imply byte-for-byte cross-build compatibility.
- Validate an installed tweak by observing the requested image in the target process. Package installation and inventory enumeration by themselves are not proof of a successful `dlopen`.
- PreferenceLoader injection into iOS 26 Settings was verified with the W^X-safe pthread/dlopen path and the target remained alive.
- A synthetic runtime test package enumerated correctly but did not load. It was removed instead of being left in a misleading or unstable state.

## CatVNC menu rule

- CatVNC 0.0.2 uses a **direct-plist** PreferenceLoader pane:
  `/var/jb/Library/PreferenceLoader/Preferences/catvnc/Preferences.plist`.
- Its descriptor contains `entry` plus inline `items` (`Enabled` and `Password`) and intentionally has no `entry.bundle`.
- A runtime sync that copies descriptors only when `entry.bundle` is present silently drops CatVNC from the sealed Cryptex. Copy every inventory-approved descriptor first; copy a PreferenceBundle additionally only when `entry.bundle` exists.
- After the fix, require all of the following before reporting the menu ready:
  1. The CatVNC package is `install ok installed`.
  2. The mounted runtime contains `Library/PreferenceLoader/Preferences/catvnc/Preferences.plist`.
  3. Control inventory reports `preference_title: CatVNC` and `settings_available: true`.
  4. PreferenceLoader injects successfully into the current Settings process.
  5. The CatVNC service is running from the current runtime mount.
- On iOS 26.0 the CatVNC image loaded in SpringBoard, while its backboardd attempt was rejected without killing backboardd and was quarantined per target. Do not equate the working menu/server with proof that every optional hook loaded; keep this target-specific failure visible in diagnostics.

## Rebuild/tool snapshot integrity

- Deploy a complete, matching automation snapshot. A newer `sync_runtime_cryptex.py` can depend on new source files (for example sandboxed-injector sources); replacing that one script without its companion files can make rebuilds fail before installation.
- If a field fix is required, patch the deployed generation narrowly and retain the previous script under the instance backup directory. Rebuild the distributable kit later from one coherent source revision.
- Ensure the Intel host build environment has `/usr/local/bin` in `PATH`; `dpkg-deb` was required during runtime generation.
- Run the installed host app from `~/Applications/0-Sky Bridge.app`. Do not use an AppTranslocation/quarantined copy, and do not allow overlapping health probes to exhaust SSH sessions.

## Rebuild validation checklist

1. Record product type, OS version, build, Darwin version, UDID, and target Cryptex identifiers.
2. Confirm Control and Link resolve to live MCM paths and report the expected version/build.
3. Launch Control and Link for at least 15 seconds and check for new crash reports.
4. Confirm the registrar, runtime manager, bridge/keeper services, and current runtime mount are alive.
5. Confirm Runtime Manager 2.4.20, ElleKit 1.2, and PreferenceLoader 2.4.3-1+debug package states.
6. Confirm each installed tweak has its dylib/filter metadata and any direct-plist or bundle-backed preference artifacts in the sealed generation.
7. Launch Settings and require a successful PreferenceLoader injection from the **current** randomized runtime mount.
8. For CatVNC, require the direct plist, `settings_available=true`, the running server, and the Enabled/Password items.
9. Preserve installer output showing the fresh nonce, live TSS ticket, transport, and final `INSTALL SUCCESS`.
10. Keep rollback artifacts and script backups, but never put passwords, private keys, pairing records, or device tokens in this document.

## Validated iOS 26 artifacts from this session

- Registrar mount identifier: `codes.rambo.research.appregistrard` (daemon-only legacy MCM registration).
- Final CatVNC-capable runtime generation:
  `runtime-generations/20261004T163941Z-ios26-catvnc-menu-final`
- Final runtime install used a fresh domain-3 nonce, a live TSS ticket, and the userspace USB transport.
- Control and Link remained registered as durable MCM applications after the runtime rebuild.

## AppSync/Cylinder/Doodle/Atria validation on iOS 26

- Validated packages on `iPhone15,4`, iOS 26.0 (`23A341`):
  - AppSync Unified `116.0+0sky26.1`
  - Cylinder Reborn `1.1.2`
  - Doodle `1:1.1+0sky27.2`
  - Atria `1.4.1+0sky27.4`
  - Alderis `1.2.3`
- A package can own more than one independently targeted injection dylib. AppSync owns both `AppSyncUnified-FrontBoard.dylib` and `AppSyncUnified-installd.dylib`; runtime inventory, signing, trust payloads, manifest generation, and verification must iterate the complete `dylibs` array rather than only the legacy primary `dylib` field.
- Every sealed tweak manifest record needs both `source_sha256` and final `sha256`. The runtime manager uses `source_sha256` to match the installed dpkg bytes and `sha256` to locate the exact trusted sealed payload. Omitting the source hash causes `SEALED_TWEAK_UNAVAILABLE` even when the final dylib is present.
- iOS 26 `installd` required the reviewed sealed `sandboxed-injector`; the ordinary W^X-safe loader could not add the AppSync image while `installd` remained alive. Keep the complete sandboxed-injector source snapshot beside the sync coordinator, build arm64 and arm64e slices, sign it with the measured loader role, record its hash in the sealed manifest, and configure `installd` with `libellekit.dylib` as a verified dependency.
- The final iOS 26 runtime proved successful injection of both AppSync components: FrontBoard into SpringBoard and the installd component into `installd` through the sealed sandboxed injector. Cylinder, Doodle, and Atria also loaded successfully into the same live SpringBoard process without a crash.
- Cylinder and Atria are bundle-backed PreferenceLoader panes. Seal their descriptors, executable bundles, Alderis framework, and `libcolorpicker.dylib`. Doodle has no separate PreferenceLoader pane and is configured through 0-Sky Control.
- The final validated runtime generation is `runtime-generations/20261004T1718Z-ios26-appsync-sourcehash-final`. Settings launched successfully, PreferenceLoader injected from that generation, all three expected tweak descriptors (CatVNC, Cylinder, and Atria) were present, and no related recent SpringBoard, Settings, installd, Atria, Cylinder, Doodle, or AppSync crash report was observed.
