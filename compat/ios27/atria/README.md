# Atria iOS 27 compatibility port

This directory rebuilds Atria 1.4.1 from the public GPL-3.0 source at the
immutable upstream commit `f9668422b7f7143ac8d038feb05199fe4690d792`.

## Acceptance criteria

- Target: iPhone 12 SRD (`iPhone13,2`), iOS 27.0 build `24A5390f`.
- Architectures: `arm64` and `arm64e`; rootless package layout under `/var/jb`.
- Toolchain: Xcode iPhoneOS 26.5 SDK and the repository-pinned Theos checkout.
- Package: `me.lau.atria`, replacing upstream 1.4.1 without deleting its
  preference domain (`me.lau.AtriaPrefs`).
- Runtime entry point: ElleKit/CydiaSubstrate injection into SpringBoard.
- First milestone: SpringBoard survives Atria injection, no Atria quarantine is
  created, Settings loads `AtriaPrefs.bundle`, and the layout editor opens from
  an icon shortcut or triple tap.
- Functional UAT: make and reverse one layout change, then confirm SpringBoard
  remains stable. A build alone is not a runtime verification.

## Diagnosed failure

The upstream 1.4.1 binary was quarantined after SpringBoard terminated during
injection on 2026-10-01. The matching crash is an
`NSInvalidArgumentException`:

```text
-[SBIconController _rootFolderController]: unrecognized selector
```

On the exact target build, `SBIconController` is an `NSObject`, not a
`UIViewController`. Its `iconManager` returns `SBHIconManager`, which exposes
`rootFolderController` and `rootViewController`. The patch uses the legacy API
only when it exists, otherwise obtains `SBRootFolderController` from the icon
manager. It also uses that controller for editor/splash presentation and makes
the root-list lookup nil-safe.

Two later compatibility failures were also reproduced on the exact target and
remain part of the evidence rather than being described as working:

- `1.4.1+0sky27.1` sent the removed `application` selector to `SBWidgetIcon`
  and `SBFolderIcon` during interactive use.
- `1.4.1+0sky27.2` survived that selector path, but later crashed with a
  pointer-authentication failure in `-[SBIconListModel
  gridSizeClassSizesWithOptions:]`. The old `GridLayout.xm` path wrote iOS
  13–16 private grid structs directly into SpringBoard ivars. Build `.3` skips
  those legacy ABI hooks on iOS 17 and later while retaining the copied
  layout-configuration path in `MainLayout.xm`.

The port also replaces the preference bundle's root descriptor with a native,
data-only iOS 27 page. It contains only controls that 0-Sky Control hosts
without loading third-party preference code: groups, switches, segmented
choices, and text fields. Preference writes remain scoped to
`me.lau.AtriaPrefs`, and Atria observes the matching
`me.lau.AtriaPrefs/ReloadPrefs` Darwin notification.

## Build

```sh
compat/ios27/atria/build.sh --dry-run
compat/ios27/atria/build.sh
```

The script clones only the pinned upstream commit into `.build`, verifies the
commit and tree, applies the numbered patch, overlays the reconstructed Theos
project, performs a clean build, normalizes package ownership and timestamps,
and validates the DEB. Two consecutive clean builds produce the same final DEB
SHA-256. The output remains an untracked build artifact under
`.build/atria-ios27/output/`.

The build does not install or restart SpringBoard. Installation and runtime
testing require an explicitly selected, backed-up SRD and an operator-approved
device-changing step.

## Current status

- Source diagnosis: **verified** on iOS 27.0 build `24A5390f`.
- Clean host build/package validation: **passed**.
- Compatibility build `1.4.1+0sky27.1`: **failed and quarantined during
  functional testing**. It fixed `_rootFolderController`, but icon-view setup
  still sent the removed `application` selector to `SBWidgetIcon` and
  `SBFolderIcon`.
- Compatibility build `1.4.1+0sky27.2`: **failed on the exact target**. Its
  installed dylib produced an `EXC_BAD_ACCESS` / possible pointer-
  authentication failure while SpringBoard queried grid-size class data.
- Compatibility build `1.4.1+0sky27.3`: **clean host build, deterministic
  package validation, and package installation passed; runtime test pending**.
  The runtime renewal did not commit because both Apple RemoteXPC transports
  timed out before the new Cryptex could be installed. The device was kept at
  the explicit runtime-pause recovery point and restarted, then disconnected
  from USB. The `.3` dylib has therefore not been injected or described as
  working. A different connected SRD was not substituted for the pinned
  hardware/build target.
- Native iOS 27 preferences: **installed and structurally validated**. Runtime
  display/write verification remains pending with the `.3` target test.
- Editor functional UAT: **pending**. A researcher must still open the editor,
  make and reverse one layout change, and confirm the final visual state.
- Upstream 1.4.1: **failed**. Captured crashes load the upstream dylib SHA-256
  `f8d84a5c1917f50e4e18e5ba53f210ae3912d32645627318f096ac9900f88686`
  and show the exact removed-selector exception above. Those reports are not
  evidence that the compatibility dylib failed.

The prior DEB and its failed device result remain recorded in
`validation/device-validation-24A5390f.json`. Device identifiers, pairing
material, signing keys, and raw crash reports are deliberately excluded.

The first runtime renewal exposed stale, device-local Crane enrollment hashes.
The operator reconciled those hashes only after the currently mounted and
registered Crane bundles were byte-for-byte equal and passed strict host
codesign verification. The retry used the repository virtual environment so
the native installer had its pinned Python dependencies. This is device-state
repair evidence, not an Atria source dependency and not a reason to weaken any
runtime validation.

The patch deliberately retains legacy fallbacks and does not claim that every
iOS 13-16 private API remains functional on iOS 27. Missing floating-dock hooks
are non-applicable to the iPhone 12 target; broader device support remains
untested.
