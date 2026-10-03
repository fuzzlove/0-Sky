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

## Build

```sh
compat/ios27/atria/build.sh --dry-run
compat/ios27/atria/build.sh
```

The script clones only the pinned upstream commit into `.build`, verifies the
commit and tree, applies the numbered patch, overlays the reconstructed Theos
project, performs a clean build, and validates the DEB. The output remains an
untracked build artifact under `.build/atria-ios27/output/`.

The build does not install or restart SpringBoard. Installation and runtime
testing require an explicitly selected, backed-up SRD and an operator-approved
device-changing step.

## Current status

- Source diagnosis: **verified** on iOS 27.0 build `24A5390f`.
- Clean host build/package validation: **passed**.
- Package installation: **passed**. Version `1.4.1+0sky27.1` is installed on
  the selected `iPhone13,2` SRD.
- Runtime injection: **passed**. The runtime registry and injection state both
  record the installed Atria dylib SHA-256
  `2d06dfea3b50d6e1696460e5e7331cc87b2c89943f9eae13fd3fac8f134a7507`
  in SpringBoard, with no Atria quarantine. SpringBoard remained on the same
  PID for the automated stability window and no new SpringBoard crash appeared.
- Preference bundle load: **passed**. An isolated device-side `dlopen` of
  `AtriaPrefs.bundle/AtriaPrefs` completed successfully after the runtime
  trust-cache generation was renewed.
- Editor functional UAT: **pending**. A researcher must still open the editor,
  make and reverse one layout change, and confirm the final visual state.
- Upstream 1.4.1: **failed**. Captured crashes load the upstream dylib SHA-256
  `f8d84a5c1917f50e4e18e5ba53f210ae3912d32645627318f096ac9900f88686`
  and show the exact removed-selector exception above. Those reports are not
  evidence that the compatibility dylib failed.

The validated DEB has SHA-256
`c450b4e7d65b8f0f89dd2cc52305044dbb39808d32140108b141006d955e0e4c`.
See `validation/device-validation-24A5390f.json` for the sanitized automated
result. Device identifiers, pairing material, signing keys, and raw crash
reports are deliberately excluded.

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
