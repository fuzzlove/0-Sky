# Jellyfish iOS 27 compatibility implementation

This directory contains a clean-room compatibility implementation of the
observable Jellyfish 1.6.5 lock-screen behavior. The original CyPwn DEB is a
proprietary binary and is neither copied into this repository nor treated as
reconstructable source. Its URL and SHA-256 are recorded in `source.json` only
to make the interoperability analysis auditable.

## Target and safety boundary

- Target: iPhone 12 SRD (`iPhone13,2`), iOS 27.0 build `24A5390f`.
- Architectures: `arm64` and `arm64e`, installed through the rootless
  `/var/jb` package layout.
- Injection target: SpringBoard only.
- Runtime guard: the hook is installed only when both the exact build and the
  `SBFLockScreenDateView` `layoutSubviews` method are present.
- Preference domain: `xyz.royalapps.jellyfish`.
- Native preference bundle: `Jellyfish27Preferences.bundle`, linked to Apple's
  Preferences framework and limited to standard iOS preference cells.

The package is disabled by default. Enabling it is an explicit preference
write; the preference page posts the scoped Darwin notification
`xyz.royalapps.jellyfish.changed` so SpringBoard can relayout without a
respring.

## Native iOS 27 preferences

The preference page is a real, signed `PSListController` bundle rather than a
redirect to General settings or a data-only placeholder. It supplies standard
native controls for:

- enable/disable;
- left, center, or right alignment;
- text size and edge padding;
- custom date format;
- text shadow; and
- battery percentage display.

All editable rows use the same scoped preference domain and notification. No
row names a third-party custom cell class.

## Reproducible build

Prerequisites are Xcode with the iPhoneOS 26.5 SDK, the repository-pinned Theos
checkout, `dpkg-deb`, `ldid`, and standard macOS command-line tools.

```sh
compat/ios27/jellyfish/build.sh --dry-run
compat/ios27/jellyfish/build.sh
```

The build output is written to:

```text
.build/jellyfish-ios27/output/xyz.cypwn.jellyfish_1.6.5+0sky27.7_iphoneos-arm64.deb
```

The build script never installs a package or changes a device. It rebuilds from
the tracked clean-room source, normalizes package timestamps and ownership, and
runs the offline validator.

## Verified state

Package `1.6.5+0sky27.3` verified the native preference menu and stable
injection, but produced no confirmed visible lock-screen change. Runtime class
metadata showed why: iOS 27 uses `SBUILegibilityLabel` wrapper views, while that
build searched only for descendant `UILabel` objects. Builds `0sky27.4` and
`0sky27.5` targeted those wrappers, but a real lock-screen capture proved the
active iOS 27 path is the CoverSheet `CSProminentDisplayView`, not the legacy
date view. Build `0sky27.7` hooks that exact prominent-display path, its native
title-label protocol, and its date-string method while retaining the legacy
path for compact layouts. Device results are recorded separately in the
validation manifest.

The settings layer and the `0sky27.7` lock-screen visual path are **verified**
on build `24A5390f`. The acceptance capture showed the configured custom date,
battery percentage, left alignment, and 115% clock scale. Device-specific
evidence and prior failed or superseded variants are recorded in the validation
manifest; the screenshot itself remains outside Git because it contains a
device wallpaper and other operator-controlled visual state.

The sanitized device evidence is in
`validation/device-validation-24A5390f.json`. It deliberately excludes device
identifiers, pairing material, keys, and raw crash reports.
