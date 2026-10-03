# NeoSky Background

NeoSky Background is an exact-build-guarded SpringBoard extension for the
0-Sky iOS 27 SRD environment. It presents Neofetch-style system information
behind the Home Screen icons and beneath the prominent Lock Screen content.

The extension intentionally does not start Bash or Neofetch inside
SpringBoard. The displayed fields are collected through lightweight native
Darwin APIs once per configured interval. This avoids making SpringBoard
depend on a shell, a randomized cryptex mount path, or a long-running child
process.

Supported target:

- iPhone13,2
- iOS 27.0 build `24A5390f`
- arm64 and arm64e

The runtime refuses to install hooks on any other OS build. It uses the
verified `SBHomeScreenView` and `CSProminentDisplayView` paths and writes a
small diagnostics plist without device-unique identifiers.

## Build

```sh
compat/ios27/neosky-background/build.sh
```

Output:

```text
.build/neosky-background-ios27/output/xyz.0sky.neoskybackground_1.0.0+0sky27.2_iphoneos-arm64.deb
```

The package defaults to disabled. Enable **NeoSky Background** in the native
preferences menu after installation. Home Screen and Lock Screen visibility,
text size, opacity, vertical placement, refresh interval, logo, and color are
independently configurable.

For deterministic device testing, `neoskyctl enable|disable|status` updates the
same mobile preference domain and posts the same Darwin notification as the
native preference pane.
