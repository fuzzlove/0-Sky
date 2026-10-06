# NeoSky Background

NeoSky Background is an exact-build-guarded SpringBoard extension for the
0-Sky iOS 27 SRD environment. It presents Neofetch-style system information
behind the Home Screen icons. A separate Lock Screen path is retained as an
experimental, default-off control; it is not currently a verified feature.

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
.build/neosky-background-ios27/output/xyz.0sky.neoskybackground_1.0.0+0sky27.7_iphoneos-arm64.deb
```

The package defaults to disabled. Enable **NeoSky Background** in the native
preferences menu after installation. Home Screen visibility, text size,
opacity, vertical placement, refresh interval, logo, and color are
configurable. **Lock Screen (Experimental)** defaults to disabled.

## Validation status

- Host: two clean builds of `1.0.0+0sky27.7` were byte-identical and passed
  package, architecture, signing-input, and native-preference checks.
- Device installation and current-variant runtime validation are recorded in
  `validation/device-validation-24A5390f.json`.
- Home Screen: the implementation attaches directly to an existing exact-class
  `SBHomeScreenView` after late injection. It does not force a UIKit layout pass
  through unrelated tweak hooks.
- Lock Screen: the hook and layout diagnostics executed on the supported build,
  but repeated screenshots did not show the overlay. This path is therefore
  **unverified**, labeled experimental, and disabled by default.
- Earlier SpringBoard transition crashes symbolicated to `Atria.dylib` at
  `SBFloatingDockViewController viewDidLoad`. A later report terminated in
  SpringBoard's Continuity-display modal-library assertion without a tweak frame.
  NeoSky was not a faulting frame in either signature. This is attribution
  evidence, not a claim that the combined stack is crash-free.

The standard 0-Sky refresh entry point selected a stale Python 3.9 support
interpreter on this host while the runtime builder requires Python 3.12 or
newer. Device validation used the repository `.venv/bin/python` to run the
support copy of `sync_runtime_cryptex.py` directly; the host-selection defect
must not be hidden by disabling its version check.
