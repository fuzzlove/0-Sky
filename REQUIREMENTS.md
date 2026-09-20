# Build and runtime requirements

## Common security requirements

- An Apple Security Research Device, or another device the researcher is
  explicitly authorized to control.
- Device Developer Mode enabled where required.
- User approval of Apple pairing/trust prompts; no source component bypasses
  physical trust approval.
- No production pairing record, SSH key, token, password, UDID, Apple account,
  or provisioning profile should be copied into this checkout.

## 0-Sky Bridge — macOS

### Build

- macOS 15 or later.
- Xcode/Command Line Tools with Swift 6 and the macOS 15 SDK.
- Apple Silicon (`arm64`) or Intel (`x86_64`).
- Swift Package Manager.

Build and test:

```sh
cd bridge
swift build -c release
swift run BridgeCoreTests
```

The checked-in Xcode project can also build the GUI, helper, and service. Code
signing identities are intentionally not committed. Ad-hoc signing is suitable
only for local development; public distribution requires the publisher's own
Developer ID Application/Installer certificates and Apple notarization.

### Runtime host tools

- Xcode command-line tools: `xcrun`, `clang`, `codesign`, `lipo`, `hdiutil`,
  `plutil`, and `swift`.
- Homebrew dependencies: `python@3.12`, `dpkg` (`dpkg` and `dpkg-deb`),
  `libusbmuxd` (`iproxy`), `zstd`, `ldid`, `autoconf`, `automake`, and
  `pkgconf`.
- OpenSSH client utilities and standard macOS tools (`ssh`, `ssh-keygen`,
  `nc`, `lsof`, `tar`, `ditto`, `shasum`, and `launchctl`).
- Python device tooling is installed into a private virtual environment. The
  release wheelhouse pins pymobiledevice3 and Frida 17.18.0; the wheelhouse is
  a release artifact rather than source and is not committed here.
- Apple-provided SRD/developer services, including the appropriate Xcode Device
  Support/DDI and `cryptexctl`, must be obtained through Apple.
- The complete-project controller source is bundled with Bridge source builds, but
  its signed device payload Kit remains external and must include a valid
  `SHA256SUMS` manifest.

Binary-release users should select **Install All 0-Sky Requirements** in
0-Sky Bridge. The guided installer detects Apple Silicon and Intel Homebrew,
can invoke Homebrew's official interactive bootstrap, explicitly installs
Python 3.12 and dpkg, and creates the isolated pinned environment from the
release wheelhouse. Apple's `/usr/bin/python3` may start the bootstrap but is
not accepted as the completed 0-Sky runtime.

## 0-Sky Link — iOS/SRD

- macOS with Xcode and an iPhoneOS SDK supporting iOS 17 or later.
- `xcrun`, Apple Clang, `codesign`, `zip`, `sips`, and `shasum`.
- Target: `arm64-apple-ios17.0`.
- The included source build is an ad-hoc development IPA. Installation and use
  require an authorized SRD signing/registration workflow.
- Runtime services are reached only through the device loopback endpoint at
  `127.0.0.1:48654`; the service and its per-device secrets are not embedded.
- The production Link release carries a separately integrity-checked SRD Kit.
  Apple-provided assets and generated device payloads are intentionally absent
  from source control and may be supplied only through `ZEROSKY_KIT_SOURCE` in
  authorized local builds.

Build:

```sh
cd link
./build.sh
```

## 0-Sky Control — iOS/SRD

- macOS with Xcode and an iPhoneOS SDK.
- Theos configured through `THEOS`.
- Homebrew packages: `libarchive`, `openssl@3`, and `pkg-config`.
- `ldid`, GNU Make, Python 3, `dpkg-deb`, and standard archive tools.
- Target settings in the source use iPhoneOS SDK 16.5 compatibility and an
  iOS 14 deployment floor inherited from upstream; 0-Sky SRD functionality is
  validated only on the supported iOS 17+ research environment.
- The checked-in private-framework `.tbd` stubs provide link-time declarations;
  the private frameworks themselves come from the Apple SDK/device environment.
- No certificate or private key is committed. The lite/Control build uses ldid
  development signing; distribution must use the researcher's authorized
  signing and registration workflow.

Build:

```sh
cd control
make control
```

Output is produced by Theos under `TrollStoreLite/packages/` and remains ignored
by Git. The application depends on its device-local 0-Sky runtime service for
privileged operations and fails closed when that service is unavailable.

## External components not committed

The following are intentionally distributed separately or generated locally:

- Apple SDKs, Xcode DDIs, SRD authorization, and Apple research Cryptex assets.
- Pairing records, device tickets/nonces, trust caches personalized to a device,
  provisioning profiles, certificates, and private keys.
- Prebuilt IPAs, DEBs, DMGs, PKGs, Frida binaries, Python wheels, and Procursus
  bootstrap archives.
- Device logs, crash reports, screenshots, research evidence, and user state.

## Multi-computer pairing requirements

- Each Mac must independently complete Apple's physical Trust/Developer Paired
  Macs approval and have its own local 0-Sky instance, SSH key, and Mac identity.
- The initial additional-Mac authorization requires the exact SRD connected by
  USB to an already paired Mac. Network trust-on-first-use is not allowed.
- Signed public-only requests expire after seven days and are limited to one
  device; private keys, Lockdown pairing records, bridge tokens, and passwords
  must not be transferred.
- A device accepts at most 16 0-Sky Mac identities. The registry migrates legacy
  single-Mac markers and preserves existing entries atomically.
