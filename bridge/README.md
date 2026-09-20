# 0-Sky Bridge source

Native macOS GUI and persistent service for device discovery, pairing/trust,
USB/Wi-Fi transport, RemoteXPC, SSH, developer services, DDI/debugserver,
Frida, recovery, and research-session evidence.

The version 1.0 agreement in [`../EULA.md`](../EULA.md) is bundled into the
application. On first launch—or after a future agreement version change—the
Bridge blocks device discovery and service startup until the user accepts the
agreement and separately certifies device/system ownership or explicit
authorization. Only the accepted version and timestamp are stored locally.

## Requirements

- macOS 15+
- Xcode/Command Line Tools with Swift 6
- Apple Silicon or Intel Mac

Runtime dependencies and Apple-provided SRD requirements are documented in the
repository [`REQUIREMENTS.md`](../REQUIREMENTS.md).

In the binary application, **Install All 0-Sky Requirements** runs a guided
Terminal workflow for Homebrew Python 3.12, `dpkg`/`dpkg-deb`, USB/build tools,
and the isolated pinned Python environment. Source builds require a separately
supplied, integrity-checked Kit/wheelhouse as described below.

## Build and test

```sh
swift build -c release
swift run BridgeCoreTests
```

The Swift package products are:

- `0SkyBridge`
- `0SkyBridgeService`
- `0SkyBridgeHelper`
- `0SkyBridgeCLI`
- `BridgeCore`

The checked-in Xcode project builds the native application. Signing identities,
binary installer payloads, device kits, pairing records, and research evidence are
not part of the source repository. The complete-project controller source is
included under `0SkyBridge/Resources/Scripts`; it requires a separately supplied,
integrity-checked SRD Kit at runtime.
