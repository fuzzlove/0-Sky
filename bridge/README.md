# 0-Sky Bridge source

Native macOS GUI and persistent service for device discovery, pairing/trust,
USB/Wi-Fi transport, RemoteXPC, SSH, developer services, DDI/debugserver,
Frida, recovery, and research-session evidence.

## Requirements

- macOS 15+
- Xcode/Command Line Tools with Swift 6
- Apple Silicon or Intel Mac

Runtime dependencies and Apple-provided SRD requirements are documented in the
repository [`REQUIREMENTS.md`](../REQUIREMENTS.md).

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
installer payloads, device kits, pairing records, and research evidence are not
part of the source repository.
