# 0-Sky Bridge source

Native macOS GUI and persistent service for device discovery, pairing/trust,
USB/Wi-Fi transport, RemoteXPC, SSH, developer services, DDI/debugserver,
Frida, recovery, and research-session evidence.

The canonical agreement in [`0SkyBridge/Resources/Legal/EULA.md`](0SkyBridge/Resources/Legal/EULA.md) is bundled into the
application. On first launch—or after a future agreement version change—the
Bridge blocks device discovery and service startup until the user accepts the
agreement and separately certifies device/system ownership or explicit
authorization. Only the accepted version, document digest, affirmative state,
and timestamp are stored locally. Acceptance of the unchanged version 1.0
document is migrated from the earlier local preference keys.

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

## Full-disclosure security diagnostics

The Diagnostics screen publishes the complete, versioned security-check
contract and verbose measured output. Every check explains its method, accessed
data, privileges, network scope, mutation status, evidence, secret handling,
and limitations. Unmeasured checks are explicitly `NOT_RUN`, never `PASS`.
Exports include machine-readable and human-readable disclosure, normalized
health, collection policy, and SHA-256 hashes without credentials, key material,
tokens, or pairing records. See [`docs/DIAGNOSTICS.md`](docs/DIAGNOSTICS.md).

## Remove a device from this Mac

The Devices detail panel and both device context menus provide **Remove Device
from 0-Sky Bridge…** behind an explicit destructive-action confirmation. It
removes only the exact device's validated Mac-side enrollment, owned
instance-scoped LaunchAgents, and cached trust/transport receipts. It never
contacts or modifies the Apple device and preserves research evidence,
diagnostics, shared SSH keys, unrelated processes, and other device profiles.
An active research session blocks removal.
