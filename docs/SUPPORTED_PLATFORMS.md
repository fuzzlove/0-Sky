# Verified compatibility matrix

Compatibility claims are evidence-scoped. A binary slice is not a runtime
test, and a successful SSH command is not proof of Apple trust, pairing,
signing, or entitlement acceptance.

| Component | Environment | Evidence | Status |
| --- | --- | --- | --- |
| Bridge source and Swift core | Apple-silicon macOS host, Swift 6 toolchain | Clean release compilation and 33 BridgeCore tests | Verified in this audit |
| Bridge Universal 2 output | macOS 15+, arm64 and x86_64 | Build and release gates require both slices in the app and every declared native host runtime component | Statically enforced; Intel runtime not executed |
| Compiled package on clean Mac | Apple silicon and Intel | Requires complete approved host runtime, signing, notarization, and clean-account UAT | Not executed / release blocker |
| Link | arm64 iOS/iPadOS SRD payload | Clean IPA build, identity/icon/signature structure, checksum, and sanitizer | Source artifact verified; fresh hardware deployment not executed |
| Control | arm64 iOS/iPadOS SRD payload | 21 source compatibility/security checks | Source verified; package build blocked without THEOS |
| Exact SRD evidence | iPhone 12 (`iPhone13,2`), iOS 27.0 (`24A5390f`), arm64e | Retained reproducibility manifests and prior exact-build evidence | Evidence retained; live setup not rerun in this audit |
| Other iOS/iPadOS 17+ SRDs | Exact UDID/build/capability probe required | No complete hardware matrix available | Unverified; never inferred from version alone |

The application refuses a device payload when its compatibility manifest does
not match the selected device's measured model, OS build, architecture, and
required capabilities. Add a row only after retaining the corresponding test
evidence; do not broaden a release claim from source compilation alone.
