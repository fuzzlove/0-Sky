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
| Control | arm64 iOS/iPadOS SRD payload | 21 source compatibility/security checks plus clean 3.5.36 rootless package build | Source and package build verified; live deployment not executed |
| Exact iOS 26 SRD evidence | iPhone 15 (`iPhone15,4`), iOS 26.0 (`23A341`), arm64e | Separate live-device session retained a fresh domain-3 nonce/live-ticket Cryptex install, durable MCM registration for Link and Control, Runtime Manager 2.4.20, and successful measured runtime loading; see `addons/PoC/IOS26_COMPATIBILITY_NOTES.md` | Validated on device in the retained session; not rerun during this packaging turn |
| Exact SRD evidence | iPhone 12 (`iPhone13,2`), iOS 27.0 (`24A5390f`), arm64e | Retained reproducibility manifests and prior exact-build evidence | Evidence retained; live setup not rerun in this audit |
| Other iOS/iPadOS 17+ SRDs | Exact UDID/build/capability probe required | No complete hardware matrix available | Unverified; never inferred from version alone |

The application refuses a device payload when its compatibility manifest does
not match the selected device's measured model, OS build, architecture, and
required capabilities. Add a row only after retaining the corresponding test
evidence; do not broaden a release claim from source compilation alone.
The Cryptex installer selects GenericDmg slot 9 for iOS 26.0–26.3 and slot 10
for iOS 26.4+ and iOS 27, using the selected device's reported OS version. It
fails explicitly for another OS family rather than silently applying the iOS
27 value. This transport selection does not bypass the exact model/build and
capability gates above.
