# AppSync + AFC2D SRD research port

This directory preserves reproducible host-side source for the authorized
`iPhone13,2` SRD research target running iOS 27.0 build `24A5390f`. It does
not assert that the current AFC2 candidate is safe or functional.

## Pinned inputs

- AppSync commit `235aca6cddfbdc9fa87fcb5b2aec2df37ed6d65a`, archive SHA-256
  `f816f6e63dc2f8852855f4bce3e047487a2876f92484ae1fc90caf9dd6eea1e7`.
- afc2d-arm64 commit `7587154c9eed60636fe9d8d2ca0b286b59177b0a`, archive SHA-256
  `92b804570960798f82a42beffa430d55cb1271b5e87f68272d3881ad5d33e80a`.
- Exact-build `afcd`, SHA-256
  `fd53a6c591dedf2b1c30e8d5c542f3df5e80099306607a52eaa4e4f2958c87f8`.
- Exact-build `lockdownd`, SHA-256
  `e6844bdf52dd3dfab0558c004f85506ca56892c69f318df88aedfe3306e1ebf7`.

The Apple binaries are device-derived, excluded from Git and archives, and
must be reacquired from an authorized SRD on the exact supported build. The
default Theos checkout is pinned in the reproducibility manifest. Builds use
the iPhoneOS 26.5 SDK, iOS 26.0 minimum, and arm64/arm64e slices.

## Research status

Earlier hook variants reached process injection but produced
`CODESIGNING: Invalid Page` before service logic ran. Later trials also
produced PAC and memory failures. The exact-build-guarded `__DATA_CONST`
import-pointer variants are preserved under `variants/` and remain
unverified. Loader reports are not proof that `com.apple.afc2` registration or
root service access succeeded.

The working hypothesis is that repackaging alone is insufficient and that the
service must be registered before `lockdownd` consumes its embedded registry.
Whether an earlier pre-main mechanism is required is not yet verified.

`make check` performs host-only build and static validation. It never installs
to a device. Device mutation is deliberately outside the default restore and
rehearsal path.
