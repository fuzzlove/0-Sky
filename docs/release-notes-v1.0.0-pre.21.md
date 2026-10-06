# 0-Sky 1.0.0 pre-release 21

This experimental replacement fixes the next live Intel fresh-SRD failure.
Pre.20 correctly supplied the verified first-runtime package, but release
pruning omitted source files that the enrolled Mac must compile with Xcode.

## Preserve first-runtime Xcode inputs

- The release package now retains `test_host.c`, `test_tweak.c`, and
  `test_tweak.plist`. Despite their historical names, these are production
  first-enrollment compiler inputs, not test output.
- Maintenance tests, Python bytecode, caches, and other generated artifacts
  remain excluded.
- Release preparation now fails before signing with
  `FIRST_RUNTIME_XCODE_INPUTS_MISSING` and identifies every missing relative
  path plus the exact kit-rebuild action.
- Runtime setup checks all four builder inputs before invoking Xcode. If a kit
  is incomplete, the UI explains that Xcode itself is not the missing
  dependency and instructs the user to install a complete package.
- A clean local probe compiled the exact runtime host and dylib for arm64 and
  arm64e, created the universal products, signed them ad hoc for the device
  Cryptex flow, and built both expected Debian packages.

## User action

Install pre.21 over pre.20, keep the same unlocked SRD connected directly by
USB, and press **Resume**. Do not delete the profile, pairing record, SSH
identity, SRDssh Cryptex, Procursus bootstrap, or device data. Setup should
reuse all previously completed stages and continue at the first trusted
runtime.

## Evidence boundary

The live pre.20 Intel run passed the 2.4.10 package gate and uploaded/unpacked
the complete offline first-runtime package set. It then failed at the first
clang command because the release package lacked `test_host.c`. Automated
validation for this fix passed 308 tool/release tests (3 skipped unavailable
private fixtures) plus the direct clean Xcode build described above. Pre.21
still requires live Resume, remaining component deployment, and final health
UAT before completion can be claimed.
