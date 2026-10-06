# 0-Sky 1.0.0 pre-release 22

This experimental replacement fixes the next live Intel fresh-SRD failure.
Pre.21 included all Xcode inputs and successfully compiled the runtime, but its
bundled Debian helper supported inspection and extraction only, not package
creation.

## Self-contained device-package construction

- The bundled `dpkg-deb` compatibility helper now supports the exact
  `--root-owner-group -b ROOT OUTPUT` operation required by first enrollment.
- Package output is deterministic: ownership, timestamps, tar ordering, gzip
  metadata, and ar headers are normalized from the locked build epoch.
- Inputs are bounded, unsafe paths and symlinks are rejected, and the final
  package is written atomically.
- Release preparation now rebuilds the pinned Intel/Apple-silicon host runtime
  from the current source on every release instead of accepting a structurally
  valid but stale helper.
- Before signing, the release pipeline performs two byte-identical package
  builds, reads the resulting Debian metadata, extracts the payload, and
  verifies its exact bytes.
- Runtime checks for build-capable helper version 1.1 before first-runtime
  device mutation. An older package produces an explicit reinstall instruction
  and clarifies that users do not need Xcode or Homebrew repairs.

## User action

Install pre.22 over pre.21, keep the same unlocked SRD connected directly by
USB, and press **Resume**. Preserve the profile, pairing record, SSH identity,
SRDssh Cryptex, Procursus bootstrap, and device data. Setup will reuse completed
stages and continue at the first trusted runtime.

## Evidence boundary

The live pre.21 Intel run compiled and signed both arm64 and arm64e runtime
inputs, proving Xcode and all source inputs are healthy. It stopped only when
the bundled extract-only helper rejected package construction. The corrected
helper completed that exact builder locally, and the full tool suite passed 314
tests with 3 unavailable private-fixture skips. Pre.22 still requires live
Resume, remaining component deployment, and final health UAT before completion
can be claimed.
