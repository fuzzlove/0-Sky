# 0-Sky 1.0.0 pre-release 20

This experimental replacement fixes the next live Intel fresh-SRD failure.
Pre.19 completed SRDssh and Procursus, then the first trusted-runtime stage
requested a runtime-manager DEB version that was not present in the signed kit.

## Complete first-runtime bootstrap

- The controller now selects the checksum-bound
  `srd-runtime-manager_2.4.10_iphoneos-arm64.deb` bootstrap actually shipped in
  the kit.
- This package establishes device Python; setup then assembles the current
  source-controlled runtime generation into the per-device Cryptex.
- Release preparation reads the controller's version directly and fails before
  packaging if the exact DEB is absent or is a symlink.
- Bundled `dpkg-deb` must prove the expected package ID, exact version, and
  `iphoneos-arm64` architecture. Renaming a different package cannot satisfy
  the gate.
- Missing or mismatched packages produce an explicit release-blocker code and
  an actionable rebuild instruction.

## User action

Install pre.20 over pre.19, keep the same unlocked SRD connected by USB, and
press **Resume**. Do not delete the profile, pairing record, SSH identity, or
device data. The already verified SRDssh/Procursus generation should be
preserved while setup continues with the first trusted runtime.

## Evidence boundary

The live pre.19 Intel run passed exact-device userspace RemoteXPC, SRDssh
Cryptex installation, reboot/reconnect, authenticated UID-0 SSH, and Procursus.
It stopped before uploading the missing first-runtime DEB. Automated validation
for this fix passed 306 tool/release tests and an exact semantic probe of the
externally supplied verified 2.4.10 package. Pre.20 still requires live Resume,
remaining component deployment, and final health UAT before completion can be
claimed.
