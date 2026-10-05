# 0-Sky 1.0.0 pre-release 25

This experimental replacement fixes the Control crash and the two final Intel
deployment failures exposed by the complete pre.24 hardware run.

## Fixes

- 0-Sky Control is now version 3.5.37. Its Tweaks inventory validates every
  nested Core JSON value before dictionary subscripting. A temporarily
  unavailable collector may return JSON `null`; pre.24 sent
  `objectForKeyedSubscript:` to that value and crashed with
  `NSInvalidArgumentException`.
- Host deployment derives the expected Control version and build directly from
  the checksum-bound IPA. Pre.24 installed Control 3.5.36 correctly but still
  waited for obsolete 3.5.28 metadata, so the resumable pipeline stopped before
  Link and Filza.
- The Control worker gives the fixed 384 MiB application Cryptex the same
  bounded transfer window as its paired-userspace installer. A cold Intel
  reinstall can legitimately exceed the old five-minute outer deadline.
- Control replacement uses Apple's exact-device `devicectl` service instead of
  entering pymobiledevice3's Intel ctypes/libffi callback path. A fresh Link
  install is materialized from its already verified Cryptex through the
  dedicated, bounded appregistrard transaction because live Intel testing
  proved `devicectl` waits for its full deadline when no Link MCM target exists.
  Both routes independently verify installed bytes, registration, and launch
  over host-key-pinned SRD SSH.
- Distribution notarization now supplies an explicit 50-minute service wait.
  Apple's notary queue continued processing pre.25 after `notarytool` exhausted
  its shorter implicit wait, which discarded an otherwise valid signed build.

## Export comparison

The two user-provided device exports were inspected but are not used as release
inputs. Their versions are Control 3.5.36 and Link 1.9.0 build 48. Both exports
omit the registration marker sealed by their installed signatures, and the
exported Link embeds an older Control 3.5.17 payload. Pre.25 therefore rebuilds
Control from the audited source and stages it into the verified kit rather than
republishing mutable device output.

## Upgrade

Install pre.25 over pre.24, keep the same unlocked SRD connected directly by
USB, and press **Resume**. Existing pairing, SSH keys, Procursus, application
data, and completed Cryptex state are preserved. Resume installs Control only
when its release-bound version differs, then continues Link, Filza, and final
health verification.
