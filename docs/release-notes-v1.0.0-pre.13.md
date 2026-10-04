# 0-Sky 1.0.0 pre-release 13

This experimental replacement fixes the fresh-SRD setup ordering failure found
during live Intel testing.

## Fresh-device setup

- **Set Up New Device** no longer invokes host-only pairing before device SSH
  exists.
- The action now opens the confirmed Complete Project stage for the explicitly
  selected USB SRD.
- The complete controller uses the supported exact-device RemoteXPC path to
  establish SRDssh/Procursus first, then converges the host profile, pairing,
  applications, services, and health checks.
- Setup guidance distinguishes pairing an already prepared SRD from preparing
  a fresh SRD, eliminating the circular `pairing exited 2` workflow.
- The controller now accepts manifest-hashed relative links only when they
  resolve inside the verified kit. This fixes the Intel preflight rejection of
  legitimate Universal Python entry points such as `2to3 -> 2to3-3.12`, while
  absolute, escaping, and broken links remain blocked.
- Release preparation no longer replaces the canonical SRDssh bootstrap and
  Cryptex installer with compatibility placeholders. Both reviewed adapters
  are source-controlled, manifest-bound, exact-device scoped, and choose the
  validated GenericDmg slot for iOS 26 or iOS 27.
- Corrected the stale bundled-public-key checksum that previously stopped a
  fresh setup before RemoteXPC authorization.

## Retained pre.12 fixes

- Duplicate profile candidates are validated independently; an incomplete
  preserved profile no longer blocks the sole complete exact-device profile.
- Deterministic interrupted setup resumes and reserves ports found in stale
  profiles without deleting them.
- Two complete profiles fail closed with `ERR_PROFILE_CONFLICT`.
- Pairing output is retained owner-only in
  `instances/<instance>/logs/pairing-last.log`, while the GUI receives a
  redacted actionable cause.
- The embedded-kit permission repair and verified iOS 26.0/iOS 27 Cryptex
  selection behavior remain included.

## Evidence boundary

Read-only live inspection was executed on a MacBookPro16,1 (`x86_64`) running
macOS 26.5.2 with an iPhone12,8 on iOS 27.0. The signed Universal 2 app,
readable embedded kit, USB discovery, Apple developer services, all 19 SRDssh
assets, native RemoteXPC, a 48-byte domain-3 nonce, and live Apple TSS ticket
authorization were verified without device mutation. The old action ordering,
incomplete duplicate profiles, overly narrow symlink gate, disabled SRDssh
adapter, and stale key hash were reproduced. A complete pre.13 installation
and post-install health check on that Intel Mac and fresh SRD remain hardware
UAT, not yet claimed as passed.
