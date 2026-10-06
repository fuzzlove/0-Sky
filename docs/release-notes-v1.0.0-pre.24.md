# 0-Sky 1.0.0 pre-release 24

This experimental replacement fixes the Intel transport deadlock exposed after
pre.23 successfully repaired offline Zstandard extraction.

## Reuse the proven paired USB transport

- First-runtime sync now defaults to the existing exact-UDID paired userspace
  USB RemoteXPC channel with `autopair=False`.
- It no longer probes native `remoted` during the mutating transfer. On the
  tested Intel host, that backend blocked inside ctypes/libffi callback
  allocation before Python could enforce its advertised timeout.
- The runtime-generation and automation installer copies are byte-identical, so
  initial enrollment and later runtime refreshes cannot silently diverge.
- Native remoted remains an explicit recovery backend through
  `ZERO_SKY_CRYPTEX_TRANSPORT=native`; its existing one-time userspace fallback
  and post-reset commit verification remain covered.
- Transport output explicitly states which backend is active.

## User action

Install pre.24 over pre.23 with the same unlocked SRD connected directly by
USB, then press **Resume**. Existing pairing, SSH identity, SRDssh, Procursus,
offline Python packages, and generated runtime inputs are preserved.

## Evidence boundary

Live pre.23 Intel setup passed SRDssh, package upload, offline Zstandard
extraction, Xcode arm64/arm64e builds, signing, and Cryptex asset construction.
A host process sample localized the stop before device mutation to native
libffi callback allocation. Automated validation passed 317 tool tests (3
private-fixture skips), 130 host-tool tests (1 external-kit skip), and 33/33
BridgeCore checks. Pre.24 still requires live Resume and final component health
verification before end-to-end readiness can be claimed.
