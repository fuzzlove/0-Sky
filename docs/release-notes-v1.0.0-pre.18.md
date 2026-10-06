# 0-Sky 1.0.0 pre-release 18

This experimental replacement fixes an already-paired iOS 27 SRD being sent
through a new Paired Macs enrollment after a native RemoteXPC timeout.

## Existing-pairing recovery

- RemoteXPC preflight now uses two separately process-bounded attempts: a
  30-second native-preferred attempt followed by a 120-second forced userspace
  USB attempt.
- The forced userspace attempt reuses the exact selected device's existing
  pairing record. It does not delete, copy, or silently replace pairing state.
- Guided Paired Macs enrollment remains available only when both supported
  routes fail and the device actually needs approval.
- Exact-UDID matching and the live domain-3 nonce check remain mandatory.
- Failure text states which route timed out or failed and gives a concrete
  recovery action without claiming that a transport timeout means unpaired.

## User action

Install this package over pre.17, keep the same SRD unlocked and directly
connected by USB, and press **Resume**. Do not remove the existing pairing. The
technical log should show the native attempt and, when needed,
`existing paired userspace USB` before any pairing prompt is offered.

## Evidence boundary

On the live Intel test Mac, a read-only forced-userspace probe reused the
existing pairing and reached the exact connected iPhone12,8 running iOS 27.0;
cryptexd returned a 48-byte domain-3 nonce. Automated validation passed 301
tool/release tests, 126 Python 3.12 host-tool tests, and 33 BridgeCore tests.
The new package still requires live Resume/install and final health UAT; this
evidence does not claim that device mutation has completed.
