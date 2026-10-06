# 0-Sky 1.0.0 pre-release 17

This experimental replacement fixes the next live Intel fresh-SRD failure:
after pre.16 correctly reused the saved exact-device port, iOS 27 RemoteXPC
timed out and the packaged GUI did not enable the controller's supported
Paired Macs recovery.

## Guided iOS 27 RemoteXPC pairing

- Complete Project Setup now enables `--pair-remotexpc` automatically when the
  explicitly selected device reports iOS 27 or later.
- If the initial exact-device RemoteXPC handshake fails, the app displays the
  existing guided action: open **Settings → Developer → Paired Macs** on the
  unlocked SRD, select this Mac, and complete the displayed code flow.
- After pairing, setup retries the reviewed SRDssh bootstrap and still requires
  the returned RemoteXPC identity to match the explicitly selected UDID.
- iOS 26 does not receive the iOS-27-only pair-host option; its previously
  validated Cryptex path remains unchanged.
- The fallback remains bounded to 180 seconds and does not disable Apple trust,
  pairing, signature, nonce, TSS, or exact-device checks.

## User action

Install this package over pre.16, keep the same SRD unlocked on USB, and press
**Resume**. When prompted, perform the Paired Macs action on the SRD. Do not run
the pairing command manually or copy pairing records from another Mac/device.

## Evidence boundary

The live attempt passed kit migration and saved-port recovery, then timed out in
`PreferredRsdTunnel` while native RemoteXPC browse returned no usable peer. A
BridgeCore regression test verifies that iOS 27 receives the guided fallback
and iOS 26 does not. Completion of the on-device code flow and subsequent
device mutation remain live hardware UAT.
