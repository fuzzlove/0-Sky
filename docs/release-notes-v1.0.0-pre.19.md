# 0-Sky 1.0.0 pre-release 19

This experimental replacement fixes the next live Intel failure after pre.18
successfully reused an existing SRD pairing: the actual Cryptex installer
discarded the proven userspace route, retried native RemoteXPC, and appeared to
hang while the controller hid its child output.

## Exact transport continuity

- Bootstrap now returns the exact RemoteXPC route that proved the selected
  UDID and domain-3 nonce.
- That route is passed explicitly to both the read-only live-TSS preflight and
  the actual Cryptex installer. A userspace success is no longer followed by an
  unrelated native retry.
- Direct automatic installer use prefers paired userspace USB before native
  remoted, avoiding an Intel ctypes/libffi callback stall.
- Exact-device, nonce, Apple ticket, manifest, and signature checks remain
  mandatory; no trust or compatibility check was disabled.

## Truly verbose progress

- Child stdout and stderr are drained one line at a time instead of waiting for
  64 KiB or process exit.
- Each flushed child line is retained for error handling, appended to the
  owner-only stage artifact, and shown in the expandable technical output.
- The existing ten-second heartbeat remains as evidence when an underlying
  library produces no output.

## User action

Cancel any pre.18 attempt that remains at `native phase still running:
bootstrap`, install pre.19, keep the same unlocked SRD connected by USB, and
press **Resume**. Preserve the existing pairing and setup state.

## Evidence boundary

Live Intel inspection identified the stalled pre.18 stack in native
ctypes/libffi callback allocation before the Cryptex mutation call. Automated
validation passed 304 tool/release tests, including exact transport selection
and streamed/captured child output. The pre.19 package still requires live
Resume/install and final health UAT before device completion can be claimed.
