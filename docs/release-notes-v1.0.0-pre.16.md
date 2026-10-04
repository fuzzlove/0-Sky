# 0-Sky 1.0.0 pre-release 16

This experimental replacement fixes the second Resume failure found during
live Intel fresh-SRD testing immediately after pre.15 migrated the host profile.

## Interrupted-profile port recovery

- The Python setup controller now reads the exact device's deterministic,
  validated interrupted profile before allocating a local SSH port.
- Resume reuses that profile's port even when its exact-device USB tunnel is
  still listening. Previously, the listener made the allocator choose the next
  port, after which the installer correctly rejected the changed endpoint with
  `existing profile ssh_port belongs to another endpoint`.
- A newly selected device cannot take a port reserved by another profile even
  when no process is currently listening on it.
- A malformed, unsafe, wrong-device, or conflicting LaunchAgent/profile pair
  fails before port allocation or device mutation and directs the user to Host
  Profile Repair.
- Port recovery is deterministic and does not edit the saved profile, pairing
  records, generated keys, device data, or the pre.15 rollback checkpoint.

## User action

Install this package over pre.15. Connect the same SRD directly by USB, unlock
it, approve Trust/Paired Macs prompts if shown, and press **Resume**. If the app
says no USB device is visible, reconnect the data cable or port before retrying;
that transport condition is separate from the repaired profile-port failure.

## Evidence boundary

The live failure showed the existing profile on port 2222 while the resumed
controller selected 2223 because the prior exact-device tunnel still occupied
2222. Regression tests cover reuse of a busy saved port, reservation of another
profile's idle port, and wrong-device refusal before allocation. Full
post-Cryptex device health remains live hardware UAT.
