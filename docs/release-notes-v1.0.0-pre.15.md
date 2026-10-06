# 0-Sky 1.0.0 pre-release 15

This experimental replacement fixes `install failed: instance uses another kit
revision`, reproduced during live Intel fresh-SRD testing of pre.14.

## Audited per-device kit upgrade

- Setup, Resume, and Repair now recognize an exact-device profile staged by an
  older verified 0-Sky kit and upgrade its immutable staged assets instead of
  stopping at the revision check.
- The upgrade validates the selected UDID, instance name, loopback host, local
  and remote SSH ports, and SSH-key path before changing any state. A profile
  for another endpoint still fails closed.
- Pairing records, generated keys, private logs, the managed Python
  environment, and unrelated per-device state remain in place.
- Old staged assets, configuration, and the previous completion marker are
  moved to an owner-only checkpoint under the selected instance before the new
  assets become visible.
- Replacement directories are prepared completely before atomic rename. Any
  failure restores the old directories, configuration, and completion marker.
- A successful refresh clears the old completion marker so the current kit's
  pairing and health checks must complete before setup can report success.
- Repeating setup with the current revision is idempotent and does not create
  another checkpoint.

## User action

Install this package over pre.14, open 0-Sky Bridge, select the same unlocked
SRD connected directly by USB, and press **Resume**. Do not delete the old
profile, pairing records, or SSH keys. The technical log records
`KIT_REFRESH=PASS` and the private checkpoint path when migration occurs.

## Evidence boundary

The profile-revision failure was traced to the host-only companion staging
gate before any device mutation. Regression tests execute successful refresh,
wrong-endpoint refusal, rollback after an injected failure, preservation of
runtime/private state, completion-marker invalidation, and idempotent rerun.
Intel fresh-SRD setup beyond this repaired host stage remains live hardware UAT
and is not claimed complete by this release note.
