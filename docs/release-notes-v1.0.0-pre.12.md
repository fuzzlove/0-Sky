# 0-Sky 1.0.0 pre-release 12

This experimental replacement fixes the Intel setup failure:

```text
ERR_PROFILE_STALE: Multiple profiles claim this UUID
```

## Setup repair

- Validates every per-device host profile instead of counting any `config.json`
  containing the selected UUID as a completed enrollment.
- Resumes the sole complete exact-device profile when an interrupted setup
  directory also exists.
- Resumes the deterministic device directory when all matching profiles are
  incomplete, with the exact unlocked device selected over USB.
- Reserves local SSH ports found in incomplete profiles so a resumed setup does
  not collide with an older per-device forward.
- Never selects by filesystem enumeration order.
- Preserves incomplete profiles rather than deleting user state automatically.
- Fails closed with `ERR_PROFILE_CONFLICT` when two complete profiles exist and
  directs the user to export redacted Diagnostics before removing only the
  obsolete Mac-side enrollment.

The distribution package retains the pre.11 embedded-kit permission fix and
the verified iOS 26.0 / iOS 27 compatibility behavior. This build still needs
live Intel setup validation against the reporter's fresh SRD.
