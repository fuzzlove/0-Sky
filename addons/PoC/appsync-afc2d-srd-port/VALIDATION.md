# AFC2 validation record

Checkpoint date: 2026-10-02

Target: authorized Apple SRD, `iPhone13,2`, iOS 27.0 build `24A5390f`,
arm64e. Device-unique identifiers are intentionally omitted.

## What is verified

- Host-side package construction and static checks have passed for generated
  candidates when the exact device-derived inputs are supplied.
- A read-only host smoke test connected to the currently exposed
  `com.apple.afc2` service and listed root markers including `/Applications`,
  `/System`, `/private`, `/usr`, and `/var`.
- The smoke test proves the currently running service exposes a read-only root
  view. It does not identify the exact installed AFC2 package or variant.

## What is not verified

- The `1.2.0+0sky27.5` AFC2 package is **unverified** as the source of the live
  service. Current SSH host-key validation is stale and AFC cannot read dpkg
  status files, so the installed package hash/version was not freshly proven.
- The `__DATA_CONST` import-pointer variants in `variants/` are **untested as
  successful fixes**. Earlier test sessions associated with this line of work
  terminated `lockdownd` before service logic with `CODESIGNING: Invalid
  Page`; later trials also showed PAC and memory exceptions.
- No checkpoint or restore rehearsal modifies `lockdownd`, installs a package,
  restarts a daemon, checks in/restores the SRD, or fuzzes the device.

See `docs/reproducibility/STATE.md` and the sanitized evidence index for the
complete failure/status matrix.
