# Checkpoint state

Checkpoint date: 2026-10-02. Canonical tag:
`0sky-reproducibility-2026-10-02-r2`.

## Verified

- Canonical Git remote is `https://github.com/fuzzlove/0-Sky`.
- Target identity was read-only verified as `iPhone13,2`, iOS 27.0,
  `24A5390f`. Device-unique identifiers are redacted.
- A read-only AFC2 smoke test reached the current service and enumerated root
  filesystem markers. The mount was stopped cleanly.
- Exact-build `afcd` and `lockdownd` hashes were captured without adding the
  binaries to Git.
- AppSync/afc2d upstream commits and archives are pinned by hash.
- Independent appregistrard and srdzsh work is committed locally, tagged, and
  exported as patches based on public upstream commits.

## Failed or unavailable

- Earlier AFC2 hook/import-pointer trials: **failed** with
  `CODESIGNING: Invalid Page` before service logic. Later related trials also
  produced `PAC_EXCEPTION` and `KERN_MEMORY_ERROR` signatures.
- Root SSH inspection: **unavailable** because strict host-key verification
  rejected the stale pin. It was not bypassed or repaired for this checkpoint.
- Installed package/version proof: **unavailable**. AFC could stat the dpkg
  status path but could not open it; SSH was unavailable.
- `srdtool`: **unavailable on the host**, preventing an official cryptex
  lifecycle/check-in restore rehearsal.

## Untested or unverified

- The exact-build-guarded `__DATA_CONST` import-pointer sources under
  `addons/PoC/appsync-afc2d-srd-port/variants/`: **not verified working**.
- `com.cannathea.afc2d-arm64` version `1.2.0+0sky27.5`: host artifact hash is
  known, but its identity as the currently working installed service is
  **unverified**.
- The current hypothesis—that service registration must precede embedded
  registry parsing and may require a pre-main mechanism—remains a hypothesis.
- No package installation, `lockdownd` modification, daemon restart, fuzzing,
  check-in, restore, or other device mutation was performed in the checkpoint.

The exact commit IDs and archive hashes are recorded in
`RESTORE_REHEARSAL.md` after the final rehearsal.
