# Restore rehearsal report

Date: 2026-10-02

Source checkpoint commit:
`7029a5d47c708d1292775e50f96f119682af2a40`.

Isolated checkout:
`/tmp/0sky-restore-parent.<random>/checkout` (ephemeral; the random suffix is
not part of the restore contract).

No device-changing command was run. No SRD was selected for installation,
check-in, restore, restart, or fuzzing.

## Passing checks

| Check | Result |
| --- | --- |
| Restore script dry run | PASS |
| Clean clone and manifest verification | PASS, 8 immutable tracked inputs |
| Independent appregistrard patch | PASS |
| Independent srdzsh patch | PASS |
| Restore rerun/idempotency | PASS; both patches detected as already applied |
| Pinned Theos checkout and recursive submodules | PASS |
| `swift run BridgeCoreTests` | PASS, 33/33 |
| Control device compatibility tests | PASS, 15/15 |
| AFC2/AppSync clean host build | PASS |
| AFC2/AppSync package metadata, arm64/arm64e, minimum OS and ad-hoc signature checks | PASS |
| Targeted credential and developer-path scan | PASS; no live key/token or checkpoint-host/device value found outside fixtures/vendor examples |

The clean AFC2 build downloaded the two upstream archives, verified their
SHA-256 hashes, applied the tracked patches, consumed separately supplied
exact-build `afcd`/`lockdownd` inputs, compiled with Xcode 26.6/iPhoneOS 26.5,
signed ad hoc, packaged, and passed `scripts/check-port.sh`.

## Checks with known failures

- `python -m unittest discover -s tools/tests`: 218 tests, 2 errors, 4
  skipped. Both errors require the intentionally excluded prepared external
  kit (`sync_runtime_cryptex.py` and bundled `host-mac/install.py`).
- Python 3.12 Bridge host tools: 106 tests, 2 errors, 1 skipped. One error is
  the same absent external runtime kit; one is a pre-existing Crane reviewed
  binary-transformation contract mismatch.
- `swift test` builds all Swift products but reports that the package has no
  XCTest target. The intended executable test target, `swift run
  BridgeCoreTests`, passes 33/33.
- The repository release sanitizer reports fixture/vendor strings (example
  device IDs, test paths, network examples, and source code that recognizes a
  private-key header). Validation was not disabled. A second scoped scan for
  actual private-key blocks, common token formats, checkpoint-host paths, and
  the observed SRD identifiers passed.
- `git diff --check` reports historical whitespace in preserved upstream
  patch files and vendored source. It was not hidden or auto-rewritten.

## Reproducibility limitation found during rehearsal

Two successive clean AFC2/AppSync builds both passed static and signature
validation but did not produce identical DEB hashes. `SOURCE_DATE_EPOCH` and
`-Wl,-no_uuid` are now set for future builds, but the ad-hoc-signed tweak
dylibs still differed. Therefore the checkpoint guarantees reproducible
source, pinned inputs, build success, payload semantics, and signature/static
checks—not bit-identical candidate DEBs. The older DEB hashes in the manifest
identify local historical artifacts and must not be treated as expected
rebuild hashes or proof of what is installed.

## Gaps preventing full replication

1. Apple's authorized SRD repository/`srdtool` was absent, so official
   check-in, configuration, cryptex installation, and restore were not
   rehearsed.
2. The proprietary/generated prepared 0-Sky kit and its clean replacement
   signed device payloads are not exportable from this source checkpoint.
3. Exact-build Apple `afcd` and `lockdownd` must be reacquired from an
   authorized matching SRD and hash-verified.
4. Signing identities, private keys, profiles, pairing records, SSH host-key
   pins, and credentials must be supplied by the clean-Mac operator.
5. Current root SSH trust is stale, so installed package versions and daemon
   state could not be freshly verified.
6. The current working AFC2 service can expose a read-only root view, but the
   installed package/variant identity remains unverified.
7. The import-pointer variants remain failed/unverified as recorded; no
   successful device test is claimed.
