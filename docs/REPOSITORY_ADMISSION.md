# iOS 27 repository admission

`REPO_ADMISSION=PASS` requires each of these stages to be `PASS` for the exact
component hash and target environment: inventory, dependency, architecture,
PII/secrets, build, package, installation, registration when applicable,
runtime, smoke, UAT, and license/provenance. The implementation is
`admission()` in `tools/ios27_compat_pipeline.py`.

Unknown, skipped, failed, or stale stages block admission. Quarantined
components remain quarantined even if earlier build and install checks passed.
`repository-admission.json` and per-package `0sky-compat.json` files show the
current gate state. The default generated state is blocked; promotion requires
reviewed functional evidence and a transactional installer backend. No scanner
result alone publishes an artifact.

Repository admission and package compatibility are separate. `UNKNOWN` does
not mean an artifact is incompatible, but it still withholds admission until
the missing evidence is collected. Compatibility blockers must name the
measured dependency, platform, entitlement, or architecture cause.
`manifest-index.json` lists the current generated manifests. When a package
disappears, the scanner removes only a stale manifest directory containing its
own recognized generated file; unexpected files are left for manual review.

Both `.deb` and `.ipa` packages receive admission entries and per-artifact
manifests. Historical builds sharing a package or bundle identifier remain
blocked as duplicates until an exact-hash candidate is selected in
`compat/ios27/reviewed-candidates.json`. Identical copies resolve to one
canonical candidate; additional copies and superseded builds remain blocked.
Archive identity and architecture inspection do not satisfy runtime or UAT
evidence.

Device evidence is imported only through `compat/ios27/reviewed-admission.json`.
That file pins the SHA-256 of a receipt named `<artifact-sha256>.json` under
`compat/ios27/admission-evidence/`. Each `PASS` stage in the receipt names a
stage JSON file in the sibling `<artifact-sha256>/` directory and pins that
file's SHA-256. Stage files carry the component ID, artifact hash, environment
hash, stage, result, and nonempty expected/observed observations. The scanner
checks every pin and the exact artifact/environment identity before applying
the gate. Missing, edited, malformed, or unreviewed evidence remains blocked.

The review pin records that a researcher inspected the underlying UAT and
license evidence. A scanner run does not create or approve these receipts.
The initial review registry is empty, so static intake alone admits nothing.

DEBs with maintainer scripts require an additional `maintainer_scripts` PASS
stage. Its receipt entry must list every script as `name:sha256`, matching the
control archive scanned from the exact artifact. The stage evidence must also
describe the review outcome. A changed script hash invalidates the review;
the scanner never executes a script to establish trust.
