# Release cleanup report

Date: 2026-10-05

This report records release-distribution cleanup. It does not rewrite Git
history, move a tag, or replace a published binary.

## Authoritative release

- **State:** CURRENT / VERIFIED / SUPPORTED
- **Tag:** `v1.0.0-pre.26`
- **Commit:** `a60643b98e469fc3863af6d7a310c42182c0bf50`
- **Installer SHA-256:**
  `7eab748c43fcc1789944ba6590ab083004e711d829d8acf44d11ec2dcc4cd68f`
- **Release:** <https://github.com/fuzzlove/0-Sky/releases/tag/v1.0.0-pre.26>

The package was preserved byte-for-byte. Its freshly downloaded four-file
release set passed manifest, Developer ID, nested-code, Universal 2,
notarization, staple, Gatekeeper, dependency-kit, package-structure, and
privacy verification. Installation over pre.25 on the Intel test host passed;
the installed app's kit identity matched the package and its post-install iOS
27 SRD report passed all ten stages.

## Inventory and selection

The audit enumerated local and remote Git tags, 25 GitHub releases, all 42
public release assets, release bodies and states, local build/archive trees,
packages, disk images, archives, IPAs, DEBs, compiled outputs, manifests,
checksums, signatures, notarization/staple status, SBOM availability, and test
reports. Every public asset was downloaded before cleanup and hashed. The
complete sanitized snapshot is retained in
[`release-evidence/v1.0.0-pre.26/public-release-audit.json`](../release-evidence/v1.0.0-pre.26/public-release-audit.json).

Current `tools/verify_release.py --notarized` results were:

- `v1.0.0-pre.26`: PASS, zero errors;
- `v1.0.0-pre.17` through `v1.0.0-pre.25`: FAIL dependency-kit admission;
- pre.21 through pre.25 additionally lack the required SRDssh command-shell
  link; and
- historical release notes independently document the sequential live-runtime
  failures that caused each replacement.

The older source checkpoint archive passed its historical checksum but failed
the current source admission policy because it predates the reviewed allowlist
and carries fixed-home examples plus binary vendor fixtures. It was not needed
for provenance because its immutable Git tag remains available.

## Deprecated releases

All 24 GitHub releases older than `v1.0.0-pre.26` are classified
**DEPRECATED / UNSUPPORTED / DO NOT USE**: `v1.0.0-pre.2`,
`v1.0.0-pre.3-r2`, and `v1.0.0-pre.4` through `v1.0.0-pre.25`.
Their existing notes are retained below a standardized warning and their
prerelease state is preserved.

## Removed public assets

The source-controlled [`release-status.json`](../manifests/release-status.json)
records original size, SHA-256, tag, and reason for every removed asset.
Removed from public distribution:

- nine known-broken Universal 2 installer packages from pre.17 through pre.25;
- the pre.3-r2 historical source archive that fails the current admission
  policy; and
- that archive's checksum sidecar.

Non-executable `RELEASE_AUDIT.txt`, `RELEASE_MANIFEST.json`, and `SHA256SUMS`
assets remain on pre.17 through pre.25 as historical hash/audit evidence. They
are not installation sources.

## Provenance retained

- All Git commits and branch history were retained.
- Every local and published tag retained its original object/commit target.
- No force push, history rewrite, tag move, version reuse, or binary
  replacement occurred.
- Historical release notes were retained.
- Original hashes and pre-cleanup release metadata were committed as sanitized
  evidence.

## Repository cleanup

Ignored local build products were inspected before removal. They consisted of
Swift/Xcode intermediates, Theos objects and packages, Python bytecode, local
release rehearsal output, cached host runtimes, and a generated source IPA.
No tracked source or provenance file was removed. Existing ignore rules already
cover these product classes; release evidence is deliberately not ignored.

## Security and PII findings

All pre.17–pre.26 package privacy sections passed: no developer home, username,
hostname, repository path, device identifier, email, credential, private key,
or debug artifact was detected by the packaged-release verifier. The current
release also passed the independent source PII audit. The obsolete pre.3-r2
source archive failed today's stricter source admission policy and was removed
from downloads. No secret, signing credential, private certificate material,
pairing record, or device-unique value is stored in the retained evidence.

## Validation improvements

- Added [`docs/RELEASE_POLICY.md`](RELEASE_POLICY.md).
- Added `manifests/release-status.json` as the single release-state authority.
- Added `tools/verify_release_policy.py` and regression tests.
- Added a CycloneDX SBOM and sanitized package/test/UAT evidence.
- Added CI policy verification and a manual GitHub-release validation workflow.
- Updated README and installation guidance to link only the supported release.

## Tests executed after cleanup

- Tool/release unit suite: PASS — 337 tests, 4 unavailable or cleaned-fixture skips.
- Host-tool suite under pinned Python 3.12: PASS — 138 tests, 1 expected skip.
- Control compatibility: PASS — 22 tests.
- AFC2 compatibility: PASS — 21 tests, 6 unavailable exact-build fixture skips.
- BridgeCore: PASS — 33/33.
- EULA verification: PASS.
- Source PII audit: PASS — 35 reviewed allowlisted findings, zero unallowlisted findings.
- Repository inventory reproducibility: PASS.
- Release-policy verifier: PASS — one current, 24 deprecated, 11 removed assets.
- GitHub release-hygiene verifier: PASS.
- Remote tag before/after comparison: PASS — no changed refs.
- Current four-asset before/after byte comparison: PASS.
- Fresh current-release manifest verification: PASS.
- Fresh current-release full notarized verification: PASS — `FINAL_RESULT=PASS`.
- Historical public package audit: pre.17 through pre.25 fail current admission; pre.26 passes.

## Remaining risks

- The exact package UAT was completed on Intel macOS; Universal 2 structure was
  verified, but an equivalent clean-account Apple-silicon package UAT remains
  outstanding.
- Uninstall UAT and the broader supported-device matrix remain incomplete.
- The current supported version is still a semantic prerelease. Promotion to a
  stable version requires a new tag/version and full admission; pre.26 must not
  be renamed or silently reused.
