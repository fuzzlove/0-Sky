# Release policy

## Supported-release invariant

Exactly one published version may be identified as
**CURRENT / VERIFIED / SUPPORTED**. The machine-readable authority is
[`manifests/release-status.json`](../manifests/release-status.json). The public
release title and the repository README must identify the same tag. A source
tag, successful compile, valid signature, or passing packaging audit alone does
not make a version supported.

The current release is `v1.0.0-pre.26`. It remains a semantic prerelease and a
GitHub prerelease; that label does not weaken its status as the project's sole
supported build. A future stable release must receive a new version and its own
complete evidence.

## Verified-release admission

A release may become current only when all applicable evidence passes:

1. unit, integration, compatibility, and smoke tests;
2. deterministic release-manifest and SHA-256 verification;
3. dependency-kit completeness and exact version consistency;
4. Intel and Apple-silicon architecture inspection for Universal 2 claims;
5. strict application, nested-code, and installer signature verification;
6. hardened-runtime, entitlement, and signing-team consistency checks;
7. Apple notarization acceptance, staple validation, and Gatekeeper assessment;
8. package structure, ownership, EULA, and installed-app launch checks;
9. source and packaged-artifact PII, credential, secret, private-key, absolute
   developer path, hostname, debug-log, and build-leakage scans;
10. an SBOM and retained non-secret build/signing/notarization evidence;
11. an upgrade or clean-install UAT on every platform claimed as exercised; and
12. applicable iOS/SRD deployment, registration, component, and foreground
    launch checks.

Unsupported platform combinations must remain explicitly unverified rather
than inferred from architecture support. `tools/verify_release.py` and
`tools/verify_release_policy.py` are fail-closed and must return zero before
publication or promotion.

## Release states

### Current

There is exactly one **CURRENT / VERIFIED / SUPPORTED** release. Its original
binary assets are immutable. It is the only release linked as an installation
source from the README and installation guide.

### Deprecated

Every superseded version is **DEPRECATED / UNSUPPORTED / DO NOT USE**. Its
GitHub title and first release-note block must say so and point to the current
release. Historical notes and tags remain available for provenance. A
deprecated release must not be described as a fallback or recommended repair.

### Removed from distribution

Known-broken, incomplete, corrupt, unsafe, improperly signed/notarized,
machine-specific, path-leaking, secret-bearing, or dependency-incomplete
binary assets are removed from GitHub downloads. Their commits, immutable tag
targets, release notes, original hashes, sizes, failure reasons, and relevant
audit results are retained in source-controlled evidence. Metadata that cannot
be executed may remain when it materially supports provenance.

## Versioning and immutability

Versions follow semantic versioning. Prerelease identifiers are never reused.
A published tag is never moved to another commit, and a published asset is
never silently replaced. A corrected build receives a new patch or prerelease
version and a new tag. Git history is not rewritten to hide a failed release.

## Signing and notarization

Public macOS packages require a current Developer ID Application signature for
the app and nested code, a Developer ID Installer signature for the package,
trusted timestamps, hardened runtime where applicable, consistent signing
team, Apple notary acceptance, a stapled ticket, and passing Gatekeeper
assessment. Evidence records only the result and credential category. Private
keys, account identifiers, certificate fingerprints, app-specific passwords,
keychain contents, and notarization credentials are never committed.

## Checksums and manifests

Every supported release contains exactly one installer, `RELEASE_AUDIT.txt`,
`RELEASE_MANIFEST.json`, and `SHA256SUMS`. SHA-256 is mandatory. The manifest
binds product, version, build, distribution mode, sizes, roles, and hashes. A
checksum mismatch or extra/missing file is a release failure.

## SBOM policy

Every supported release retains a CycloneDX SBOM under
`release-evidence/<tag>/sbom/`. It identifies the exact installer hash,
architecture claim, embedded Python wheels with versions and hashes, and
checksum-bound packaged runtime inputs. Undeclared license metadata remains
declared as unknown rather than guessed. SBOM regeneration for the same tag may
clarify metadata but must never change or substitute the published binary.

## Evidence retention

Non-secret evidence lives under `release-evidence/<tag>/` and includes the
public checksum and build manifest, sanitized signing and notarization results,
automated test summaries, UAT summaries, SBOM, and the public-artifact audit.
Device identifiers, pairing records, host keys, private logs, operator names,
credentials, tokens, provisioning material, and private certificate data are
excluded.

## Rollback

A rollback never moves a tag or overwrites an asset. If the current release is
found unsafe, its executable assets are withdrawn, its release is marked
deprecated, and the issue is documented. A previously published version may be
promoted only if it independently satisfies the current admission policy;
otherwise a fixed higher version is built, verified, and published. User data
and device profiles are preserved whenever the documented migration permits.

## Unsupported versions

Deprecated, withdrawn, experimental, test, development, and local-candidate
builds receive no installation support and must not be redistributed as
production packages. Reports involving them should first be reproduced with
the current supported release. Historical source remains available for audit,
debugging, and attribution.

## Automation and review

CI runs the source privacy audit, repository-inventory comparison, unit and
compatibility suites, EULA verification, and release-policy verifier. The
manual release-validation workflow downloads an identified GitHub release and
reruns manifest, signature, architecture, package, privacy, notarization,
staple, and Gatekeeper checks on macOS. Publication still requires the recorded
hardware UAT appropriate to the claimed support matrix.
