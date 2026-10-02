# Compatibility architecture

```text
repository scanner -> inventory + graph -> selected artifact
    -> DISCOVER -> ANALYZE -> PLAN -> ADAPT -> BUILD -> INSTALL
    -> TEST -> DIAGNOSE -> REPAIR -> RETEST -> CLASSIFY
    -> repository admission
```

`tools/ios27_compat_pipeline.py` owns repository discovery and deterministic
report generation. `compat/ios27/build.py` runs hash-pinned source recipes in
two fresh workspaces; it does not grant repository admission. The recipe review
registry is empty until an upstream source and its build logic are reviewed.
`bridge/DeviceRuntime/zero_sky_compat` owns device-specific analysis,
adaptation plans, bounded repair, adapter policy, registry, and transactions.
`CompatibilityEngine` is the orchestration entry point; its analyzer classes
share one `Report` and evidence stream rather than embedding heuristics in the
UI. Static batch analysis uses bounded workers, while device-changing
operations share a serialization lock. `0-Sky Control` reads the
registry through the authenticated runtime API. The repository gate requires
all evidence for the same source hash and environment fingerprint.
Transaction journals are written through private temporary files, fsynced,
and atomically replaced; symbolic journal paths are rejected. An unfinished
transaction blocks another mutation until the matching backend verifies
rollback.
The repository scan includes staged artifacts, including `.deb`, `.app`, and
`.ipa` payloads. IPA inspection reads the archive directory and bounded
metadata without extracting it into the repository. Unsafe paths, archive
symlinks, malformed app identity, or unsupported executable architecture block
that archive for review. An inventoried IPA is still unverified until the
device installation, launch, smoke, and UAT gates pass.
The DEB listing is parsed without running maintainer scripts; traversal,
duplicate or special entries, and symlinks are blocked before conversion.
Control-archive members are hashed without execution. A DEB with maintainer
scripts needs a pinned review stage listing every exact script hash before
repository admission can pass.

## Manual conversion forensics

`tools/analyze_manual_conversions.py` compares curated original and working
artifact pairs through the hardened intake path. It records recursive content
and mode changes, package metadata, Mach-O dependency and RPATH data, plists,
launch services, entitlements, preference bundles, and maintainer script
behavior without executing package code. Logical labels replace host paths in
the report. The generated rules under
`compatibility/rules/generated-candidates/` always begin at `EXPERIMENTAL` and
cannot grant repository admission.

`tools/0sky-convert` applies only deterministic rules whose preconditions are
fully established. `--dry-run --explain` performs no package or device
mutation. The first rules normalize bounded ZIP compression and canonicalize
a plist through an exact artifact conversion lock. Output remains `UNTESTED`
until runtime evidence exists for that exact artifact and environment.
Malformed archives and invalid upstream metadata receive `BROKEN_UPSTREAM`;
unsafe archive entries and repeated identical failures receive
`UNSAFE_TO_ADAPT`. Concrete architecture evidence receives
`BLOCKED_BY_ARCHITECTURE`. Unknown methods, launch contexts, APIs, or device
capabilities remain `UNKNOWN` and create analysis evidence.
`RootlessPaths` derives application, library, daemon, preference, log, and
state paths from the measured bootstrap prefix. Its translator accepts only
paths explicitly owned by the staged payload; it does no broad string
replacement.

`artifacts/compatibility/private-api-map.json` lists observed private framework
references as unresolved. An entry may gain a replacement only after actual
iOS 27 runtime evidence; names inferred from old code are insufficient.

The conversion plan is dependency-first. Concrete cycles and missing required
dependencies are blocked with evidence. Unknown architecture, entitlement
state, source method, or installer backend remain pending analysis while
independent components continue. Runtime
crash quarantine remains authoritative and cannot be overridden by static
analysis or a package-manager success code.
If a source checkout is a fork, its URL and revision are recorded separately
from the original upstream. A fork without an explicit trust classification
remains blocked for source review even if the original upstream is official.
Byte identical copies of a package resolve to one canonical artifact; extra
copies cannot be admitted separately. Different builds under one package ID
require an exact component ID and SHA-256 pin in
`compat/ios27/reviewed-candidates.json`. A candidate pin selects the build to
evaluate; it does not grant compatibility, license approval, or repository
admission. Unknown licenses and missing source revisions remain blocked.

The Security Research Toolkit catalog may describe a reviewed private tweak
variant separately from the upstream OS ceiling. Recognition requires the
installed package version, dylib SHA-256, device model, and iOS build to match
the adapted variant. Current runtime PASS additionally requires a matching
device receipt and live injection record. This only changes compatibility
and runtime facets; source trust, automated smoke/UAT, and repository admission
remain independent gates. The Doodle iOS 27 private port uses this path.

## SRD package code admission

APT and dpkg can place a valid Mach-O in the writable rootless prefix without
making its CodeDirectory executable under the SRD trust policy. The package
runtime adapter therefore receives the exact set of changed Debian package
identifiers from the authenticated Bridge transaction. It accepts only valid
package names, reads only dpkg-owned top-level `usr/bin`, `usr/sbin`, and
rootless library files, ignores scripts and data after file-magic inspection,
and follows the bounded Mach-O dependency closure. The exact signed bytes and
their libraries enter the next personalized research Cryptex trust cache.

This is shared infrastructure for CLI tools and tweak support binaries. It is
not a package-name allowlist. The transformed generation records package,
original hash, admitted hash, dependencies, Cryptex generation, and device
verification. Sileo reports the package as installed but unverified until a
separate functional probe succeeds.

Loader failures are also bounded. A target crash quarantines the exact
target/dylib/hash tuple immediately. When the target stays alive, three
identical loader outcomes quarantine that same tuple. A changed package hash
gets one fresh evaluation. Control reads the quarantine evidence and displays
`ADAPTATION REQUIRED` with runtime `FAIL`; it does not show READY or keep
retrying the same strategy.
