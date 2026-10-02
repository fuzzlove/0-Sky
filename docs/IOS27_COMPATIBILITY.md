# iOS 27 compatibility

The repository scanner is `tools/ios27_compat_pipeline.py`. It inventories both
`.ipa` and `.tipa` application archives through the same bounded parser. Run it from a clean
checkout with `python3 tools/ios27_compat_pipeline.py`. It writes deterministic,
read-only results under `artifacts/compatibility/`. The scanner inspects file
magic, package control fields, Mach-O load commands, plists, source paths, and
dependencies. For DEBs it also hashes members of the control archive and marks
maintainer scripts for review. It never extracts or executes package scripts.
The source-audit CI workflow runs this scanner and the compatibility tests on
each push and pull request with `dpkg-deb` installed. Newly added artifacts therefore appear in the
inventory automatically and remain blocked from admission without evidence.

The device-side `zero_sky_compat` package supplies intake, static analysis,
deterministic plans, reviewed rootless adaptation, exact-artifact evidence,
transactional backend contracts, bounded repair, rollback, batch analysis, and
the Compatibility view in Control. `CompatibilityEngine.process()` drives the
full lifecycle. Installation requires a matching reviewed backend and complete
functional evidence.

`UNKNOWN` means evidence is incomplete. `NATIVE_COMPATIBLE` means static
analysis found no required transformation; runtime testing is still pending.
`ADAPTATION_REQUIRED` and `BUILD_REQUIRED` produce plans instead of rejection.
Only specific measured failures produce `BLOCKED_BY_*`, `BROKEN_UPSTREAM`, or
`UNSAFE_TO_ADAPT`. Generated manifests remain blocked from repository admission
until device runtime, smoke, UAT,
source/license, and rollback evidence is attached for the exact artifact and OS
build. No package is admitted by the scanner alone.

Run parallel read-only analysis with `python3 -m zero_sky_compat --state STATE
--environment ENV analyze-batch ARTIFACT...`. Installation remains serialized.

Sileo installations route every changed package through the shared SRD package
code adapter. This matters for command line packages as well as tweaks: a
successful dpkg transaction does not itself authorize newly written Mach-O
code. The runtime synchronizer validates package ownership and paths, admits
the exact executable and library CodeDirectories in a personalized Cryptex,
and then requires a functional smoke probe. The `jq` 1.6 package is the first
dual-device acceptance case: before adaptation its `libonig` dependency was
rejected by code-signing policy; after the generated Cryptex was installed,
both tested devices loaded both dependencies, returned `jq-1.6`, and completed
a JSON filter.

The first scan includes archived development material under `addons/PoC`; the
inventory is evidence, not a release payload. Developer paths are redacted in
reports and flagged for review. `artifacts/` is ignored by Git.
