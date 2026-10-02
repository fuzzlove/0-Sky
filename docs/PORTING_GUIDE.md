# Porting a component to iOS 27

1. Run the repository scanner and locate the component ID in `inventory.json`.
2. Verify upstream project, commit, license, original hash, package source, and
   maintainer scripts. The scanner records control-member hashes, absolute
   paths, and command references. Review each script's effects and record its
   exact `name:sha256` in a pinned `maintainer_scripts` stage. Keep unreviewed
   binaries and scripts blocked.
3. Run `python3 -m zero_sky_compat --state STATE --environment ENV analyze ARTIFACT`
   using a measured device environment. Read its issues and dependency graph.
   An unknown install method remains `UNKNOWN`; use its generated
   `adaptation-plan.json` to add a shared reviewed backend or adapter.
4. Rebuild from maintained source when architecture, ABI, or private API is
   incompatible. Do not alter Mach-O architecture metadata to simulate support.
   A source build recipe must pin the source tree hash and appear by SHA-256 in
   `compat/ios27/reviewed-recipes.json`. The `compat.ios27.build` runner executes
   only reviewed argument arrays and compares two clean build outputs.
5. Use the reviewed `rootless-v1` adapter only for payload-owned paths. Keep
   application registration, service activation, and privileged operations in
   their existing dedicated backends.
6. Record patch hashes, build toolchain, source commit, output hash, and exact
   target environment in `0sky-compat.json`. Rerun analysis after every change.
7. Install through a transactional backend on an authorized test SRD. Require
   launch or hook behavior, dependencies, smoke tests, UAT, and rollback evidence.
   Each repair iteration must use a distinct strategy and add evidence. The
   default limit is three attempts; repeated identical failures stop retries.
8. Admit only through the repository gate in `REPOSITORY_ADMISSION.md`.

If source or a supported API is demonstrably absent, retain the specific
blocking reason. If that fact is not established, retain `UNKNOWN`. A copied
binary, successful `dpkg` exit, or loaded dylib does not complete the port.

## Reusing a manual repair

Before adding a new package-specific fix, add its untouched and working
artifacts to `compatibility/manual-conversion-pairs.json` and run:

```sh
python3 tools/analyze_manual_conversions.py --search-root /path/to/originals
```

Review the generated findings and candidate rule. Promote no rule solely from
a visual diff. Add a deterministic fixture, prove the original remains
unchanged, prove the derivative is reproducible, then attach exact device
runtime and rollback evidence. Use `tools/0sky-convert PACKAGE --dry-run
--explain` to inspect an already reviewed rule match.
