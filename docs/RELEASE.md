# macOS release procedure

The public distribution artifact is a single signed Universal 2 `.pkg`. A
release candidate can be built without distribution signing but remains
non-public and reports `FINAL_RESULT=BLOCKED`. The
entry point is [`scripts/build_release.sh`](../scripts/build_release.sh),
with independent artifact verification through
[`scripts/verify_release.sh`](../scripts/verify_release.sh). The older
[`build.sh`](../build.sh) remains an unsigned development build. This procedure
preserves the separate iOS/SRD Link and Control payloads; those binaries are
validated for their device platform, not given Intel slices.

Every run must use a new empty output directory. A successful run contains
exactly the package, `RELEASE_AUDIT.txt`, `RELEASE_MANIFEST.json`, and
`SHA256SUMS`. This explicit allowlist prevents stale packages, logs, symbols,
or local test output from being published with the installer.

1. Start from a clean checkout. Obtain the authorized external kit and its
   manifest separately. Verify toolchain/dependencies with
   `tools/environment_preflight.py`; inspect
   [UNIVERSAL_BUILD_AUDIT.md](UNIVERSAL_BUILD_AUDIT.md). Supply the reviewed
   Theos checkout explicitly with `--theos`; the build no longer derives
   include paths by invoking Homebrew.
2. Configure caller-owned Developer ID Application and Developer ID Installer
   identities in the keychain. Public distribution also requires a `notarytool`
   keychain profile; the build now blocks before compilation when it is absent.
   Keep all credentials outside the source tree and output logs. The builder
   automatically selects an identity only when exactly one valid identity of
   each required category is present; multiple identities require explicit
   fingerprints and are never guessed.
3. Run the documented build command in [BUILDING.md](BUILDING.md). The pipeline
   fails closed on invalid kit hashes, signed payload PII, EULA mismatch,
   missing Mac architecture slices, incomplete Python wheel coverage,
   unexpected payload contents, unsafe permissions, development files,
   invalid signatures, or Gatekeeper rejection.
4. Inspect `RELEASE_AUDIT.txt`. When it says `FINAL_RESULT=PASS`, verify the
   directory and package once more without relying on the removed build tree:

   ```sh
   python3 tools/release_manifest.py verify /path/to/release
   scripts/verify_release.sh --release-directory /path/to/release \
     --report /tmp/0sky-independent-release-audit.txt
   ```

   Publish the complete four-file set. Retain private symbol archives
   separately and never add them to the release directory.
5. On both Apple Silicon and Intel hardware, record clean install, launch,
   upgrade, and supported uninstall/reinstall results. Record `NOT_EXECUTED`
   for unavailable hardware; never relabel slice verification as runtime UAT.

The latest local distribution validation completed the canonical build and an
independent package-only verification with `FINAL_RESULT=PASS`. This is build
evidence, not authorization to publish: publication remains a manual release
owner action after required clean-account and hardware UAT.

The package uses an allowlisted `Applications/0SkyBridge.app` payload and no
installer scripts. The verifier expands it with `pkgutil --expand-full`,
compares every file and mode with the signed staged app, scans the expanded
package including nested IPA/ZIP native bytes, verifies the EULA, inspects
every Mac Mach-O and its Developer ID/hardened-runtime signature, and checks
for unexpected debug entitlements. If notarization is configured, the
pipeline waits for acceptance, staples the package, and validates the ticket.
Without a profile, a distribution build stops at `SIGNING_PREFLIGHT` and prints
the exact `xcrun notarytool store-credentials` command; it never emits an
unnotarized package as a public release.

Before the outer app signature is sealed, the distribution pipeline signs all
loose macOS runtime binaries and every macOS native member of the offline wheel
archives with Developer ID and a secure timestamp. It regenerates each wheel's
PEP 376 `RECORD`, then rebuilds `WHEEL_INVENTORY.json`, `SHA256SUMS`, and the kit
content manifest. This is required because Apple's notary service recursively
inspects native code inside bundled dependency archives; signing only the app
shell is insufficient.

`RELEASE_MANIFEST.json` records the product version, build, mode, roles, sizes,
and SHA-256 digests. `SHA256SUMS` covers the installer, audit report, and JSON
manifest. The verifier rejects symlinks, path components, duplicate entries,
missing files, checksum drift, and any fifth file.

Release staging excludes generated `__pycache__`, `.pyc`, and `.pyo` artifacts.
A missing `HOST_RUNTIME_MANIFEST.json` is repaired reproducibly by the pinned
dual-architecture runtime builder. Raw home/volume/debug strings in reviewed
upstream payloads are reported as advisories; they are not treated as proof of
a secret or broken runtime path. Actual Mach-O dependency and effective RPATH
commands are inspected structurally and remain blocking when nonportable.
Public upstream test keys are accepted only through an exact archive SHA-256,
member-prefix, and category entry in
`manifests/release-sanitizer-exceptions.json`; changed bytes fail closed.

0-Sky creates each user's SSH/private key material after installation in that
user's protected application-support state. Those keys are expected runtime
identity, are mode-restricted, and must never appear in the app, package,
diagnostic export, or release manifest. Use `release_sanitize.py --verbose`
or `kit_pii_report.py` for a private detailed review; the normal successful
build prints only advisory counts. See
[EXTERNAL_KIT_BLOCKERS.md](EXTERNAL_KIT_BLOCKERS.md) for the current evidence
and remaining hardware validation boundaries.
