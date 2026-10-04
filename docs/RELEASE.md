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
   [UNIVERSAL_BUILD_AUDIT.md](UNIVERSAL_BUILD_AUDIT.md).
2. Configure caller-owned Developer ID Application and Developer ID Installer
   identities in the keychain. Configure a `notarytool` keychain profile if
   notarizing. Keep all credentials outside the source tree and output logs.
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

The package uses an allowlisted `Applications/0SkyBridge.app` payload and no
installer scripts. The verifier expands it with `pkgutil --expand-full`,
compares every file and mode with the signed staged app, scans the expanded
package including nested IPA/ZIP native bytes, verifies the EULA, inspects
every Mac Mach-O and its Developer ID/hardened-runtime signature, and checks
for unexpected debug entitlements. If notarization is configured, the
pipeline waits for acceptance, staples the package, and validates the ticket.
Without a profile, the report says `NOT_EXECUTED` for notarization and
stapling; it never claims those steps passed.

`RELEASE_MANIFEST.json` records the product version, build, mode, roles, sizes,
and SHA-256 digests. `SHA256SUMS` covers the installer, audit report, and JSON
manifest. The verifier rejects symlinks, path components, duplicate entries,
missing files, checksum drift, and any fifth file.

At present the available external kit blocks `PREPARE_KIT` with
`FIXED_HOME_PATH` and `DERIVED_DATA_PATH` in signed Frida and PreferenceLoader
device binaries. The private diagnostic inventory is written by
`python3 tools/kit_pii_report.py KIT artifacts/release-kit-pii.json` and
contains no secret values. No
public installer should be produced from it. The ignored local kit, cached
builds, and old installers are not trusted release inputs. A deeper audit of
the old unsigned app also found additional privacy/secret-pattern matches in
compressed wheel, Debian, and IPA contents; those inputs need review too.
See [EXTERNAL_KIT_BLOCKERS.md](EXTERNAL_KIT_BLOCKERS.md) for the source-level
remediation required for each class.
