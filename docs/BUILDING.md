# Building 0-Sky Bridge for macOS

The Mac product is `0SkyBridge.app` for macOS 15 or newer. Xcode must provide
the macOS SDK and both `arm64` and `x86_64` slices. Python 3.12, the Apple
command-line tools, and an independently obtained authorized kit with
`SHA256SUMS` are required. Use `python3 tools/environment_preflight.py --mode
development --kit KIT --skip-device` to discover the current toolchain; the
report redacts the hostname and user-specific support path.

Build source/tests from any working directory using repository-relative
scripts. The kit, signing identities, notarization profile, DerivedData,
configuration, and output directory are inputs, never source edits. A local
build path layout comes from `tools/release_paths.py`; installed Swift code
uses `BridgePaths` and bundle resources rather than the source checkout. The
single source-build command accepts the raw authorized kit, prepares and
sanitizes it, then creates the local unsigned Universal 2 app:

```sh
./build.sh --kit "/path/to/authorized kit" --derived-data "/path/to/build output"
```

This local build is not distributable.

To build a non-public release candidate, run:

```sh
scripts/build_release.sh --mode release-candidate --kit KIT --output dist
```

The candidate runs the PII, kit-manifest, offline-install, architecture,
extracted-package, and EULA gates. Its audit states `FINAL_RESULT=BLOCKED`
until distribution signatures are present. To build a public Universal 2
package, run:

```sh
scripts/build_release.sh --mode distribution --kit KIT --output dist \
  --app-identity APP_CERT_SHA1 \
  --installer-identity INSTALLER_CERT_SHA1 \
  --notary-profile PROFILE
```

Use the exact SHA-1 fingerprints of Keychain identities classified as
Developer ID Application and Developer ID Installer. An Apple Development
certificate is accepted only in `--mode development` for a non-public build.
Identity fingerprints may instead be supplied through
`ZERO_SKY_APP_IDENTITY` and `ZERO_SKY_INSTALLER_IDENTITY`; the optional
notarytool keychain profile uses `ZERO_SKY_NOTARY_PROFILE`. Configure these on
the build machine. Never commit certificates, private keys, API keys, or
notarization credentials. For project-specific local deny patterns, pass
`--deny-file PRIVATE_JSON` with `{"patterns":{"label":"regex"}}`; keep this
file outside Git. The build creates an additional temporary, mode-0600
denylist for its own home, username, hostname, private host addresses,
checkout, and staging paths. `ZERO_SKY_RELEASE_DEVICE_IDS` optionally adds a
comma-separated list of known test-device identifiers for local-only matching.

The single release entry point verifies the canonical EULA, stages the
manifest-listed kit, builds both Mac slices with Xcode, signs nested Mac code
before the app, builds and signs a package, optionally notarizes and staples
it, expands the package again, and writes `dist/RELEASE_AUDIT.txt`. It moves
the installer into `dist/` only after all mandatory checks pass. A failing
build leaves only a sanitized FAIL report, not an installer advertised as
ready. The wheelhouse may contain separate Intel and Apple-silicon wheels;
the verifier checks each pinned dependency for both architectures.
The prepared kit contains `RELEASE_KIT_APPROVAL.json`,
`RELEASE_KIT_MANIFEST.json`, `WHEEL_INVENTORY.json`, and `SHA256SUMS`. Approval is written only after
the Link payload, full kit PII scan, architecture checks, and an isolated
`pip --no-index` install pass. The app build independently verifies the
manifest and scans the kit again before embedding it.
The dependency command defaults to offline mode and selects the manifest-
verified Universal 2 Python 3.12 and host tools below
`Kit/host-mac/runtime/bin`. `HOST_RUNTIME_MANIFEST.json` records versions,
licenses, runtime requirements, destinations, architectures, and hashes. A kit
without that complete runtime fails the release build; development-only online
repair may use an already-installed Homebrew but never downloads or executes a
moving Homebrew bootstrap script.

Run `python3 -m unittest discover -s tools/tests -q`,
`(cd bridge && swift run BridgeCoreTests)`, and the host-tool tests described
in the root [BUILDING.md](../BUILDING.md). Physical Intel execution, a clean
installation, an upgrade, and SRD operation require their corresponding
hardware/environment and must be recorded separately from slice verification.

The currently supplied external kit fails the PII gate because signed device
payloads contain former builders' home paths. Replace them with authorized,
verified, sanitized signed payloads, update the manifest, and rerun. Do not
patch signed binaries in place or bypass the gate.
