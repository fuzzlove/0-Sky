# Building 0-Sky Bridge for macOS

The Mac product is `0SkyBridge.app` for macOS 15 or newer. Xcode must provide
the macOS SDK and both `arm64` and `x86_64` slices. Python 3.12, the Apple
command-line tools, and an independently obtained authorized kit with
`SHA256SUMS` are required. Use the human-readable doctor to discover the
current toolchain; the report redacts the hostname and user-specific support
path and prints a complete install/repair sequence for every missing item:

```sh
python3 tools/environment_preflight.py --human --mode development \
  --kit "/absolute/path/to/authorized kit" \
  --theos "/absolute/path/to/locked/theos" --skip-device
```

Build source/tests from any working directory using repository-relative
scripts. The kit, signing identities, notarization profile, DerivedData,
configuration, and output directory are inputs, never source edits. A local
build path layout comes from `tools/release_paths.py`; installed Swift code
uses `BridgePaths` and bundle resources rather than the source checkout. The
single source-build command accepts the raw authorized kit, prepares and
sanitizes it, then creates the local unsigned Universal 2 app:

```sh
./build.sh --kit "/path/to/authorized kit" --theos "/path/to/theos" \
  --derived-data "/path/to/build output"
```

Paths containing spaces and non-ASCII characters are supported. If an
interactive macOS run omits Theos or points at a kit without `SHA256SUMS`, the
build opens a folder chooser and states exactly which directory to select.
Headless/CI builds never guess: pass absolute `--kit` and `--theos` paths.

This local build is not distributable.

To build a non-public release candidate, run:

```sh
scripts/build_release.sh --mode release-candidate --kit KIT --theos THEOS --output dist
```

The candidate runs the PII, kit-manifest, offline-install, architecture,
extracted-package, and EULA gates. Its audit states `FINAL_RESULT=BLOCKED`
until distribution signatures are present. To build a public Universal 2
package, run:

```sh
scripts/build_release.sh --mode distribution --kit KIT --output dist \
  --theos THEOS \
  --notary-profile PROFILE
```

When exactly one valid Developer ID Application identity and one valid
Developer ID Installer identity are available, the release builder selects
them automatically. If the Keychain contains more than one identity of either
type, use `security find-identity -v -p basic` and pass the intended SHA-1
fingerprints through `--app-identity` and `--installer-identity`. An Apple Development
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

Create a notarization profile without putting the app-specific password in
shell history:

```sh
xcrun notarytool store-credentials 0-sky-release \
  --apple-id YOUR_APPLE_ID --team-id YOUR_TEAM_ID
# Enter the app-specific password only when notarytool prompts.
python3 tools/environment_preflight.py --human --mode release \
  --kit KIT --theos THEOS --notary-profile 0-sky-release --skip-device
```

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
without that complete runtime is repaired by the canonical source/release build
from the pinned, SHA-256-verified archive lock. The installed application never
uses Homebrew or developer Python as a fallback. For a disconnected builder,
pre-populate `.build/host-runtime-cache` and run
`python3 tools/build_host_runtime.py KIT --offline`; a missing cache item prints
its exact URL, destination, expected hash, and verification command.

Run `python3 -m unittest discover -s tools/tests -q`,
`(cd bridge && swift run BridgeCoreTests)`, and the host-tool tests described
in the root [BUILDING.md](../BUILDING.md). Physical Intel execution, a clean
installation, an upgrade, and SRD operation require their corresponding
hardware/environment and must be recorded separately from slice verification.

The prepared external kit passes the blocking sanitizer gate. Raw upstream
build/debug strings remain visible as advisories, while actual Mach-O loader
paths are checked structurally. Exact hash-bound public test fixtures do not
authorize any other key material. Do not patch signed binaries in place or
bypass a structural/signature gate.
