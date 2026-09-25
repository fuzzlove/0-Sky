# Building from a clean checkout

Supported host source-build targets are macOS 15+ on arm64 or x86_64, with
Xcode/Command Line Tools providing Swift 6, the macOS 15 SDK, and a compatible
iPhoneOS SDK. Select Xcode with `xcode-select` or `DEVELOPER_DIR`. Python 3.12,
OpenSSH, and the documented dependencies in [REQUIREMENTS.md](REQUIREMENTS.md)
are required for the full host workflow. The optional `iproxy` and
`idevice_id` tools improve diagnostics and USB forwarding. Use the installer
for the pinned, isolated Python runtime; do not rely on a developer's global
site packages.

The Git checkout contains source but intentionally excludes the proprietary
and generated SRD kit, wheelhouse, Apple-derived assets, signed device
payloads, and signing credentials. A clean checkout can run source tests and
preflight. A complete app build requires an **externally supplied kit** with a
valid `SHA256SUMS` manifest and the required Link payload slot. Source-only
checkout builds fail with an actionable missing-kit error, not a hidden
dependency on a former installation.

The canonical EULA is `bridge/0SkyBridge/Resources/Legal/EULA.md`; its
independent version, effective date, and SHA-256 digest are in the adjacent
`EULA.json`. Run `python3 tools/verify_eula.py` before building. The Xcode app
copies both files to `Contents/Resources/Legal`; the Swift package copies the
same canonical directory into its resource bundle. Neither build uses a
developer workstation path to find the agreement.

```sh
REPO=/path/to/0-Sky
KIT=/path/to/authorized-kit
python3 "$REPO/tools/environment_preflight.py" --mode development --kit "$KIT" --skip-device
python3 "$REPO/tools/prepare_release_kit.py" "$KIT" /path/to/work/release-kit
"$REPO/build.sh" --kit /path/to/work/release-kit --derived-data /path/to/work/derived
```

`prepare_release_kit.py` verifies manifest-listed inputs, stages a Link kit
without recursive IPA/test fixtures, rebuilds Link, verifies its identity,
icon, and signature, runs the release PII gate, and publishes the prepared kit
atomically. `build.sh` accepts `--kit` and `--derived-data` (or the corresponding
`ZERO_SKY_*` variables), builds Intel and Apple-silicon slices, verifies the
Mac binary and Bluetooth helper slices, and checks the embedded Link IPA. It
produces an **unsigned** local app under the chosen derived-data directory.
The build requires the prepared kit's deterministic `PORTABILITY.json` marker;
passing the raw external kit directly is rejected.

The final app-wide sanitization gate currently blocks distribution with this
local external kit because several signed device binaries retain their
builders' home-directory paths. The Mac executable's debug/source paths are
stripped safely because this local output is unsigned. Replacement signed
device payloads are required for a passing release build; see
[RELEASE.md](RELEASE.md).

For source regressions, run:

```sh
cd "$REPO"
python3 -m unittest discover -s tools/tests -v
cd bridge
swift run BridgeCoreTests
```

Host-tool tests require Python 3.12 with the pinned `cryptography` wheel. An
isolated test environment can use the kit wheelhouse with `pip --no-index`
and `--find-links`, then run `python -m unittest discover -s
bridge/Tests/HostToolsTests -v` from the repository root. One test binds a
loopback socket and requires a test environment that permits that operation.

To inspect one SRD without changing it, run preflight with `--udid EXACT_UDID`.
USB trust, CoreDevice availability, root SSH, and device payload validation
remain separate checks. iOS/iPadOS 17+ is the minimum target; 27+ is a
capability probe, not a guarantee that every future OS build has matching
Apple or project payloads.
