# External kit review status

The ignored `bridge/0SkyBridge/Resources/Scripts/kit` tree is an input, not a
canonical source tree. The source-controlled Link app and host scripts can be
rebuilt, but Frida, ElleKit, PreferenceLoader, Commissary, device Python
packages, and several wheel files arrive as already-built external artifacts.
Their provenance and source/build recipes are not present in this checkout.

Run `python3 tools/kit_pii_report.py KIT artifacts/release-kit-pii.json` for a
private mode-0600 record with `FILE`, `LINE_OR_KEY`, `CATEGORY`,
`ORIGINAL_VALUE`, and `REQUIRED_ACTION`. Secret-bearing values are redacted.
Do not commit or package that report.

| Finding class | Current disposition | Required control |
| --- | --- | --- |
| Home, DerivedData, and mounted-volume strings | Retained upstream source/debug strings are advisory, not runtime paths. | `verify_release.py` inspects Mach-O load commands and fails if an actual dependency or effective RPATH points to a developer location. Rebuild/re-sign only when that structural gate fails. |
| Key-header/test-key patterns | Parser header constants are not keys. Known public CPython/PyCryptodome test keys are advisory only when exact archive hash, category, and member prefix match the reviewed exception manifest. | Changed bytes or another member fail closed. Never add a global category exception. End-user keys are generated after install and cannot be bundled. |
| Local-address, file-URI, and payment strings | Reported as review advisories when they occur in examples, metadata, documentation, or upstream payload UI. | Keep the private detailed report; exact release-owned hostname, address, email, device ID, credentials, or custom deny patterns remain blocking. |

The raw local kit also contained one current-workstation home path in generated
`host-mac/__pycache__/install.*.pyc`. That finding is fixed: release and Link
staging omit `__pycache__`, `.pyc`, and `.pyo` entries even when an input
manifest lists them. Offline validation sets `PYTHONDONTWRITEBYTECODE=1` and
the prepared tree is pruned before its final manifest. Regression coverage
verifies that no interpreter cache remains.

The former host-runtime blocker is resolved: the canonical pipeline assembles
the pinned arm64/x86_64 CPython runtime and compatibility helpers, verifies its
manifest, and retains its license notices. The prepared kit now passes the
blocking privacy scan while preserving an advisory summary for provenance
review. Generating a hash manifest alone does not make an arbitrary kit
approved. The pipeline writes
`RELEASE_KIT_APPROVAL.json` only after PII, portability, architecture, offline
installation, and integrity checks pass.

The current wheel inventory contains 117 artifacts and 743 declared dependency
edges; three wheels do not declare license metadata in their package records.
The pinned arm64 environment installs from the wheelhouse with `--no-index`,
and static wheel coverage checks both Mac architectures. Intel execution and
a completely offline bare-Mac install remain unverified. The prepared kit now
receives the self-contained macOS Python 3.12 runtime; Xcode and Apple SRD host
assets remain builder- or program-supplied inputs and are not redistributed as
device payloads.

The source-controlled Control blocker is no longer in this list. A clean
3.5.36 arm64/rootless build completed with an explicit Theos checkout, and two
independent canonical IPA staging runs produced identical bytes. Live SRD
installation remains unexecuted.
