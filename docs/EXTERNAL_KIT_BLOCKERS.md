# External kit release blockers

The ignored `bridge/0SkyBridge/Resources/Scripts/kit` tree is an input, not a
canonical source tree. The source-controlled Link app and host scripts can be
rebuilt, but Frida, ElleKit, PreferenceLoader, Commissary, device Python
packages, and several wheel files arrive as already-built external artifacts.
Their provenance and source/build recipes are not present in this checkout.

Run `python3 tools/kit_pii_report.py KIT artifacts/release-kit-pii.json` for a
private mode-0600 record with `FILE`, `LINE_OR_KEY`, `CATEGORY`,
`ORIGINAL_VALUE`, and `REQUIRED_ACTION`. Secret-bearing values are redacted.
Do not commit or package that report.

| Failure class | Root cause | Required remediation |
| --- | --- | --- |
| Home and DerivedData paths in iOS Mach-O | External Frida, ElleKit and PreferenceLoader binaries retain source/build paths; the existing Link IPA repeats them. | Obtain canonical source and reproducible build instructions, rebuild for the required device platform, validate entitlements and signatures, then update the external kit manifest. |
| Mounted-volume paths in Mac native wheels | Both Frida wheel variants contain their original build-volume path. | Replace with verified wheels built from clean source; audit native members for both Mac architectures. |
| Key/password patterns in device Python payload | The external Python runtime includes test fixtures and nested pip/wheel material. | Review canonical package contents and produce a minimal runtime package from source, documenting every omission and proving the offline install still works. |
| Local-address and absolute-file URI strings | External wheels and device Python include examples, metadata, or compiled constants. | Classify each value from authoritative source; rebuild or replace where machine-specific. Do not globally allowlist patterns. |
| Personal payment URL in Commissary | A prebuilt device application/package embeds a payment account URL. | Change its canonical source and rebuild/re-sign the device payload; verify the resulting IPA and Debian archive. |

The raw local kit also contained one current-workstation home path in generated
`host-mac/__pycache__/install.*.pyc`. That finding is fixed: release and Link
staging now omit `__pycache__`, `.pyc`, and `.pyo` entries even when an input
manifest lists them. Regression coverage verifies the output count and absence
of those files. This does not waive the separately listed opaque third-party
binary findings.

The former host-runtime blocker is resolved: the canonical pipeline assembles
the pinned arm64/x86_64 CPython runtime and compatibility helpers, verifies its
manifest, and retains its license notices. The candidate now reaches the full
`PREPARE_KIT` privacy scan and stops on the external payload findings above.
Generating a hash manifest for the dirty kit does not make it approved. The pipeline writes
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
