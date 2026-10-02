# 0-Sky Manual Conversion Findings

This report compares retained originals and working derivatives without executing package scripts. Candidate rules remain `EXPERIMENTAL` until their validations and rule promotion requirements pass.

## Compared pairs

| Pair | Relationship | Added | Removed | Content changes | Mode changes | Mach-O changes |
|---|---:|---:|---:|---:|---:|---:|
| `trollrecorder-zip-normalization` | deterministic_packaging_repair | 0 | 0 | 0 | 0 | 0 |
| `srdzsh-2.0.4-final-signing` | iterative_working_build | 0 | 0 | 3 | 0 | 0 |
| `doodle-binary-to-source-port` | cross_version_source_port | 0 | 31 | 3 | 0 | 1 |
| `doodle-port-package-evolution` | iterative_adapted_package | 0 | 0 | 2 | 0 | 0 |
| `sileo-havoc-auth-evolution` | iterative_source_rebuild | 0 | 0 | 1 | 0 | 1 |

## Findings

### trollrecorder-zip-normalization

Relationship: `deterministic_packaging_repair`.

Original SHA-256: `ffddee2dea5c407ff435d18348b20119f24f6da935ea99ec0ca247eeb46916ac`

Working SHA-256: `02f90c91d9df7c3c963fbdfef71394dc34f5648d9ecb35ae47a084b379c79adb`

Changed payload files: 0; added: 0; removed: 0; mode changes: 0.

Every extracted member byte and Unix mode is identical. The derivative changes ZIP compression from Stored/LZMA to Deflate so the authorized SRD installer can extract it.

### srdzsh-2.0.4-final-signing

Relationship: `iterative_working_build`.

Original SHA-256: `83be26b15c233a9ad075e9000392f2d1dbe697ebb07fef1c403b5af43cc6aabe`

Working SHA-256: `4783100d08c8d4156c0046150dee08d0c5a8a1ef8742563e33fa0b13224b527b`

Changed payload files: 3; added: 0; removed: 0; mode changes: 0.

Changed files:

- `Payload/SRDZsh.app/SRDZsh`
- `Payload/SRDZsh.app/_CodeSignature/CodeResources`
- `Payload/SRDZsh.app/usr/libexec/srdzsh-rootd`

### doodle-binary-to-source-port

Relationship: `cross_version_source_port`.

Original SHA-256: `4725c0170e89413308b8434e4f1e80fc7357880e628d87af76c9e45920aa656a`

Working SHA-256: `3bd29448716730774e20583f1b634b44cf7c2879a8cd949742ff9835c591c24f`

Changed payload files: 3; added: 0; removed: 31; mode changes: 0.

This is source port evidence across different upstream versions. It cannot establish that the supplied binary was deterministically converted, so it is excluded from automatic rule reproduction claims.

### doodle-port-package-evolution

Relationship: `iterative_adapted_package`.

Original SHA-256: `0a1c5442bc5933ff0b3f6a58279e615951546981d28fbfcab006ce3ad5bbd6a6`

Working SHA-256: `3bd29448716730774e20583f1b634b44cf7c2879a8cd949742ff9835c591c24f`

Changed payload files: 2; added: 0; removed: 0; mode changes: 0.

Changed files:

- `DEBIAN/control`
- `var/jb/Library/MobileSubstrate/DynamicLibraries/Doodle.plist`

### sileo-havoc-auth-evolution

Relationship: `iterative_source_rebuild`.

Original SHA-256: `43116eaed755d2b4aff6b625fc5bbc5a1a87c64d0ee59aa0fb2ec4ba7a7dbc57`

Working SHA-256: `08b7459f6597015ccc7371b05843a5b24223cca5a2deaee4256971ff4567f919`

Changed payload files: 1; added: 0; removed: 0; mode changes: 0.

Changed files:

- `Payload/Sileo.app/Sileo`

## Generated candidate rules

- `zip-compression-normalization-v1` — Normalize unsupported IPA/TIPA ZIP compression (HIGH, EXPERIMENTAL)
- `authorized-resign-after-source-build-v1` — Refresh authorized signatures after a controlled source build (MANUAL, EXPERIMENTAL)
- `legacy-plist-canonicalization-v1` — Canonicalize a parseable legacy tweak filter plist (HIGH, EXPERIMENTAL)

## Evidence gaps

- **TrollDecrypt 0-Sky**: The tested adapted IPA exists, but an untouched upstream IPA from the pinned source revision is not retained as a comparison artifact. Source and patch provenance are retained instead.
- **Filza**: Device repair and runtime evidence exists, but no authoritative untouched/working artifact pair is retained locally.

## Conclusions

Two HIGH-confidence deterministic conversions reproduce retained working artifacts byte for byte: ZIP compression normalization for TrollRecorder and locked legacy plist canonicalization for the Doodle port. Source rebuild and signing differences remain manual or component-specific until stronger repeated evidence exists.
