# Privacy and secret gate for public installers

Run the automated release pipeline; do not approve an installer from a source
scan alone. It checks the staged app and expands the signed package to inspect
the actual payload. The scanner covers filenames, symlink targets, text,
native binary strings, and nested IPA/ZIP members without printing matched
secrets. Large files are streamed in full. A temporary mode-0600 denylist adds
the current builder's home, username, hostname, checkout, and staging paths.
The denylist itself never enters the app or installer.
Use `tools/kit_pii_report.py` to write a private per-file finding inventory;
the report is never packaged. The scanner reports mounted-volume paths,
DerivedData strings, absolute file URIs, private-network examples, and raw
build prefixes as advisories. Exact release-owned identity values,
credentials, real private-key material, unsafe archives, and nonportable
Mach-O load commands remain blockers.

- Confirm `FINAL_RESULT=PASS` in `dist/RELEASE_AUDIT.txt`, zero **blocking**
  sanitizer findings, and a reviewed advisory summary. Review any source attribution, bundle ID, certificate identity,
  and legal contact information as intentional public metadata.
- Confirm the package payload is only `Applications/0SkyBridge.app`; there is
  no `.git`, `.env`, SSH material, pairing record, certificate export, build
  log, DerivedData, symbol archive, or untracked workspace file.
- Confirm the canonical EULA version/content/digest match the bundle and the
  application's explicit acceptance workflow remains intact.
- Confirm `RELEASE_KIT_APPROVAL.json`, `RELEASE_KIT_MANIFEST.json`,
  `WHEEL_INVENTORY.json`, and `SHA256SUMS` validate after embedding and after
  nested code signing. The default dependency command must remain offline.
- Confirm Mac binaries are Universal 2 and device binaries remain correctly
  signed for their own platform. Verify signatures after every byte change.
- Confirm installer signing and Gatekeeper assessment. If a notary profile was
  configured, confirm acceptance and staple validation.
- Confirm native members inside the offline wheelhouse and split-architecture
  Python runtime have Developer ID signatures with secure timestamps; confirm
  wheel `RECORD`, wheel inventory, and kit hashes were regenerated afterward.
- Record Apple Silicon and Intel installation/launch results separately from
  architecture inspection. Keep internal symbols under controlled access.

The currently prepared kit has passed the blocking sanitizer gate and reports
the reviewed upstream/debug strings as advisories. Public test-key exceptions
are bound to exact outer-archive hashes and member prefixes; any artifact
change invalidates the exception. User-specific keys are generated only after
installation and remain outside distributable content. Changing bytes inside
an existing signed binary or adding a broad exception is not remediation.
