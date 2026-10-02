# Privacy and secret gate for public installers

Run the automated release pipeline; do not approve an installer from a source
scan alone. It checks the staged app and expands the signed package to inspect
the actual payload. The scanner covers filenames, symlink targets, text,
native binary strings, and nested IPA/ZIP members without printing matched
secrets. Large files are streamed in full. A temporary mode-0600 denylist adds
the current builder's home, username, hostname, checkout, and staging paths.
The denylist itself never enters the app or installer.
Use `tools/kit_pii_report.py` to write a private per-file finding inventory;
the report is never packaged. The scanner also rejects mounted-volume paths,
DerivedData strings, and absolute file URIs.

- Confirm `FINAL_RESULT=PASS` in `dist/RELEASE_AUDIT.txt` and no sanitizer
  findings. Review any source attribution, bundle ID, certificate identity,
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
- Record Apple Silicon and Intel installation/launch results separately from
  architecture inspection. Keep internal symbols under controlled access.

The current supplied kit fails this checklist: several signed device binaries
retain builder home paths. The unsigned local app also has pattern matches
inside compressed wheels and Debian packages, plus a legacy personal-payment
URL inside a bundled IPA. Distinguish upstream public fixtures from genuine
secrets through provenance review; do not ship a candidate while high-confidence
findings remain. Obtain clean inputs and rerun all gates. Changing bytes inside
an existing signed binary or suppressing a scanner finding is not remediation.
