# 0-Sky 1.0.0 pre-release 14

This experimental replacement fixes the managed-Python migration failure found
during live Intel fresh-SRD testing of pre.13.

## Host runtime repair

- Packaged setup now accepts a per-user or per-device Python environment only
  when its base interpreter resolves inside the signed Universal host runtime.
- A healthy older environment backed by Homebrew or python.org is shown as
  **Repair required**, not **Available**.
- **Install All 0-Sky Requirements** preserves the previous environment under
  the private `0-Sky/recovery` directory, rebuilds fully offline from bundled
  Python and locked wheels, validates the new base and dependencies, and
  restores the previous environment if rebuilding fails.
- Complete Project and later pairing/repair operations print the exact GUI
  recovery sequence instead of the generic `Invalid or unapproved path` error.
- Device discovery does not silently reuse an unapproved machine-local Python.

## Signed dependency integrity

- Release signing now refreshes the path-confined Frida wheel checksum
  allowlist after native wheel members are signed and their RECORD files are
  regenerated. The signed outer kit and the guided offline installer therefore
  agree on the same bytes.

## Retained pre.13 fixes

- Fresh SRDs enter the exact-device RemoteXPC pipeline before SSH pairing.
- The source-controlled SRDssh bootstrap and Cryptex adapter are shipped rather
  than fail-closed placeholders.
- Safe contained runtime symlinks pass manifest verification.
- iOS 26 and iOS 27 use their validated GenericDmg image slots.
- Duplicate-profile recovery and detailed owner-only pairing logs remain.

## Evidence boundary

The original failure was reproduced on MacBookPro16,1 (`x86_64`) running macOS
26.5.2: the managed venv resolved to an external Homebrew interpreter and the
signed app's allowlist blocked it. The corrected repair preserved that venv and
rebuilt the locked dependency environment from the signed bundled Python.
Read-only exact-SRD RemoteXPC, nonce, and live TSS authorization had already
passed. Full device mutation and post-install health remain hardware UAT and are
not claimed by this release note.
