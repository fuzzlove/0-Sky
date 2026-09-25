# Release procedure

Use a clean checkout and a separately obtained, authorized kit. Keep the kit,
signing identities, pairing records, SSH keys, provisioning profiles, and
generated device state outside Git. Verify the kit's provenance before use.
No personal Team ID or signing certificate is supplied by this repository.

1. Run `python3 tools/verify_eula.py` and review the canonical legal artifact
   under `bridge/0SkyBridge/Resources/Legal`. A changed text digest, version,
   or effective-date mismatch blocks release. Preserve the legal text unless
   the authorized document owner supplies a revision. The EULA version is
   independent of the app version.
2. Run `python3 tools/environment_preflight.py --mode release --kit KIT
   --skip-device`. A missing signing input is BLOCKED. A configured input is
   only a preflight signal; verify the actual certificate, entitlements, and
   provisioning on the final artifacts.
3. Run `python3 tools/prepare_release_kit.py KIT RELEASE_KIT`. Pass
   `--deny-file DENY.json` for release-specific hostnames, usernames, or other
   patterns. The JSON shape is `{"patterns":{"label":"regex"}}`.
4. Run `./build.sh --kit RELEASE_KIT --derived-data DERIVED_DATA` from any
   working directory. `ZERO_SKY_RELEASE_DENY_FILE` passes the same deny file
   to the Xcode embed gate. The build also verifies that the bundled
   `Contents/Resources/Legal/EULA.md` and `EULA.json` exactly match the
   canonical files; its output records EULA version and SHA-256.
5. Run `python3 tools/release_sanitize.py APP --deny-file DENY.json` and
   `python3 tools/pii_audit.py`. The gate scans text entries inside IPA/ZIP
   files and binary strings in the app, then reports category/member basename
   without printing matched data. `build.sh` runs this app-wide scan itself.
6. Sign and notarize the Mac app with the publisher's own credentials and
   required entitlements. Verify signatures and architecture slices after
   signing. The local `build.sh` output is unsigned and is **not** a public
   release artifact.
7. On a clean account, verify the complete first-launch EULA, unchecked
   acceptance controls, explicit Decline/Accept paths, and a persisted local
   version/digest/timestamp record. Verify a newer EULA requires acceptance
   again while an app-only update does not.
8. Install and test on the exact authorized SRD: USB detection, trust,
   pairing, CoreDevice, root SSH, Link icon and registration, Control, bridge,
   wireless reconnect where applicable, upgrade, uninstall/restore, and
   reinstall. Preserve the existing bootstrap and pairing material.

The scanner covers known high-confidence home paths, device IDs, private key
headers, embedded passwords, developer CoreDevice hostnames, local IPs,
temporary build paths, and configurable deny patterns. It does not prove that
opaque native binaries, DMGs, DEBs, or every archive format are free of all
possible PII. Audit those packages separately before distribution. A failed
scan blocks release; do not turn off validation to get a build through.

The currently supplied external kit contains home-directory build paths in
signed Frida and PreferenceLoader binaries. The release gate therefore fails
for this kit. Replace them with independently verified, sanitized, correctly
signed vendor/device payloads and update the kit manifest before publishing.
Do not strip signed binaries in place; that would invalidate their signatures.

Source tests, the arm64 local build, and generated Link IPA were exercised in
this checkout. Intel execution, a fresh machine without the external kit,
publisher signing/notarization, and the full iOS 17–27+ live matrix require
their corresponding hardware and assets. Report these as unverified until
actually exercised; an unsigned local build is not release approval.
