# 0-Sky reproducibility checkpoint

This checkpoint preserves the current source state for 0-Sky Link, Control,
Bridge, installation/repair workflows, package conversion, SRD tooling, and
the AFC2 research branch. It is source-first: device-derived Apple binaries,
signing secrets, pairing records, raw device backups, generated cryptex roots,
and unsanitized logs are deliberately excluded.

## Supported checkpoint target

- Mac host: Apple silicon, macOS 26.5.1 (`25F80`)
- Xcode: 26.6 (`17F113`)
- iPhoneOS SDK: 26.5; deployment target 26.0 where applicable
- SRD hardware: `iPhone13,2` (iPhone 12), arm64e
- SRD OS: iOS 27.0, build `24A5390f`
- Canonical source: `https://github.com/fuzzlove/0-Sky`

Other device builds are not covered by the exact-build AFC2 experiments.

## Required operator-supplied inputs

Set paths and identifiers in the shell; never edit them into tracked files:

```sh
export ZERO_SKY_CHECKOUT=/path/to/0-Sky
export SRD_UDID='<selected-authorized-SRD-UDID>'
export SRD_INSTANCE=/path/to/operator/instance
export SRD_RECOVERY_DIR=/path/to/encrypted/recovery/location
export IOS_DEVELOPMENT_IDENTITY='<keychain identity name>'
export SRD_REPO_PATH=/path/to/apple/security-research-device
```

Acquire `srdtool` from Apple's authorized SRD repository and verify it using
that repository's documented build/help flow. It was unavailable on the
checkpoint host, so cryptex lifecycle restoration was not rehearsed.

For the AFC2 host build, independently extract `/usr/libexec/afcd` and
`/usr/libexec/lockdownd` from an authorized `iPhone13,2` on exact build
`24A5390f`. Verify the hashes in `manifest.json`. These Apple binaries are not
redistributable checkpoint content.

Signing inputs are supplied from the operator's Keychain or documented Apple
developer workflow. No private key, certificate payload, profile, token,
password, or pairing record is included. Ad-hoc-signed research binaries must
still be admitted through the authorized SRD trust/cryptex workflow.

## Fresh Mac restore

1. Install Xcode 26.6 and select it:

   ```sh
   sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
   xcodebuild -version
   xcrun --sdk iphoneos --show-sdk-version
   ```

2. Install host prerequisites: Git, Python 3, GNU Make, `dpkg-deb`, `ldid`,
   and a Python environment containing `pymobiledevice3==11.3.1` plus the
   dependencies captured in `manifest.json`.

3. Clone and restore the checkpoint. Replace the tag after reading the final
   checkpoint record in `STATE.md`:

   ```sh
   git clone https://github.com/fuzzlove/0-Sky.git "$ZERO_SKY_CHECKOUT"
   git -C "$ZERO_SKY_CHECKOUT" checkout 0sky-reproducibility-2026-10-02-r2
   python3 "$ZERO_SKY_CHECKOUT/scripts/reproducibility/verify_manifest.py" \
     --repo "$ZERO_SKY_CHECKOUT"
   ```

   An archive restore is also supported: verify its `.sha256`, extract it,
   and use the extracted root as `ZERO_SKY_CHECKOUT`.

4. Recreate independent source trees and apply the checkpoint patches:

   ```sh
   "$ZERO_SKY_CHECKOUT/scripts/reproducibility/restore.sh" \
     --source "$ZERO_SKY_CHECKOUT" \
     --dest /tmp/0-sky-restored \
     --ref 0sky-reproducibility-2026-10-02-r2 \
     --prepare-external \
     --create-venv --python /opt/homebrew/bin/python3.12
   ```

5. Build/validate without touching a device:

   ```sh
   cd /tmp/0-sky-restored/bridge
   swift test
   cd ../control/TrollStoreLite
   python3 tests/test_device_compatibility.py
   cd ../../
   .venv/bin/python -m unittest discover -s tools/tests -p 'test_*.py'
   ```

6. Optionally reproduce the host-only AFC2 packages after supplying the two
   exact-build Apple inputs:

   ```sh
   scripts/reproducibility/restore.sh \
     --source . --dest /tmp/0-sky-afc2 \
     --ref 0sky-reproducibility-2026-10-02-r2 \
     --afcd-input /secure/input/afcd \
     --lockdownd-input /secure/input/lockdownd \
     --build-afc2
   ```

## Device setup and validation

Device-changing steps are intentionally not automated by the restore script.
Before any future AFC2 experiment:

1. Select exactly one authorized SRD with `SRD_UDID`; confirm ProductType
   `iPhone13,2` and BuildVersion `24A5390f` read-only.
2. Use official `srdtool` documentation to check in/configure the device and
   verify the current stable cryptex. Do not reuse pairing material from the
   old Mac.
3. Create an encrypted stable recovery export in `SRD_RECOVERY_DIR`; record
   its checksum outside Git and test the rollback command.
4. Repair/pin SSH trust interactively for this host. The checkpoint host's
   prior pin was stale, so no SSH-derived package inventory is asserted.
5. Run the read-only AFC test first:

   ```sh
   python3 tools/test_afc2_live.py --udid "$SRD_UDID"
   ```

6. Only after reviewing the recovery path may an operator invoke the existing
   device installer manually with its explicit UDID, instance, and recovery
   arguments. The checkpoint scripts never invoke it.

## Secrets and private recovery material

No private recovery bundle was created because all source changes are
reproducible and the remaining non-exportable inputs must be reacquired. A
private operator bundle, if later needed, must be encrypted and kept outside
Git. It may contain only separately acquired signing material and recovery
receipts; it must never be copied into this repository or source archive.
