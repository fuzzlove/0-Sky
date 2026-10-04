# Installing 0-Sky

## Recommended path: verified macOS package

Use one audited 0-Sky release directory containing exactly:

- `0-Sky-Bridge-<version>-distribution-universal.pkg`
- `RELEASE_AUDIT.txt`
- `RELEASE_MANIFEST.json`
- `SHA256SUMS`

Do not install a development or release-candidate package on the assumption
that it is a public release. Its audit result is deliberately `BLOCKED`.

1. On the Mac that will control the SRD, verify the downloaded directory:

   ```sh
   python3 tools/release_manifest.py verify /path/to/0-sky-release
   scripts/verify_release.sh \
     --release-directory /path/to/0-sky-release \
     --report /tmp/0-sky-independent-audit.txt
   ```

   The second command expands the package, validates its single allowlisted app
   payload, signatures, architectures, EULA, embedded kit, permissions, and
   privacy gates. A distributable build must end with `RELEASE_GATE=PASS`.

2. Open the verified `.pkg`. macOS may request administrator approval because
   the package installs `0SkyBridge.app` in `/Applications`; the package has no
   installer scripts and does not modify the SRD.
3. Open **0-Sky Bridge**, review the EULA, and choose **Install All 0-Sky
   Requirements**. A release package uses its bundled, manifest-verified
   Universal 2 Python and host tools; it does not require developer Python or
   Homebrew. Development builds may use an existing Homebrew after explicit
   review, but 0-Sky never downloads and executes Homebrew's moving bootstrap
   script. Pinned Python dependencies remain in 0-Sky-owned environments.
4. Connect and unlock the authorized SRD over USB. Approve Apple's Trust prompt,
   select that device in Bridge, and run setup. Bridge binds the profile and
   USB forwarding to the selected device's exact UDID; it never silently uses
   the first connected device.
5. Re-run the health check. Treat missing exact-build assets, pairing, root SSH,
   or worker proof as blockers rather than bypassing them.

The primary UI action is **Set Up Bridge and SRD**. **Repair** reruns only
supported convergence checks, **Resume** re-enters an interrupted persisted
stage, **Diagnostics** produces a redacted report, and device removal previews
an exact-device host-side uninstall. The setup controller also supports a
headless exact-device resume:

```sh
"/Applications/0SkyBridge.app/Contents/Resources/Kit/host-mac/runtime/bin/python3" \
  "/Applications/0SkyBridge.app/Contents/Resources/Scripts/0sky_project_setup.py" \
  --setup --resume --udid EXACT_UDID
```

See the evidence-scoped [compatibility matrix](docs/SUPPORTED_PLATFORMS.md).

There is currently no verified public binary installer built from the local
external kit described in [RELEASE.md](RELEASE.md). Signed payloads containing
builder paths must be replaced and rebuilt; do not edit them in place.

## Upgrade and repair

- **Upgrade:** verify and run the newer package, then reopen Bridge and run the
  dependency/setup checks. Per-device profiles are preserved and manifest
  revisions are validated before reuse.
- **Repair dependencies:** choose **Install All 0-Sky Requirements** again. The
  installer is idempotent: valid tools and environments are reused, incomplete
  managed environments fail with a repair instruction, and per-device services
  are not duplicated.
- **Repair one device profile:** connect only the intended SRD, select it in
  Bridge, and rerun setup. CLI recovery requires `--udid EXACT_UDID`; see
  [Troubleshooting](docs/TROUBLESHOOTING.md).

## Reversible host-side uninstall

Preview removal before applying it:

```sh
python3 "/Applications/0SkyBridge.app/Contents/Resources/Kit/host-mac/uninstall.py" \
  --instance-name INSTANCE --udid EXACT_UDID
```

Apply the exact-device plan only after reviewing the counts:

```sh
python3 "/Applications/0SkyBridge.app/Contents/Resources/Kit/host-mac/uninstall.py" \
  --instance-name INSTANCE --udid EXACT_UDID --apply
```

The command stops and moves only matching Mac-side LaunchAgents and state into
an owner-only rollback directory. It does not alter Apple pairing, the device,
the bootstrap, or research evidence. The command prints the rollback identifier.
Remove `0SkyBridge.app` through Finder only after the host-side plan succeeds.

## Source/developer build

A Git checkout is not a complete installer. It intentionally omits signing
credentials, Apple assets, signed device payloads, and the external wheelhouse.
Developers should follow [BUILDING.md](BUILDING.md); release engineers should
use only `scripts/build_release.sh` as documented in [RELEASE.md](RELEASE.md).
The root `setup_0sky_devices.*` files are compatibility wrappers around the one
canonical state machine, `bridge/macos_host_setup.py`; they do not implement
independent installers.
