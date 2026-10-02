# LocalFence SRD repair

Repaired on 2026-09-26 on the paired SRD `<SRD_UDID>`,
iOS 27.0 build `24A437`, LocalFence 0.2.1.

The installed client and daemon could not execute. The Procursus launchctl
also imported `_launch_active_user_switch`, which this OS does not export.
The network utilities were killed at launch, and the daemon's app path check
did not recognize LaunchServices' Bundle/Application installation path.

`repair_localfence.py` signs staged copies of the client, patched daemon,
route and arp; includes the unchanged signed libiosexec dependency; and
builds a compatible launch helper from the local LaunchKit sources. The
peer-path adaptation follows the existing iOS 27 support patch and retains
the daemon's UID and executable-suffix checks.

The complete runtime is an Apple-authorized persistent research Cryptex,
`com.emp0ry.localfence.srd-repair2`. Its single-volume APFS image uses the
working SRD SSH image layout. The initial partitioned image encountered
mount failures; the single-volume image installed successfully with a fresh
domain-3 nonce and live Apple TSS authorization. Existing app Cryptexes and
the global Procursus launchctl were preserved.

## Verify the installed repair

Run from this directory:

```sh
../../.venv/bin/python repair_localfence.py \
  --udid "$SRD_UDID" --verify
```

This restarts only LocalFence, checks its status, and compares installed
code against the trusted mounted runtime. For inspection without restart,
omit `--verify`.

Verified: daemon running as root; restart succeeds; status returns `ok: true`
with interface `en0`, gateway and subnet; no active blocks; mobile-owned
socket mode `0600`; all five installed code files match the research runtime.
The Cryptex contains a KeepAlive/RunAtLoad daemon definition. A full device
reboot, app UI interaction, active discovery and blocking were not tested.

Reports and build assets are in `localfence-repair-v2/`, especially
`verification.json`, `activation.json`, `payload-sha256.json`, and
`active-build.json`. All Cryptex asset SHA-384 digests were verified against
the BuildManifest, and staged executables passed strict codesign verification.

## Build and activate on a fresh matching installation

Do not reinstall the already installed runtime. The installer refuses to
replace an existing identifier. These commands describe the tested sequence:

```sh
../../.venv/bin/python diagnose_localfence.py \
  --udid "$SRD_UDID" \
  --output compatibility-work/localfence-live-before.json
../../.venv/bin/python repair_localfence.py \
  --udid "$SRD_UDID" --collect-network-tools
../../.venv/bin/python repair_localfence.py \
  --udid "$SRD_UDID" --build
../../.venv/bin/python repair_localfence.py \
  --udid "$SRD_UDID" --build-cryptex --flat-image
../../.venv/bin/python repair_localfence.py \
  --udid "$SRD_UDID" --install-runtime
../../.venv/bin/python repair_localfence.py \
  --udid "$SRD_UDID" --activate
../../.venv/bin/python repair_localfence.py \
  --udid "$SRD_UDID" --verify
```

Use a new `--output` directory when rebuilding. Activation verifies the
mounted payload and dependency hashes, saves the original four binaries,
then atomically replaces them. Failed status validation restores those
originals. The successful activation's device backup is:

`/var/jb/var/lib/localfence-srd/backups/20466078-f2fd-4c23-9454-39fa1a19bec1`

Its `before.json` records original hashes; the backup contains
`localfencectl`, `localfenced`, `route`, and `arp`. Preserve this directory
and the host build artifacts for rollback. Package upgrades can replace the
repaired binaries; run verification afterward.
