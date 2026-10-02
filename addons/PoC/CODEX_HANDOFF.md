# Codex task: simple Python PoC for 0-Sky Control and 0-Sky Link

Work on this Mac using the filesystem and terminal tools available to Codex.
Inspect `$ZERO_SKY_ROOT` as the reference project. Create a simple
Python 3 PoC in `$ZERO_SKY_ROOT/addons/PoC` that installs **0-Sky
Control** and **0-Sky Link** as Apple-authorized research cryptexes, registers
both apps, and verifies their Home Screen icons. Finish the implementation
and document a reproducible command. Keep the PoC small; reuse the working
helpers already here where practical.

## Scope and access

- Read the reference repository and existing PoC before changing anything.
- Write new code and documentation inside the PoC directory. Preserve existing
  source changes, archives, pairing records, keys, profiles, and installed apps.
- Use the caller's paired Apple Security Research Device and exact UDID. Use
  supported research services, a fresh nonce, and live Apple TSS authorization.
- The user authorizes installing the two named app cryptexes. Make reboot an
  explicit CLI option. Use Codex's normal approval mechanism for filesystem,
  network, or device operations that require escalation.
- Do not expose private keys or bridge tokens. Use the existing paired,
  host-key-pinned SSH profile if registration requires it.

## Inputs

Control IPA:
`$ZERO_SKY_ROOT/addons/Commissary-Universal-signed.ipa`

Link IPA:
`$ZERO_SKY_ROOT/addons/PoC/0-Sky-Link-1.9.0-universal.ipa`

Expected bundle IDs:

- Control: `com.liquidsky.CrypStore`
- Link: `codes.liquidsky.research.zerosky`

Inspect archive metadata rather than inferring display names or IDs from
filenames. The supplied Control IPA declares version 3.4.4/build 3.4.4.4.
Do not also install `CrypStore-2.5.0.deb`: it shares Control's bundle ID.

## Existing working implementation

Read these files in the PoC directory:

- `RESEARCH_CRYPTEX_POC.md`: workflow, tested outcomes, and limitations.
- `load_packages_as_cryptex.py`: stages packages, optionally signs them, and
  builds one Cryptex1 bundle per package.
- `make_cryptex.py`: builds with Apple's `cryptexctl create` and verifies
  manifest-bound asset digests.
- `install_built_cryptex.py`, `research_cryptex_poc.py`, `cryptex_native.py`:
  exact-device RemoteXPC personalization and installation.
- `device_python.py`: selects the pinned device Python environment.
- `register_mounted_app.py`: registration over the existing paired SSH route.
- `check_app_icon.py`: verifies the app in SpringBoard's icon layout.

Signing reference:
`$ZERO_SKY_ROOT/bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py`

Verified registrar assets and bootstrap references:
`$ZERO_SKY_ROOT/addons/PoC/appregistrard-build/stage-zero/dstroot/System/Applications/ZeroSky.app/SRDKit`

Use the registrar matching the device's actual OS build; verify its provenance.
Do not select a different build merely because this Mac has its assets.

## Dependencies and known pitfalls

- Working device interpreter:
  `$ZERO_SKY_ROOT/.venv/bin/python`
- Verified environment: Python 3.12.14, `pymobiledevice3==11.3.1`.
  The default `python3` previously lacked these device libraries.
- Apple SRD tool:
  `/System/Library/SecurityResearch/usr/bin/cryptexctl`
- Check `ditto`, `codesign`, `otool`, `xattr`, and `ldid` before signing/building.
  Require `dpkg-deb` only if handling Debian inputs or runtime package recovery.
- Find pinned requirements/offline wheels in the reference repository. Reuse
  the reviewed environment; do not silently install unpinned latest versions.
- Sign staged copies, preserving appropriate entitlements and nested code.
  The supplied Control bundle failed strict signature verification before
  staging/signing. Link contains an unsigned embedded helper. Leave the source
  IPAs untouched and verify the staged code.
- Use `cryptexctl create --use-cryptex1-format` to create images. The legacy
  manual APFS-sealing builder intermittently selected an invalid disk.
- Cryptex1 output already contains an IM4P `gtgv` asset. Do not wrap it again.
  Use the matching `ginf`; keep personalization digests consistent with the
  exact installed bytes.
- A successful cryptex mount does not prove app registration or icon visibility.
- Do not bootstrap the full 0-Sky package stack automatically just to install
  these apps. Diagnose and report any required missing registration dependency.

## Requested interface

Provide one entry point, such as `install_0sky_apps.py`, with defaults for the
two IPA paths and options for `--control-ipa`, `--link-ipa`, `--output`,
`--device-python`, `--udid`, `--doctor`, `--install`, and `--reboot-for-icons`.

Without `--install`, build and validate artifacts without device mutation.
With `--install`, require the exact UDID, install both cryptexes, register the
apps, and verify icons. Preflight dependencies and authorization before
replacing an existing app cryptex. Use stable per-app cryptex identifiers and
check for existing bundle-ID conflicts rather than accumulating duplicate
registrations. Retain useful build manifests and diagnostic logs.

Show actionable errors naming the failed step and missing dependency. Use
bounded timeouts and shell-safe subprocess argument lists. Reuse existing
helpers rather than creating another image builder or transport stack.

## Device context: verify again before use

Previously connected SRD UDID: `<SRD_UDID>` (redacted).
Device: iPhone12,8; iOS 27.0, build `24A437`.

Installed exact-build registrar: `codes.rambo.research.appregistrard` 1.7.0.
Existing app cryptex IDs:
`org.example.research.native.commissary` and
`org.example.research.native.zerosky`.

Existing paired instance:
`~/Library/Application Support/0-Sky/instances/iphonese-srd/config.json`.
Read the profile to select its route; do not guess SSH keys or host identity.

Control and Link icons were previously verified on Home Screen page two.
Control launch was verified. Link launch still needs verification. Research
authorization must be checked live; historical device state is not sufficient.

## Acceptance checks

1. `--doctor` checks the selected interpreter, imports, tool paths, input
   archives, and required registrar/profile availability.
2. Build both cryptexes without installing; verify signatures and asset digests.
3. Install on the selected paired SRD using live Apple authorization.
4. Query both bundle IDs and verify both icons through SpringBoard.
5. Smoke-test launching both apps and report any launch failure accurately.
6. Document the exact working command and separate verified installation/icon
   results from app feature behavior. Installing an app-only IPA does not
   install its external daemons, tweak libraries, or firewall functionality.

Deliver the entry point, any minimal dependency instructions, and a short
README. Report files changed, verification performed, and remaining blockers.
If the device is unavailable, finish the build and preflight work and clearly
state which device checks remain unperformed.
