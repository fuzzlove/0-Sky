# Installation and release troubleshooting

Run diagnostics before making changes:

```sh
python3 tools/environment_preflight.py --human --mode development \
  --kit "/absolute/path/to/authorized kit" \
  --theos "/absolute/path/to/locked/theos" --skip-device
python3 tools/pii_audit.py .
```

Add `--udid EXACT_UDID` only when the intended SRD is connected and unlocked.
Preflight is read-only; setup and repair are explicit operations.

| Symptom | Meaning | Action |
| --- | --- | --- |
| Doctor reports `xcrun` or `xcodebuild` missing/incompatible | Full Xcode is absent, unfinished, or not selected. | Install Xcode from the Mac App Store, open it once, then run `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`, `sudo xcodebuild -license accept`, and `xcodebuild -version`. |
| Doctor reports Python missing | A source-build interpreter is not on `PATH`; this does not mean binary-release users need Python. | Install the universal2 macOS package from <https://www.python.org/downloads/macos/> or run `brew install python@3.12`; open a new Terminal and run `python3 --version`. |
| Doctor reports locked Theos missing | The required clean checkout and recursive submodules were not selected. | Run the three exact clone/checkout/submodule commands printed by `--human`, then rerun with `--theos '/absolute/path/to/theos'`. |
| Doctor reports a Developer ID identity missing | The matching distribution certificate or private key is absent from the unlocked login keychain. | In the Apple Developer certificate portal create the reported **Developer ID Application** or **Developer ID Installer** certificate, upload the CSR matching this Mac's private key, download the `.cer`, and open it in Keychain Access. Verify both with `security find-identity -v -p basic`. |
| Doctor reports a notarytool profile missing | Developer ID signing is available, but Apple notarization credentials have not been stored. | Create an app-specific password at <https://account.apple.com>, run `xcrun notarytool store-credentials 0-sky-release --apple-id YOUR_APPLE_ID --team-id YOUR_TEAM_ID`, type the app-specific password only at the secure prompt, and rerun preflight with `--notary-profile 0-sky-release`. |
| `LIBARCHIVE_NOT_RESOLVED` or `OPENSSL_NOT_RESOLVED` | The Control source-build headers are absent or `pkg-config` cannot find them. | Run `brew install libarchive openssl@3 pkgconf ldid dpkg`, then export `LIBARCHIVE_PREFIX="$(brew --prefix libarchive)"` and `PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"` in the same Terminal. |
| `EXTERNAL_KIT_MISSING` | A source checkout lacks the private, manifest-verified kit. | Obtain the authorized kit separately. Do not copy an old installed app's kit into the source tree. |
| `ENVIRONMENT_BLOCKED` or missing Python 3.12 | Required host tools or the pinned runtime are unavailable. | In Bridge choose **Install All 0-Sky Requirements**, then rerun preflight. |
| `HOST_RUNTIME=FAIL` | The package lacks a required Universal 2 Python/tool binary, license, or matching hash. | Replace the complete four-file release; do not install Homebrew as a substitute for a broken public package. |
| `BLOCKED_HOST_RUNTIME_MISSING_OR_INVALID` | A source release build was given a kit without the manifest-verified Universal 2 host runtime. | Supply/rebuild the authorized runtime kit; the release command will not fall back to developer-installed tools. |
| `THEOS_PREFLIGHT=FAIL` | The Theos checkout, a recursive submodule, SDK, or source-build dependency differs from the lock. | Initialize the commit in `manifests/source-dependencies.json` recursively and pass it with `--theos`; do not update it during a release build. |
| More than one USB device is visible | Automatic selection would be ambiguous. | Disconnect other devices or explicitly select/pass the exact UDID. |
| Trust or pairing fails | Apple trust, project pairing, SSH, and worker state are separate checks. | Unlock the selected SRD, approve Trust, verify Xcode device support, and rerun the exact-device check. Do not copy another device's profile. |
| SSH port is occupied | The requested local port belongs to another listener. | Stop the verified stale per-device forward or choose another local port. Never terminate an unidentified listener. |
| Existing profile belongs to another endpoint | Stored UDID, instance, SSH key, port, or manifest revision differs. | Use the audited repair path or a new instance name; do not edit `config.json` by hand. |
| Setup times out | A child tool, pairing proof, or device-selection dialog did not complete. | Confirm the device is unlocked and the required tool is responsive, then rerun. Timeouts fail closed and do not prove installation. |
| `OUTPUT_NOT_EMPTY` | A release output directory contains stale or unrecognized artifacts. | Choose a new empty output directory. Keep previous releases immutable. |
| `RELEASE_MANIFEST=FAIL` | A release file is missing, extra, symlinked, or has changed bytes. | Re-download/rebuild the complete four-file set. Do not replace only the package. |
| Candidate audit ends `BLOCKED` | Development/release-candidate signing is not a public distribution result. | Use a distribution build with verified Developer ID signatures and notarization. |
| Sanitization reports a signed binary path | The signed input contains builder data. | Correct its build configuration, rebuild, and verify its signature. Do not strip or patch a signed binary. |
| Control reports “Verified update required” | A moving upstream `latest` asset has no release-bound checksum. | Upgrade using a complete manifest-verified 0-Sky release instead of the disabled privileged self-updater. |

## Private logs and state

0-Sky state belongs below `~/Library/Application Support/0-Sky`; normal logs
belong below `~/Library/Logs/0-Sky`. Do not attach unredacted logs, pairing
records, keys, device identifiers, or configuration files to public issues.
Use Bridge's redacted diagnostic export where available.

## Recovery boundaries

- A failed build does not prove an installed app is valid.
- A successful SSH command does not prove Apple pairing or worker identity.
- A matching architecture slice does not prove Intel or Apple-silicon runtime
  behavior; record unavailable hardware tests as `NOT_EXECUTED`.
- Host uninstall does not uninstall device payloads. Device removal or restore
  requires its separately documented, exact-device workflow.
