# Portability contract

0-Sky derives the executing repository or app-bundle root from the script or
bundle location. The caller's current directory is never used to find bundled
resources. Explicit relative CLI paths are interpreted relative to the caller's
current directory; stored relative paths are interpreted relative to the config
file. Environment path overrides must be absolute. No source edit is required
for another account, Mac, Xcode selection, or SRD.

## Configuration

`bridge/zero_sky_user_config.py` is the authoritative per-user configuration
reader. Effective precedence is **CLI override > config file > environment >
runtime discovery > safe default**. `0sky_project_setup.py` uses it; the app
build copies that module beside the controller. The default config is
`~/Library/Application Support/0-Sky/user-config.json` (owner-only mode 0600).
`ZERO_SKY_CONFIG` or `--config` selects another file. The setup controller's
`--init-config` and `--setup` persist effective configuration for resumption.

| Variable | Purpose |
| --- | --- |
| `ZERO_SKY_CONFIG` | Per-user JSON configuration file |
| `ZERO_SKY_SUPPORT`, `ZERO_SKY_STATE`, `ZERO_SKY_ARTIFACTS` | Account-local persistent directories |
| `ZERO_SKY_IDENTITY` | SSH identity path; key contents stay outside the repository |
| `ZERO_SKY_VENV` | Pinned Python environment path |
| `ZERO_SKY_BASE_PORT` | Proposed forwarding port, checked per device |
| `ZERO_SKY_KIT_SOURCE` | Manifest-verified external kit input |
| `ZERO_SKY_DERIVED_DATA` | Mac build output directory |
| `ZERO_SKY_RELEASE_DENY_FILE` | JSON project-specific release deny patterns |
| `ZERO_SKY_SIGNING_IDENTITY` | Release preflight input; caller must verify actual signing |

The selected device is an explicit UDID. The discovery and pairing paths keep
USB, CoreDevice, SSH, root, profile, and wireless states distinct. A forwarded
SSH session must match the selected device before mutation. A valid existing
profile is reused. Per-device state is stored outside source control. The
port 2222 default is only a proposal; it is not a hard-coded device endpoint.

## Discovery and capability checks

Run `python3 tools/environment_preflight.py --mode development --skip-device`
for a read-only host check. Add `--udid EXACT_UDID` to check one connected SRD;
no first-device fallback is used. `--mode release --kit PATH` additionally
requires a verified kit and configured signing input. Results distinguish
READY, DEGRADED, and BLOCKED, and redact host identity and device UDID.

The host tool resolver uses PATH, standard macOS paths, and known Homebrew
locations as search candidates. It checks Python 3.12's version. CoreDevice
and debugger tools are located through the active `xcrun`/developer directory,
which respects `DEVELOPER_DIR` and `xcode-select`. The preflight reports
process/native architecture, including Rosetta. Optional device tools degrade
the relevant capability rather than being treated as installed merely because
a path exists.

The platform/protocol constants `/var/jb`, Apple's SRD `cryptexctl` location,
bundle IDs, and device-local authenticated loopback port 48654 are deliberate.
Host Homebrew directories and Xcode paths are discovery candidates, not binding
configuration. See [ENVIRONMENT_AUDIT.md](ENVIRONMENT_AUDIT.md) for the complete
classification. Future iOS versions are probed by capability; their device
payloads and Apple services must still validate on the exact build.

The external kit is ignored by Git. `tools/prepare_release_kit.py` verifies it,
then overlays the versioned worker/supervisor/Cryptex scripts in
`bridge/KitScripts` and the tracked Apple transport before rebuilding Link.
It updates the manifest and adds a deterministic `PORTABILITY.json` marker.
The Mac build accepts only this prepared form, so an older external kit cannot
silently reintroduce workstation-specific script defaults.

The canonical EULA lives in `bridge/0SkyBridge/Resources/Legal`. The app finds
its bundled copy through `Bundle.main` (or `Bundle.module` in Swift Package
builds), validates the document digest, and checks a minimal local acceptance
record against the EULA version and digest. A new application build with the
same EULA does not require renewed acceptance.

## Private state and troubleshooting

Store SSH keys, pairing records, Apple signing assets, generated device data,
logs, and research evidence in account-local private locations. Never copy
them into the checkout or release kit. The config reader rejects symlinked,
wrong-owner, or group/world-readable config files. Diagnostic public output
redacts user, host, source path, device ID, and paths outside the home tree.

If preflight reports BLOCKED, follow the component's remediation. A missing kit
means obtain the authorized, manifest-verified release input; missing signing
means configure and verify the publisher's credentials. If CoreDevice is
unavailable, select a compatible Xcode and check exact-device trust. SSH
success alone does not prove Apple pairing. Host-profile repair preserves the
existing bootstrap and root SSH path; see the host-profile report/workflow.
