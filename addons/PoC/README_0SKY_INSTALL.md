# 0-Sky Control and Link Research Cryptex Installation

This script builds both app cryptexes for inspection. With `--install`, it uses
the maintained paired-Mac IPA installer to install Control and Link on the
selected Apple Security Research Device (SRD).

## Overview

The `install_0sky_apps.py` script:

1. Without `--install`, extracts and signs staged app copies, then builds
   research cryptex bundles using Apple's `cryptexctl`.
2. With `--install`, selects one complete paired profile for the exact UDID,
   restores the verified appregistrard Cryptex when needed, then sends each
   requested IPA through the authenticated 0-Sky worker. The worker signs,
   registers, and launch-checks each app. Install reports are saved under
   `--output/installer-verification`.

Cryptex1 bundles containing `Cryptex1,GenericDmg` use
`research_cryptex_poc.py install` and `cryptex_native.py` for device
personalization and installation. Legacy research bundles use
`cryptexctl personalize` followed by `cryptexctl install`.

## Requirements

- macOS with Apple Security Research cryptexctl
- Paired Apple Security Research Device (SRD)
- Python 3.12 with `pymobiledevice3==11.3.1`
- SSH key for device pairing
- Working `appregistrard` installation on device
- The 0-Sky checkout's `bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py`
  for signing staged apps and verifying their signatures

The selected device must already have a paired 0-Sky worker and a working
rootless Python runtime. The installer verifies the exact USB identity and
uses the profile's pinned SSH tunnel. If the appregistrard Cryptex is absent,
it checks the exact OS build and SHA-256 digests of its bundled assets before
restoring it.

## Installation

### Step 1: Clone or Copy Files

Copy the `PoC` directory and its contents to your desired location.

### Step 2: Ensure Dependencies

- Place `Commissary-Universal-signed.ipa` (Control) in the parent directory
- Place `0-Sky-Link-1.9.0-universal.ipa` (Link) in the PoC directory
- Install Python 3.12 with `pymobiledevice3==11.3.1` in `0-Sky/.venv/bin/python`
- Set up pairing with your SRD (SSH keys, device config)

### Step 3: Verify Dependencies

```bash
python3 install_0sky_apps.py --doctor
```

## Usage

### Basic Build (No Installation)

```bash
python3 install_0sky_apps.py
```

Each run creates a fresh `cryptex-build-0sky-*` directory under the PoC
directory and prints its path. Existing builds are preserved. `--output`
selects the parent directory for these runs.

### Install on a Paired SRD

```bash
python3 install_0sky_apps.py --install --udid YOUR_UDID
```

The exact UDID is required. If more than one complete paired profile has that
UDID, add `--instance-name NAME`.

### Build and Install with Explicit Device

```bash
python3 install_0sky_apps.py --install --udid YOUR_UDID
```

### Install with Reboot for Icon Refresh

```bash
python3 install_0sky_apps.py --install --udid YOUR_UDID --reboot-for-icons
```

### Full Command with Custom Options

```bash
python3 install_0sky_apps.py \
    --control-ipa /path/to/control.ipa \
    --link-ipa /path/to/link.ipa \
    --output /path/to/output \
    --device-python /path/to/python \
    --udid YOUR_UDID \
    --install \
    --reboot-for-icons
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--control-ipa PATH` | Path to Control IPA (auto-detected) |
| `--link-ipa PATH` | Path to Link IPA (auto-detected) |
| `--output PATH` | Parent for a fresh build directory on each run (default: PoC directory) |
| `--device-python PATH` | Python interpreter with pymobiledevice3 |
| `--srdsh-kit PATH` | SSH bootstrap kit (default: included srdsh-work kit) |
| `--ssh-only` | Legacy build option; incompatible with the paired IPA installer |
| `--udid UDID` | Exact device UDID (required with `--install`) |
| `--instance-name NAME` | Select a paired profile when more than one matches |
| `--doctor` | Run dependency checks only |
| `--install` | Install cryptexes on device |
| `--reboot-for-icons` | Reboot device after installation |
| `--force` | Accepted for compatibility; `--install` already submits both selected IPAs |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SRD_UDID` | Override device UDID |
| `SRD_PYTHON` | Path to Python with pymobiledevice3 |
| `SRD_DEVICE_CONFIG` | Path to device configuration directory |

## Expected Bundle IDs

- **Control**: `com.liquidsky.CrypStore` (version 3.4.4)
- **Link**: `codes.liquidsky.research.zerosky` (version 1.9.0)

## Output Structure

After building, the output directory contains:

```
cryptex-build-0sky-<unique suffix>/
├── control/
│   ├── assets.json
│   └── org.example.research.native.commissary.cxbd/
└── link/
    ├── assets.json
    └── org.example.research.native.zerosky.cxbd/
```

## Verification

Live verification on September 26, 2026, with the paired iPhone12,8 on iOS
27.0 build 24A437 confirmed the exact-build registrar is mounted and both
Home Screen icons are present: Control at `[2, 18]` and Link at `[2, 19]`.
Control required a signed staged copy because the supplied IPA's arm64
code was unsigned. Its repaired build is retained in
`control-signing-repair-ms356hbd`; the input IPA was preserved.

After installation and icon verification:

1. App icons appear on Home Screen
2. Apps can be launched successfully
3. Device shows both cryptexes as mounted

## Troubleshooting

### Install the Bootstrap Without Rebuilding the Apps

```bash
python3 restore_srd_bootstrap.py --udid YOUR_UDID
```

This verifies and installs the included `bootstrap_1900.tar.zst` as needed,
using the existing paired profile. A healthy Procursus installation is
preserved. The main PoC runs this stage automatically with `--install`.

The archive's `etc/localtime` entry is omitted during extraction to preserve
the device's timezone and avoid Toybox rejecting its external target. If the
link is absent, the helper creates it after extraction. A completed bootstrap
marker, clean `dpkg --audit`, and successful `apt-get check` are required
before skipping installation, so a partial extraction is retried.

### Repair SSH Without Rebuilding the Apps

```bash
python3 restore_srd_bootstrap.py --udid YOUR_UDID --ssh-only
```

This uses the included kit and existing device profile. SSH setup must
complete successfully before the main installer replaces either app cryptex.
The installer also checks that appregistrard is mounted and executable before
replacing app cryptexes. If it is missing, `setup_appregistrard.py` reads the
device's current OS build and installs the matching verified package from
`srdsh-work/components/zero-sky/kit/appregistrard`. Existing working registrar
mounts are preserved. An SSH timeout stops setup without assuming the
registrar is missing or attempting installation.

To set up the registrar without rebuilding the apps:

```bash
python3 setup_appregistrard.py --udid YOUR_UDID
```

### RemoteXPC GOAWAY Error 3 During Transfer

HTTP/2 error 3 indicates a flow-control violation. The pinned runtime's
request and handshake DATA frames were not deducted from its outbound
window. `remotexpc_flow_control.py` applies a process-local correction that
counts those frames along with file payloads and retains replies received
while waiting for window credit. It does not modify the installed runtime.
The caller allows 1,020 seconds for the native helper, which has a
900-second installation timeout.

Before retrying, check the active transport without connecting to the device:

```bash
$ZERO_SKY_ROOT/.venv/bin/python cryptex_native.py --check-transport
```

Expect `transport flow-control=all-data-v1` and `TRANSPORT CHECK SUCCESS`.
Every installation prints the runner, interpreter, and transport correction
paths before connecting. A traceback in the dependency's original
`_send_flow_controlled` indicates that the correction was not active in that
process; check that the run used the current files.

### Registration Succeeds but an Icon Is Missing

The registrar can exit with status zero even when app registration fails.
The installer now confirms each bundle ID appears in the device app registry
and returns a nonzero status if registration or either Home Screen icon check
fails. It preserves icon-check errors so connection failures are visible.

If using `--reboot-for-icons`, unlock the device after it restarts. The
installer checks the icons again for up to four minutes before reporting the
final result.

### Device Python Missing

```bash
export SRD_PYTHON=/path/to/python3.12
```

### IPA Not Found

```bash
export SRD_CONTROL_IPA=/path/to/Commissary-Universal-signed.ipa
export SRD_LINK_IPA=/path/to/0-Sky-Link-1.9.0-universal.ipa
```

### Auto-Detect Device

```bash
export SRD_UDID='<selected-authorized-SRD-UDID>'
```

### No Device Detected

Connect your SRD via USB and ensure it's paired:

```bash
python3 -m pymobiledevice3 remote browse --native
```
