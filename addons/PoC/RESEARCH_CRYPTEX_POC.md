# App package cryptex PoC

## How this fits 0-Sky

The repository has three first-party components: `bridge/` manages macOS
pairing, transports, and the pinned Python runtime; `link/` is the device
status app and carries the reviewed SRDKit in the local integration build;
`control/` is the device control app. The existing
`bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py` is the
full app installation workflow. It signs nested app code, installs a research
cryptex, calls appregistrard through the per-device paired SSH channel, and
checks the registered app. This PoC uses the same project runtime and Apple
cryptex tooling for a smaller package-to-cryptex entry point.

`load_packages_as_cryptex.py` makes **one Cryptex1 bundle per input**. It
accepts `.ipa`, `.app`, and app-only `.deb` packages. Each app is staged under
`System/Applications` in its own cryptex. DEB maintainer scripts are not run;
DEBs with non-app payload files are rejected.

Run with `python3`. The build scripts use only the Python standard library;
device installation automatically selects `0-Sky/.venv/bin/python`, which has
the project's pinned `pymobiledevice3==11.3.1`. Set `SRD_PYTHON` or pass
`--device-python` if the 0-Sky environment lives elsewhere. Missing host tools
are reported before staging begins.

Build and load in one run:

```sh
python3 load_packages_as_cryptex.py \
  0-Sky-Link-1.9.0-universal.ipa \
  ../Commissary-Universal-signed.ipa \
  /path/to/OtherApp.deb \
  /path/to/Another.app \
  --output /path/to/cryptex-builds \
  --udid YOUR_PAIRED_DEVICE_UDID \
  --sign-apps \
  --reboot-for-icons
```

Omit `--udid` to build only. Each output subdirectory contains a `.cxbd` and
`assets.json`, and the top level contains `packages.json`. To install a saved
build without rebuilding:

```sh
python3 install_built_cryptex.py /path/to/cryptex-builds \
  --udid YOUR_PAIRED_DEVICE_UDID
```

`install_built_cryptex.py` also accepts one or more individual build directories
containing `assets.json`. Required host commands are Apple's research
`cryptexctl`, `ditto` for IPA inputs, and `dpkg-deb` for DEB inputs. The 0-Sky
repository's [requirements](../../REQUIREMENTS.md) list the supported host
toolchain. `--sign-apps` uses the repository's `sign_app` routine on staged
copies and requires `codesign`, `ldid`, `otool`, and `xattr`. It preserves
per-binary entitlements, signs nested code before the outer bundle, and runs
strict bundle verification. The source archives are untouched. Device
installation needs the paired SRD, RemoteXPC access, and
Apple TSS authorization. When `packages.json` contains app metadata, the
installer checks the device app registry and calls the mounted appregistrard
through the configured 0-Sky paired SSH channel for any missing apps. It then
checks the registry again. On the verified iOS 27 device, the paired SSH
route resets; `--reboot-for-icons` instead reboots only when an icon is
missing, waits for the device to return, and checks the app registry after
appregistrard's fresh mount scan. Unlock the device once after reboot. Use
`--skip-registration` for mount-only work.
App icons require this on-device registration path; a successful cryptex
install alone does not publish an app icon. Individual `assets.json` builds
without app metadata can only be mounted by this command.

Apple's `cryptexctl` creates a sealed Cryptex1 disk image, trust cache, volume
hash, and BuildManifest. `make_cryptex.py` checks the SHA-384 digest of each
asset against that manifest. `cryptex_native.py` obtains a domain-3 nonce over
RemoteXPC, asks Apple's TSS for an exact-device ticket, and installs only
after TSS authorizes the bundle. `--preflight-only` on `cryptex_native.py`
requests a ticket without changing the device. The installer uses `ginf` and
`gtgv` directly from the matching `.cxbd` bundle.

`make_cryptex.py` also accepts `--dstroot` for a prepared filesystem. Its
`--format research` option produces the older `cpxd`/`ltrs`/`c411` layout;
those assets are not inputs for `cryptex_native.py`.

The cryptex mount and the SpringBoard app registration are separate steps.
The local [appregistrard](appregistrard/README.md) project can register apps
found in mounted cryptexes on an SRD. Two supplied inputs, the Commissary IPA
and CrypStore DEB, contain the same app bundle ID (`com.liquidsky.CrypStore`),
so their app registrations may conflict even though both cryptexes can load.

## Verified device run

On the connected device `<SRD_UDID>`, Apple TSS issued a
Cryptex1 ticket and the native install returned success for all three supplied
archives. A follow-up RemoteXPC `copy-installed` call listed:

- `org.example.research.native.commissary` 1.0
- `org.example.research.native.crypstoredeb` 1.0
- `org.example.research.native.zerosky` 1.0

The device reports `img4_chip_rsch: 0`, yet its domain-3 nonce and live TSS
authorization were available. `cryptexctl` reported that one Mach-O inside
the 0-Sky-Link IPA (`device_bridge_supervisor`) is unsigned; that binary may
be absent from the generated trust cache. Control launch was verified after
the replacement described below; Link launch has not been tested.

## iOS 27 icon registration status

The connected device also has the exact-build `appregistrard` 1.7.0 cryptex
from the ZeroSky SRDKit. Its packaged files match the SHA-256 values in
`PROVENANCE.json`, Apple TSS authorized the image, and cryptexd lists it as
installed. The earlier locally built registrar used the same launch service
label and prevented this version from bootstrapping; that local build was
uninstalled before the packaged registrar installed successfully.

The packaged daemon initially retained stale mount state, and a fresh ZeroSky
cryptex install did not produce an app registration. After the SRD was
rebooted and unlocked, appregistrard processed the mounted apps. A device app
query now returns both `codes.liquidsky.research.zerosky` and
`com.liquidsky.CrypStore`, including their primary icon metadata. A separate
SpringBoard icon-state query places **0-Sky Control** and **0-Sky Link** at
indices 18 and 19 on the second Home Screen page. That verifies the icons
are in SpringBoard's layout.

The configured 0-Sky paired SSH route was restored during the Control runtime
repair below. The PoC's on-demand `register_mounted_app.py` path has not yet
been verified end to end.
The daemon's registration path is verified after a fresh boot. The
Commissary IPA and CrypStore DEB share `com.liquidsky.CrypStore`, so they
cannot provide two distinct icons without changing one bundle identifier.

## Control replacement from the supplied signed IPA

The current Control cryptex was built from
`addons/Commissary-Universal-signed.ipa`. That file is byte-for-byte identical
to the earlier Commissary IPA and declares app version **3.4.4**, build
**3.4.4.4**. Its original extracted bundle failed strict macOS signature
verification, so the repository's `sign_app` routine signed a staged copy;
the resulting app passed `codesign --verify --deep --strict`.

Apple TSS authorized the replacement, and cryptexd now lists
`org.example.research.native.commissary` **1.1**. The older
`org.example.research.native.crypstoredeb` cryptex was removed to eliminate
the duplicate app ID. After reboot and unlock, Control's registered bundle
path changed and its registration sequence advanced from **1568** to
**1580**. Its icon remains on the second Home Screen page. `devicectl`
launched that new registered copy, and a process check more than 20 seconds
later showed it still running. Source hashes and build metadata are recorded
in `cryptex-build-control-signed-v11-retry/source.json`.

## Control “Install Error 126 / Unknown error” recovery

Control returns 126 when its bridge token is missing or invalid, or when the
bridge rejects authentication. Its generic error table has no entry for 126.
On this device the SSH/bootstrap cryptex was missing. Restoring the verified
SRDSSH image restored `/var/jb` and made the existing 65-byte token readable.
The existing Procursus package database was preserved.

Device Python then failed with a code-signature error for `libpython3.9.dylib`.
`restore_control_python.py` verified 76 installed Mach-O files against four
SHA-256-pinned offline packages and built a Python-only research cryptex.
Apple TSS authorized installation of `com.liquidsky.control.python` 1.0.
This restores the bridge interpreter; it does not restore the full tweak
injection runtime or install NetFence.

```sh
python3 restore_control_python.py \
  --kit appregistrard-build/stage-zero/dstroot/System/Applications/ZeroSky.app/SRDKit \
  --udid YOUR_SRD_UDID --output cryptex-control-python-recovery --install
python3 check_control_runtime.py --udid YOUR_SRD_UDID
```

Use a new output directory for each build. Omit `--install` to build only;
the exact-device code comparison still requires paired SSH. Host prerequisites
are `dpkg-deb`, `codesign`, SRD `cryptexctl`, and the device Python environment
selected by `device_python.py`.

After recovery, device Python reports 3.9.9 with status 0. An authenticated
bridge query reports `Ready`, `paired: true`, `PRIVILEGED_BRIDGE_READY=True`,
and `WORKER_FRESH=True`. No NetFence app was registered at that check; its
installation still needs to be retried through Control.

## Control “Install error -200” recovery

On 2026-09-26, Control returned -200 while installing an IPA. In
`control/Shared/TSUtil.m`, this status denotes a local bridge transport error
or missing response data. The device's Python interpreter failed to load
`libpython3.9.dylib` because its code signature was invalid.

`restore_control_python.py` verified all 76 installed Python code files against
the pinned offline packages in `srdsh-work/components/zero-sky/kit` and installed
`com.liquidsky.control.python` 1.0 using live Apple TSS authorization. The
recovery build is in `cryptex-control-python-recovery-20260926`.

After recovery, `check_control_runtime.py` verified Python 3.9.9 with exit
status 0, bridge stage `Ready`, detail `Waiting for an IPA`, verified Apple
pairing and host identity, `PRIVILEGED_BRIDGE_READY=True`, and
`WORKER_FRESH=True`. The failed IPA was not automatically retried; bridge
readiness does not establish that a particular IPA installs successfully.

## Control error 125 while installing NetFence

The bridge log identified an image-build failure, before Apple personalization:
`apfs_prepare_cryptex: /dev/disk6 is not an APFS volume`. The worker had already
received and signed `NetFenceApp.app` (`com.foxfort.NetFenceApp`).

The replacement files in `control-builder-fix` use Apple's
`cryptexctl create --use-cryptex1-format` for the image and verify its asset
SHA-384 digests. The installer accepts the generated IM4P volume-hash asset
and matching info plist. The worker's existing trust-cache policy remains in
effect, including its empty cache for preserved Apple-signed applications.
Exact-device nonce and live Apple TSS authorization remain required.

`repair_control_builder.py --check` successfully built a local candidate.
`--deploy` updated only the two native builder files in the existing
`iphonese-srd` Mac worker, retaining `.before-apfs-repair` backups. The worker
copies these files for each new job, so it does not require a restart.
The repository's packaged release kit was not changed.

```sh
python3 repair_control_builder.py --udid YOUR_SRD_UDID --check
python3 repair_control_builder.py --udid YOUR_SRD_UDID --deploy
python3 diagnose_control_install.py --udid YOUR_SRD_UDID
```

The earlier NetFence temporary IPA was deleted by Control after failure.
A later user attempt through the original builder succeeded before the
builder repair was deployed, indicating the original APFS failure was
intermittent. Its job log records app registration and an eight-second launch
check. A device query confirms `com.foxfort.NetFenceApp` version 1.5/build 14;
SpringBoard places its icon at `[2,20]`, on the second Home Screen page.
The new builder has passed the local build check but has not yet been verified
through a fresh device-install job.

The separate preference-repair job failed because launchd's search path did
not include Homebrew's `dpkg-deb`. `repair_control_tool_path.py` verified the
existing binary and updated the active runtime helper to resolve it from
standard Homebrew locations. No runtime synchronization was performed as
part of that lookup repair.

## NetFence settings and firewall runtime

The installed IPA provides the app interface but not the complete tweak.
`inspect_netfence_runtime.py` found no installed NetFence/Foxfort dpkg packages,
no NetFence service process, and no NetFence preferences plist. The installed
executable references `com.foxfort.netfence.service`, shared NetFence resources,
`libfoxfortutils.dylib`, and AltList. Device checks found the shared resource
bundle, library, and framework absent. Both the mobile preferences directory
and NetFence's application-support directory belong to mobile (501), mode 755;
there is no evidence that their parent-directory ownership needs changing.

The original rootless NetFence Debian package and dependencies are needed to
inspect the missing runtime. Its [seller listing](https://havoc.app/package/netfence)
requires a jailbreak and lists support through iOS 26.0.1. This device runs
iOS 27, so registering its app does not establish firewall compatibility or
enforcement. Current status: app/icon verified, firewall unverified and reported
nonfunctional by the user; settings persistence unresolved.
