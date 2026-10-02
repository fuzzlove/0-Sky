# Rebuilt 0-Sky Link DMG transfer and Procursus bootstrap

`reproduce_srd_stack.sh` performs the confirmed SSH and Procursus path, then
hands off to the reviewed CatVNC/0-Sky Control/0-Sky Link workflow captured from the internal review record, then installs or verifies the
newest post-reboot-validated Filza DMG from the preceding 48 hours. It does not
install Sileo.

`main.py` is the Python 3 entry point from the repository root. It works with
Python 3.9+ and selects an available Python interpreter for the device tools;
the actual installation still requires macOS, Xcode, and the SRD utilities.

The script:

1. detects the sole USB-connected device UDID through usbmux;
2. verifies the USB target runs iOS 17 or newer and that the exact same UDID is
   visible through macOS `remotepairingd` (it never falls back to another device);
3. verifies the recorded rebuilt DMG, trust cache, and APFS volume hash;
4. obtains a fresh research nonce and TSS ticket for the new device;
5. transfers and installs the image with `NativeRemotedTunnel` and
   `CryptexdService` using `persistence=2` and `nonce_persistence=1`;
6. reboots once, waits for the exact USB UDID, and restarts `iproxy`;
7. uses the SSH public key sealed into the image to authenticate root; and
8. installs or verifies Procursus under the device's active Preboot volume;
9. verifies Procursus `ssh` and `sshd`; and
10. installs or verifies CatVNC 0.0.2, 0-Sky Control 3.3.0, and 0-Sky Link
    1.9.0 build 33 through the paired per-device component workflow; and
11. installs or verifies Filza 4.0 from the persistent
    `codes.rambo.research.filza.permanent` Cryptex and registers its mounted app
    with LaunchServices.

The default image contains the public half of `~/.ssh/srdsh_ed25519`. The
private key never enters the image. Dropbear reads the sealed key directly for
root authentication, so first boot does not depend on mutable
`/var/root/.ssh` permissions.

## Validate without changing the device

```sh
cd <SRDssh-checkout>/exploitdev/srdsh-work
./reproduce_srd_stack.sh --check
```

## Install on a new authorized SRD

Connect exactly one SRD over USB, then run:

```sh
cd <SRDssh-checkout>/exploitdev/srdsh-work
./reproduce_srd_stack.sh
```

To rebuild the minimal image for a different SSH identity before installing:

```sh
./reproduce_srd_stack.sh --identity ~/.ssh/my_srd_key --rebuild
```

The matching `~/.ssh/my_srd_key.pub` must exist. The minimal build includes
only the cryptex runner, Toybox, Dropbear, the root public key, and the
Procursus early-boot link. Sileo, Frida, and debugserver are excluded.

The build uses the generic iOS SDK selected by Xcode by default. Select an
installed SDK explicitly when rebuilding (one DMG is produced per SDK):

```sh
./reproduce_srd_stack.sh --sdk iphoneos18.5 --rebuild
./reproduce_srd_stack.sh --sdk iphoneos26.0 --rebuild
```

For a target running iOS 18.1, build with the 18.5 SDK while setting the
minimum deployment version to 18.1:

```sh
./reproduce_srd_stack.sh --sdk iphoneos18.5 --min-ios 18.1 --rebuild
```

There is no single DMG that is simultaneously built against two SDK versions;
build and retain separate artifacts if both SDK generations are required.
If an SDK cannot be located, install the corresponding Xcode version or use
one of the SDK names shown by `xcodebuild -showsdks` (for example,
`iphoneos26.5`).

When invoked through `main.py`, the launcher automatically selects the
installed Xcode that contains the requested SDK, so `xcode-select` does not
need to be changed globally.

For an iOS 27 SRD that is not yet visible to Native RemoteXPC, pair it first:

```sh
python -m pymobiledevice3 remote pair-host
python -m pymobiledevice3 remote browse --native --timeout 5
```

Approve the Mac under **Settings > Developer > Paired Macs** on the SRD. The
USB UDID and RemoteXPC UDID must match.

If several devices are connected, select one explicitly:

```sh
./reproduce_srd_stack.sh --udid DEVICE-UDID
```

To transfer the cryptex and stop after verifying SSH:

```sh
./reproduce_srd_stack.sh --stop-after ssh
```

The default input set is:

```text
native-install/srdsh-apfs-sealed-udzo.dmg
native-install/srdsh.gtcd
native-install/srdsh-apfs-sealed.hash
procursus/bootstrap_1900.tar.zst
```

Custom rebuilt artifacts can be supplied with `--image`, `--trust-cache`, and
`--volume-hash`. The image and its trust cache/hash must come from the same
build.

## Limits

- This is only for an authorized Apple Security Research Device. The RemoteXPC
  personalization preflight must expose the research nonce domain.
- The `pymobiledevice3` RemoteXPC/cryptexd route requires iOS 17 or newer. It
  cannot install this rebuilt research cryptex on an iOS 16 device.
- The rebuilt cryptex supplies Dropbear, not Procursus OpenSSH. Bootstrap 1900's
  `launchctl` is incompatible with the recorded iOS 27 build.
- Automated bootstrap commands require working root SSH authentication. Supply
  the appropriate key with `--identity FILE` if it is not the recorded key.
