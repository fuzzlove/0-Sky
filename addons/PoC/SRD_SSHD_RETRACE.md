# Apple SRD persistent SSH retrace

Reconstructed on 2026-09-07 from local shell history and file mtimes. Assumption: this was done on your authorized Apple SRD (UDID seen in history: `00000000-0000000000000002`).

## Confirmed replay on 2026-09-07

The decisive detail was recovered from the prior Codex transcript and archived
installer logs: the successful installation did **not** use the normal
MobileDevice `cryptexctl personalize/install` transfer. It used
`pymobiledevice3`'s `NativeRemotedTunnel` and `CryptexdService`, which transfer
the personalized image through RemoteXPC.

Recreated scripts:

```text
srdsh-work/native-install/build_and_install.sh
srdsh-work/native-install/install_cryptex_native.py
```

Replay command:

```sh
cd <SRDssh-checkout>/exploitdev/srdsh-work/native-install
./build_and_install.sh
```

This flow:

1. generates and wraps the loadable trust cache;
2. rebuilds the SRDsh root as APFS;
3. seals the APFS image;
4. obtains the 48-byte research nonce through the native RemoteXPC service;
5. gets a 3074-byte TSS ticket; and
6. installs with `persistence=2` and `nonce_persistence=1`.

Confirmed result:

```text
native 00000000-0000000000000002 iPhone13,2
ids rsch 0 nonce len 48 trust len 199 image len 1447407
ticket 3074
INSTALL SUCCESS com.liquidsky.srdssh
```

`cryptexctl list` then reported the mounted `com.liquidsky.srdssh` cryptex,
and root SSH over `iproxy 2222 22` succeeded.

## Short version / likely successful path

1. You had a working temporary SSH path first:
   ```sh
   iproxy 2222 22 -u 00000000-0000000000000002
   ssh -p 2222 root@127.0.0.1
   ```

2. You cloned/built `srdsh`:
   ```sh
   git clone --recurse-submodules git@github.com:jonpalmisc/srdsh.git
   cd srdsh-work/srdsh   # inferred from current artifact locations
   ```

3. You used `CryptexManager` instead of the original `cryptexctl` flow.
   - Local binary found: `/usr/local/bin/CryptexManager`
   - Source/build dir: `srdsh-work/CryptexManager`
   - Git remote: `https://github.com/pinauten/CryptexManager.git`

4. You patched `srdsh-work/srdsh/Makefile` so the cryptex target became `.cptx` and create/install used `CryptexManager -u $(CRYPTEXCTL_UDID)`.

5. You built the SRDsh cryptex contents around **2026-09-06 22:39**:
   - `srdsh-work/srdsh/build/com.liquidsky.srdssh.root/usr/bin/dropbear`
   - `srdsh-work/srdsh/build/com.liquidsky.srdssh.root/usr/bin/cryptex-run`
   - `srdsh-work/srdsh/build/com.liquidsky.srdssh.root/Library/LaunchDaemons/dropbear.plist`
   - `srdsh-work/srdsh/build/com.liquidsky.srdssh.dmg`
   - `srdsh-work/srdsh/build/com.liquidsky.srdssh.ltrs`

6. You later ran, from what was almost certainly `srdsh-work/srdsh`:
   ```sh
   make
   make install
   ```
   The `Makefile` install rule currently expands to:
   ```sh
   CryptexManager -u $CRYPTEXCTL_UDID uninstall com.liquidsky.srdssh || true
   CryptexManager -u $CRYPTEXCTL_UDID install build/com.liquidsky.srdssh.cptx
   CryptexManager -u $CRYPTEXCTL_UDID list
   ```

7. You tested persistence by rebooting userspace over SSH and reconnecting:
   ```sh
   ssh -p 2222 root@127.0.0.1 '/bin/launchctl reboot userspace'
   ssh -p 2222 root@127.0.0.1
   ```

## Important local state

### `srdsh` repo

Path: `srdsh-work/srdsh`

```text
origin: https://github.com/jonpalmisc/srdsh.git
HEAD:   986fb0d
status: Makefile modified, apps/debugserver/module.mk modified, vendor/dropbear dirty
```

Current diff highlights:
- `CRYPTEX` output changed from `build/com.liquidsky.srdssh.cxbd` to `build/com.liquidsky.srdssh.cptx`.
- Original `cryptexctl create/personalize/install` was replaced with `CryptexManager create/install/uninstall/list`.
- `apps/debugserver/module.mk` now tolerates missing `seatbelt-profiles` with `|| true`.

### Persistent service payload

LaunchDaemon plist in the cryptex root:

```text
srdsh-work/srdsh/build/com.liquidsky.srdssh.root/Library/LaunchDaemons/dropbear.plist
```

Key attributes:
- Label: `com.liquidsky.srdssh.dropbear`
- Program: `/usr/bin/cryptex-run dropbear -r /tmp/dropbear-host-key -R -F`
- `KeepAlive` is true

This is why it survived userspace reboot: the service is packaged in the research cryptex and launched by launchd/cryptex mount integration.

## Adjacent/possibly failed experiments

These appear in history but look separate from the final `srdsh` path:

- Attempted native Apple tool path:
  ```sh
  /System/Library/SecurityResearch/usr/bin/cryptexctl create --use-cryptex1-format ...
  ```
- Tried/downloading `xsscx/srd` universal cryptex DMGs around **2026-09-07 00:53–01:00**:
  - `srdsh-work/xsscx-srd/srd-universal-cryptex.dmg`
  - `srdsh-work/xsscx-srd-retry/srd-universal-cryptex.dmg`
  - `srdsh-work/xsscx-direct/srd-universal-cryptex.dmg`
- Checked research nonce/list/dumpstate:
  ```sh
  cryptexctl -u first list
  cryptexctl -u first dumpstate
  /System/Library/SecurityResearch/usr/bin/cryptexctl -u 00000000-0000000000000002 nonce --domain=research --global
  ```

## Minimal replay checklist for the same authorized SRD

```sh
export CRYPTEXCTL_UDID=00000000-0000000000000002
cd <SRDssh-checkout>/exploitdev/srdsh-work/srdsh
make clean
make
make install

# if you need USB forwarding for SSH checks
iproxy 2222 22 -u "$CRYPTEXCTL_UDID"
ssh-keygen -R '[127.0.0.1]:2222'
ssh -p 2222 root@127.0.0.1
```

Then verify after a userspace reboot:

```sh
ssh -p 2222 root@127.0.0.1 '/bin/launchctl reboot userspace'
# wait for device/userspace services to return
ssh -p 2222 root@127.0.0.1
```

## Procursus bootstrap on iOS 27 SRD (2026-09-07)

Bootstrap source:

```text
<Dopamine-checkout>/Dopamine.app/bootstrap_1900.tar.zst
SHA-256: 2c639b83423e4365a3a849e2bc7c56671cdcc8da534d424b6b1779a27c0c7c08
```

Placing Mach-O libraries directly in `/var/jb` failed with `file system
sandbox blocked mmap()`. The working layout is the standard rootless-style
Preboot location, with `/var/jb` as a symlink:

```sh
ACTIVE=$(cat /private/preboot/active)
TARGET=/private/preboot/$ACTIVE/procursus
mkdir -p "$TARGET"
# Extract archive's ./var/jb/* into $TARGET (GNU tar: --strip-components=3)
ln -s "$TARGET" /var/jb
```

Current resolved target:

```text
/private/preboot/0D6A971DE721DF178CD7162BDE7B05DF6417F9EAA15336B40CCBD368E9C34DDA134EB300B45F398490A496C289ECFA10/procursus
```

The combined cryptex trust cache contains the Procursus Mach-O cdhashes. The
cryptex itself was installed over native RemoteXPC with `persistence=2` and
`nonce_persistence=1`.

Bootstrap configuration notes:

- `prep_bootstrap.sh` uses `/var/jb/bin/sh`, but several maintainer scripts use
  the unavailable stock `#!/bin/sh`. Invoke those scripts explicitly through
  `/var/jb/bin/sh` on this SRD.
- The Procursus `launchctl` from bootstrap 1900 is ABI-incompatible with iOS 27
  (`_launch_active_user_switch` is missing). Loading Procursus OpenSSH therefore
  fails. Persistent SSH remains provided by the cryptex's Dropbear daemon.
- `apt-get update` succeeds against `https://apt.procurs.us` suite `1900`.
- The Dopamine-only `shshd`, `libdimentio0`, and `libkrw0` packages were
  removed because no `libkrw0-plugin` exists on this SRD; `apt-get check` then
  returns success.
- Installation metadata is stored at `/var/jb/.srd_procursus_bootstrap`.

Persistence was confirmed with a full device reboot: the research cryptex
remounted automatically, Dropbear returned over USB forwarding, `/var/jb`
still resolved to the active Preboot Procursus tree, and both `dpkg` and
`apt-get` executed successfully.

The cryptex now also includes `dropbearkey`. A test using a persistent host key
under `/var/jb/etc/dropbear` failed during early boot because that path was not
available soon enough for the cryptex LaunchDaemon. The service was therefore
returned to the known-good `-r /tmp/dropbear-host-key -R` configuration. SSH is
persistent, but its host key can change after a full reboot; clear the cached
entry with `ssh-keygen -R '[127.0.0.1]:2222'` when that happens.

Verification:

```sh
readlink /var/jb
/var/jb/usr/bin/tar --version
/var/jb/usr/bin/dpkg --version
/var/jb/usr/bin/dpkg --configure --pending
/var/jb/usr/bin/apt-get update
```

## Sileo LaunchServices registration (2026-09-07)

The app embedded directly at `$CRYPTEX_MOUNT_PATH/Applications/Sileo.app`
could not be registered by Procursus `uicache`; unmodified iOS LaunchServices
does not treat that cryptex mount path as an eligible containerized app path.
The working copy is:

```text
/private/var/containers/Bundle/Application/53524453-494C-454F-A001-000000000001/Sileo.app
bundle id: org.coolstar.SileoStore
```

`srd-lsregister` now has the iOS 27 LaunchServices installation entitlements,
including `com.apple.private.coreservices.can-register-install-results` and
`com.apple.private.coreservices.can-perform-rebuild-registration`.

The stock Procursus `launchctl` references an API removed in iOS 19. A locally
built iOS-19-minimum variant, `$CRYPTEX_MOUNT_PATH/usr/bin/launchctl19`, omits
that unavailable import and is included in the cryptex trust cache. It was used
to bootstrap the registration helper in `user/501`, where the containerized
registration returned an `LSRecordPromise` with no error.

Verification and launch:

```sh
# Matching Frida client on the Mac
srdsh-work/native-install/frida-client-17.9.10/bin/frida-ps -Uai | grep -i sileo
# Expected: Sileo  org.coolstar.SileoStore

xcrun devicectl device process launch \
  --device 00000000-0000000000000002 org.coolstar.SileoStore
```
