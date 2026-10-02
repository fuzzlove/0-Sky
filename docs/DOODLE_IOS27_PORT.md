# Doodle iOS 27 private source port

The supplied Doodle 1.2 rootless DEB has SHA-256
`4725c0170e89413308b8434e4f1e80fc7357880e628d87af76c9e45920aa656a`.
Its [Havoc listing](https://havoc.app/package/doodle) declares support through
iOS 16.7.8. The developer's [public source](https://github.com/nahtedetihw/Doodle)
at commit `a364b0cdcae3198336eee16e62ca56b3f540cc18` is version 1.1,
not the exact source for the supplied 1.2 binary. No license file or
redistribution grant was found. The adapted package is for private research;
production repository admission remains blocked.

## Current result

The pinned source port in `tools/patches/doodle-ios27-source-port.patch`
builds reproducibly as signed arm64 and arm64e slices. The current dylib
SHA-256 is `64eae513d7a96e691ba177660141fcaa26327d0b3b5f862338584b28f7522086`.
The private package is version `1:1.1+0sky27.2`, SHA-256
`3bd29448716730774e20583f1b634b44cf7c2879a8cd949742ff9835c591c24f`.
Its build and package reports are under `artifacts/compatibility/doodle/`.

The package installed transactionally on the iPhone 12 (`iPhone13,2`, iOS
27.0 build `24A5390f`). The runtime registry admitted its exact dylib hash,
and injection-state recorded that dylib loaded into SpringBoard. The user
recorded three matching patterns in 0-Sky Control. During a controlled
lock-screen trial, the researcher reported a direct pattern unlock, rejection
of a different pattern, normal keypad fallback, and a second direct pattern
unlock. SpringBoard's PID stayed stable and Doodle was not quarantined.
The device removed the legacy weakly protected passcode preference only after
the port's device-only Keychain write and readback succeeded. No passcode or
pattern coordinates were collected in the UAT report.

These physical gesture checks are **researcher-observed**. The automated
checks cover package integrity, registration in the injection registry,
SpringBoard loading, preference structure, and process stability. The local
UAT receipt records the exact installed version, dylib hash, model, and OS
build; Control checks all four before it enables Doodle's switch. Control
build `3.5.0.6` was installed on both test phones. The iPhone 12 displayed
the verified Tweaks row and settings page with the switch on. Switching
the tweak prompts for an explicit SpringBoard restart because hook setup
runs at SpringBoard launch.

An isolated trust Cryptex loaded the signed dylib on both the iPhone 12 and
iPhone SE 2020 (`iPhone12,8`, iOS 27.0 build `24A437`). The reviewed private
package is now also installed on the SE and admitted to its runtime
registry with no Doodle quarantine. Three valid pattern paths were saved
without exporting their coordinates. The reviewed build was enabled and
SpringBoard restarted. The researcher reported direct pattern unlock,
wrong-pattern rejection, keypad fallback, and repeat pattern unlock on the
SE. The device retained a stable SpringBoard PID and recorded a local UAT
receipt tied to the exact package version, dylib hash, model, and OS build.
Gesture actions are researcher-observed rather than automated.

After a full SE reboot, a read-only probe confirmed the exact package
version and dylib hash, three saved paths, enabled preference, matching local
UAT receipt, live injection in the new SpringBoard process, and no Doodle
quarantine. After one native passcode unlock, the researcher reported that
the saved pattern unlocked directly again. No passcode or pattern data was
collected.

The iPhone 12 Control switch displayed an explicit restart alert when turned
off. Applying it saved `enabled=false` without changing the three patterns,
and SpringBoard restarted. A subsequent full iPhone 12 reboot preserved the
exact package, enabled preference, saved patterns, local UAT receipt, and live
injection in the new SpringBoard process. The researcher reported that the
saved pattern still unlocked directly after this reboot. In a second Control
cycle, the off and on actions each saved their requested value and restarted
SpringBoard. The reviewed dylib loaded in the final process, and the
researcher reported another direct pattern unlock.

The port removes three hooks whose methods are absent on both tested iOS 27
devices. It omits the old native Preferences executable, which crashed on
iOS 27 and embedded a developer build path. 0-Sky Control hosts Doodle's
declarative settings and native pattern recorder instead. The design retains
single-gesture unlock, using a device-only Keychain item after successful
native authentication. A stored passcode remains sensitive even in Keychain;
the normal keypad is available if the item is absent or the private unlock
call rejects it.

## Rebuild

```sh
python3 tools/build_doodle_ios27_candidate.py \
  --source /path/to/clean/Doodle-1.1 \
  --theos /path/to/theos \
  --artifact /path/to/new/Doodle.ios27.dylib \
  --report /path/to/new/build-report.json
```

Use new output paths. The builder checks the pinned commit and patch hash,
builds twice from clean trees, and rejects differing bytes. The package
builder `tools/package_doodle_ios27_private.py` then verifies that exact
signed dylib and emits a minimal rootless DEB with a canonical XML filter.
The original Doodle 1.2 binary and Preferences executable are excluded.

## Outstanding verification

`OSKY_PORTED`; private device UAT passed with warnings. Automated physical
gesture UAT is unavailable, so those checks remain researcher-observed.
`REPO_ADMISSION=BLOCKED` until the source/version provenance and redistribution
license are resolved. The exact status and evidence paths are in
`compat/ios27/doodle/0sky-compat.json`.
