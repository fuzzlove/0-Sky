# 0-Sky Link source

0-Sky Link is the device-side status and control surface for an authorized SRD
runtime. It displays the exact pairing/runtime state and communicates only with
the authenticated device-local service on loopback.

## Requirements

- macOS with Xcode and an iPhoneOS SDK supporting iOS 17+
- Apple Clang, `codesign`, `zip`, `sips`, and `shasum`
- An authorized SRD installation/signing workflow

## Build

```sh
./build.sh
```

The source build creates `dist/0-Sky-Link-1.9.0-source.ipa`. It does not contain
the production SRD Kit, third-party device packages, Apple-provided assets,
pairing records, or credentials.

For an authorized local integration build, set `ZEROSKY_KIT_SOURCE` to a
researcher-controlled, already-audited directory. The build copies that tree as
data into `SRDKit/` and generates a new SHA-256 manifest. Never point this at a
live state, pairing, log, or evidence directory.
