# 0-Sky Control source

0-Sky Control 3.5.36 is the device-side package, health, privacy, networking,
automation, recovery, and research-management application. It is derived from
TrollStore; upstream source attribution and the GPL license are retained.

## Requirements

- macOS and Xcode with an iPhoneOS SDK
- [Theos](https://theos.dev/docs/installation), with `THEOS` set
- `libarchive`, OpenSSL 3, and `pkg-config` development metadata (Homebrew is
  one supported provider; set `LIBARCHIVE_PREFIX` for another provider)
- `ldid`, GNU Make, Python 3, and `dpkg-deb`
- An authorized SRD signing/registration workflow

## Build

```sh
export THEOS=/path/to/theos
make control
```

On a Homebrew-based development host, the prerequisites may be installed with
`brew install libarchive openssl@3 pkg-config ldid dpkg`. This is a source
developer prerequisite only; the compiled Bridge package must use its verified
bundled runtime and never invokes Homebrew.

The build first produces the lite root helper, embeds it into the Control app,
and asks Theos to create the rootless package. Generated helpers, `.theos`,
packages, certificates, provisioning profiles, and keys are ignored.

The source-only `build-stubs/` directory supplies the link-time declarations
needed for Apple private frameworks; it contains no framework implementation.
`ChOma/src` is vendored source from upstream commit
`964023ddac2286ef8e843f90df64d44ac6a673df`. Upstream certificates and
precompiled libraries are deliberately excluded.

Release and canonical Bridge builds validate Theos and all recursive
submodules against `manifests/source-dependencies.json`. Initialize that exact
revision recursively; an arbitrary moving Theos checkout is not a release
input.

Run the source-level compatibility test:

```sh
python3 TrollStoreLite/tests/test_device_compatibility.py
```

The app communicates with the device-local 0-Sky runtime on loopback and fails
closed when the authenticated runtime is unavailable. No device token or
pairing record is compiled into the source.
