# AppSync + AFC2D SRD research port

This directory preserves reproducible host-side source and exact-binary
compatibility profiles for authorized SRD research targets. It does not assert
that a newly discovered AFC2 candidate is functional until device validation.

## Pinned inputs

- AppSync commit `235aca6cddfbdc9fa87fcb5b2aec2df37ed6d65a`, archive SHA-256
  `f816f6e63dc2f8852855f4bce3e047487a2876f92484ae1fc90caf9dd6eea1e7`.
- afc2d-arm64 commit `7587154c9eed60636fe9d8d2ca0b286b59177b0a`, archive SHA-256
  `92b804570960798f82a42beffa430d55cb1271b5e87f68272d3881ad5d33e80a`.
- Exact-build Apple artifacts are identified in `profiles/*.json` by ProductType,
  OS version/build, architecture, Mach-O UUID, byte length, SHA-256, and primary
  dyld shared-cache UUID/mapped size.

The Apple binaries are device-derived, excluded from Git and archives, and
must be reacquired from an authorized SRD on the exact supported build. The
default Theos checkout is pinned in the reproducibility manifest. Builds use
the iPhoneOS 26.5 SDK, iOS 26.0 minimum, and arm64/arm64e slices.

Before it stages any package, `scripts/install-device.py` selects a profile by
USB product/version/build and then fails closed unless the paired device's
`/usr/libexec/lockdownd` and `/usr/libexec/afcd` architectures, Mach-O UUIDs,
byte lengths, and SHA-256 hashes match that profile. The primary dyld
shared-cache identity must match too. Package hashes are bound per profile, and
successful preflight evidence is included in the installation report.

## Adding an exact build

`scripts/discover-device-profile.py` reads the two system binaries from one
exact paired SRD, validates their Mach-O structure, and derives the three
lockdownd values from structural references rather than a build-number table:

- the unique `_CFRunLoopRun` call from `LC_MAIN`;
- the `service_ark_add_entry_block_invoke` string reference and enclosing
  arm64e functions;
- the compiler-generated service-ark stack slot relative to main's frame.

Each record distinguishes an image-relative virtual address from a
frame-relative structure displacement and records its unslid address/file
offset where applicable, expected section, method, evidence, candidate count,
semantic checks, and validation result. Discovery is read-only on the device
and emits a `discovered` profile. Review the binary/cache identities, unique
matches, and bounded disassembly before changing the profile to `reviewed`:

```sh
make discover-profile SRD_UDID='<paired-udid>' SRD_INSTANCE='<worker-instance>'
```

The discovery target refuses to overwrite different existing artifacts unless
the explicit script-level `--replace` workflow is used. After independent
review, a reviewed profile can drive a build:

```sh
make clean
make check \
  COMPATIBILITY_PROFILE="$PWD/profiles/<ProductType>-<BuildVersion>.json" \
  AFC2D_SYSTEM_AFCD="$PWD/inputs/afcd-<ProductType>-<BuildVersion>" \
  DIST_DIR="$PWD/dist/<ProductType>-<BuildVersion>"
```

Bind the exact resulting package bytes before allowing installation:

```sh
scripts/bind-profile-packages.py profiles/<profile>.json dist/<profile>/*.deb
```

An unknown or merely discovered profile, any architecture/UUID/size/hash/cache
mismatch, a failed offset validation, or unbound package artifacts stops the
dependent workflow before staging.

At every `lockdownd` process start, the tweak obtains the current Mach-O header
instead of reusing a persisted absolute address. It verifies the exact
lockdownd UUID, primary shared-cache UUID, `__TEXT,__text` bounds, and recorded
instruction evidence before resolving `header + image_relative_offset`. The
frame displacement is separately checked for alignment/bounds and tied to its
four-instruction main-function sequence. ASLR addresses are never written to a
profile. Pointer-authenticated function pointers remain signed immediately
before use, and normal code-signing verification remains enabled.

Changing the OS, either target binary, or the dyld cache invalidates the
profile automatically at preflight. There is no nearest-version fallback:
repeat discovery and review for the changed artifacts.

## Research status

Earlier hook variants reached process injection but produced
`CODESIGNING: Invalid Page` before service logic ran. Later trials also
produced PAC and memory failures. The exact-build-guarded `__DATA_CONST`
import-pointer variants are preserved under `variants/` and remain
unverified. Loader reports are not proof that `com.apple.afc2` registration or
root service access succeeded.

The working hypothesis is that repackaging alone is insufficient and that the
service must be registered before `lockdownd` consumes its embedded registry.
Whether an earlier pre-main mechanism is required is not yet verified.

`make check` performs host-only build and static validation. It never installs
to a device. Device mutation is deliberately outside the default restore and
rehearsal path.
