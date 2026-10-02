# 0-Sky 1.0.0 pre-release 4

This source prerelease repairs the clean-checkout and GitHub Actions failures
found after the reproducibility checkpoint. It does not claim that an
experimental AFC2 hook variant has been verified.

## Fixed

- Promoted the host install, uninstall, refresh, instance-resolution, rekey,
  and SRD runtime-manager sources into tracked canonical paths.
- Made release-kit overlays consume those canonical sources instead of local
  ignored directories.
- Updated the reviewed Crane transformation test to cover both the shared-cache
  hook adaptation and the rootless support-library signing record.
- Made lifecycle and runtime tests independent of a developer's prepared kit.
- Added the missing `dpkg-deb` setup to the macOS CI job and expanded CI to run
  Bridge host, Swift, and Control tests.
- Repaired the source privacy gate with exact path/category/SHA-256 exceptions
  for immutable upstream fixtures and public repository signing keys. Changed
  bytes fail closed.
- Corrected the restore instructions to run the executable Swift test harness.

## Verified from an isolated tracked-only checkout

- Tools: 230 tests passed (4 optional-fixture skips).
- Bridge host tools: 109 tests passed (1 optional external-kit skip).
- BridgeCore: 33/33 checks passed.
- Control compatibility: 15/15 tests passed.
- iOS 27 CI selection: 100 tests passed.
- Privacy audit, EULA verification, and Bash/Zsh syntax checks passed.
- The compatibility inventory pipeline completed and correctly kept repository
  admission blocked without supplied candidate packages.

No device-changing command was run during this repair rehearsal. The earlier
AFC2 import-pointer attempts remain failed or unverified as documented in the
reproducibility state; this release does not relabel them as working.

## Current interface evidence

The root-filesystem screenshot was redacted before publication to remove the
operator name and device-unique identifiers. It shows the Bridge UI reporting
the Finder mount as mounted with read/write access; it does not establish which
experimental package variant is installed.

![0-Sky root filesystem mounted in Finder](https://raw.githubusercontent.com/fuzzlove/0-Sky/v1.0.0-pre.4/docs/assets/root-filesystem-mounted-redacted.png)

![0-Sky Research Environment launch screen](https://raw.githubusercontent.com/fuzzlove/0-Sky/v1.0.0-pre.4/docs/assets/research-environment-launch.jpeg)

![0-Sky Research Environment active component check](https://raw.githubusercontent.com/fuzzlove/0-Sky/v1.0.0-pre.4/docs/assets/research-environment-active.jpeg)

![0-Sky Control dashboard status and device research sections](https://raw.githubusercontent.com/fuzzlove/0-Sky/v1.0.0-pre.4/docs/assets/control-dashboard-status.png)
