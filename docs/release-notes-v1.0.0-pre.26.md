# 0-Sky 1.0.0 pre-release 26

This replacement fixes the SRDssh packaging defect found during the exact
pre.25 GitHub-package upgrade test on the Intel Mac.

## Fixes

- The verified release kit now requires the complete Dropbear runtime payload,
  including the confined relative `usr/bin/sh -> toybox` link used for every
  noninteractive SSH command.
- Personalized SRDssh image construction independently verifies that exact link
  before building or installing a Cryptex. Missing, absolute, traversing, or
  incorrectly targeted shell links fail before device mutation.
- Release-manifest fixtures and regression tests cover both the positive link
  shape and the missing-link failure that pre.25 did not detect.
- The post-activation UID and device-identity checks now share one authenticated
  SSH session, removing a launchd-settling race between two redundant
  connections. A later SSH or package failure also retains its real diagnosis
  instead of incorrectly opening the unrelated Paired Macs enrollment flow.
- After the exact-UDID USB bootstrap proves UID 0 through a newly rotated
  Dropbear key, setup atomically commits that verified pin to the persistent
  per-device worker profile. Strict checking remains enabled throughout; no
  LAN key scan or automatic unverified replacement is permitted.
- First-runtime Xcode packaging now receives a restricted PATH containing the
  signed, build-capable `dpkg-deb` helper and Apple system tools. It neither
  depends on nor accidentally selects a Homebrew executable.
- A large userspace USB Cryptex transfer that stops receiving HTTP/2
  flow-control credit before commit gets one bounded retry on a fresh
  exact-device connection. Other protocol errors are not retried, and the
  transport never silently pairs or falls back to an unverified endpoint.
- A newly replaced 0-Sky Control is now launched through Apple's exact-device
  `devicectl` service and must return a concrete process identifier before the
  existing eight-second survival check begins. This removes the false failure
  where `uiopen` returned success but discarded the first post-install launch.
- Release preparation now restores the reviewed transactional Cryptex
  installer for Filza instead of wrapping that active setup route in the
  legacy compatibility blocker. The kit gate also requires Filza's sealed
  image, executable, and `Info.plist` identities and verifies the image hash
  before the package can be built. Its flattened reviewed image is mounted
  read-only and rebuilt as a current SDK Cryptex with a measured trust cache;
  a bounded install-completion timeout receives the same single fresh paired-
  USB retry and pre-commit check as a flow-control stall.

## Root cause

Pre.25 installed a healthy Dropbear server and accepted the caller-owned SSH
key, but the packaged payload omitted its configured command shell. As a
result, authentication completed while every command exited status 1; the
bootstrap correctly failed closed after its bounded readiness window. This was
not a pairing, host-key, Procursus, or password problem.

## Upgrade

Install pre.26 over pre.25, keep the same unlocked SRD connected directly by
USB, and press **Resume**. Existing device data, pairing, SSH keys, installed
applications, Procursus, and completed setup state are preserved. The corrected
installer rebuilds only the required SRDssh generation, verifies UID 0 command
execution, and continues the remaining resumable stages.
