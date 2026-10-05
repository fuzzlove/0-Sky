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
