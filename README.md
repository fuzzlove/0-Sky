# 0-Sky

0-Sky is an authorized Apple Security Research Device control plane. This
repository publishes the source for the three first-party applications:

- [`bridge/`](bridge/) — 0-Sky Bridge for macOS
- [`link/`](link/) — 0-Sky Link for iOS/SRD
- [`control/`](control/) — 0-Sky Control for iOS/SRD

The source tree deliberately excludes device identifiers, pairing records,
credentials, tokens, SSH keys, provisioning profiles, certificates, research
sessions, logs, compiled applications, and device-derived evidence.

## Requirements

See [`REQUIREMENTS.md`](REQUIREMENTS.md) for complete host, SDK, dependency,
device, signing, and runtime requirements. Each component also has its own
README with exact build commands.

The binary Bridge release provides **Install All 0-Sky Requirements** in the
GUI. Its guided Terminal installer provisions native Python 3.12,
`dpkg`/`dpkg-deb`, USB/build tools, and the isolated pinned runtime instead of
requiring end users to assemble those prerequisites manually.

## Quick source checks

```sh
python3 tools/pii_audit.py .
(cd bridge && swift build -c debug)
(cd bridge && swift run BridgeCoreTests)
python3 control/TrollStoreLite/tests/test_device_compatibility.py
```

Building the device applications requires the Apple iPhoneOS SDK and the
researcher-provided signing/authorization environment described in the
requirements. This repository does not contain Apple-provided SRD assets or
any reusable signing credential.

## Binary pre-release

Prebuilt Apple Silicon and Intel macOS installers remain available under
[`v1.0.0-pre.1`](https://github.com/fuzzlove/0-Sky/releases/tag/v1.0.0-pre.1).
That tag predates this source publication, so its automatically generated
source archive contains only the repository content that existed at the tag.

## Security and privacy

Use only with devices and systems you own or are explicitly authorized to
research. Review [`SECURITY.md`](SECURITY.md) and [`PRIVACY.md`](PRIVACY.md).

## Attribution and licensing

0-Sky Control is derived from TrollStore and retains its upstream GPL license
and attribution in [`control/LICENSE`](control/LICENSE). Other bundled or
external dependencies retain their respective upstream licenses. Publication
of source does not redistribute Apple SDKs, Apple SRD tooling, private keys,
provisioning profiles, or third-party binary payloads.
