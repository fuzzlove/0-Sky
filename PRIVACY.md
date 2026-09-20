# Privacy and release hygiene

This repository is source-only. It must not contain:

- physical UDIDs, serial numbers, device names, or per-device instance IDs;
- host usernames, absolute home paths, Wi-Fi SSIDs, or private network details;
- Apple account information, email addresses used as credentials, or tokens;
- SSH private keys, pairing records, provisioning profiles, certificates, or
  signing identities;
- device logs, crash reports, evidence bundles, or copied personal device data;
- compiled installer/application payloads.

Synthetic all-zero device identifiers and loopback addresses used by tests and
local IPC are not device data. Public upstream attribution and copyright notices
are retained as required by their licenses.

The Bridge agreement acceptance record is local to the Mac and contains only
the agreement version and acceptance timestamp. It does not include a device
identifier, account, credential, pairing secret, or research artifact.

Run the mandatory audit before every push:

```sh
python3 tools/pii_audit.py .
```
