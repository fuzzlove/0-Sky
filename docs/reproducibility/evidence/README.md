# Sanitized evidence index

This directory contains summaries only. Raw `.ips` reports, installation
reports, pairing records, SSH keys/pins, device backups, preboot paths,
incident identifiers, UDIDs, and operator home paths are excluded.

- `afc2-variants.json`: exact variant hashes, build target, outcome, and
  failure signature.
- `device-state.json`: redacted read-only device/host observations.
- `crash-summaries.json`: minimally sufficient failure taxonomy and times.

Raw reports remain local-only under ignored research directories. An operator
resuming the investigation should reacquire fresh diagnostics from the
explicitly selected SRD and sanitize them before sharing.
