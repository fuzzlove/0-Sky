# Security policy

0-Sky is intended for authorized security research and Apple Security Research
Device workflows. Do not use it on devices or systems without explicit
permission.

## Reporting

Open a GitHub security advisory for vulnerabilities. Do not attach pairing
records, credentials, private keys, device identifiers, unredacted logs, or
personal research data to a public issue.

## Design boundaries

- The macOS bridge is unprivileged by default and exposes no arbitrary root
  command executor.
- Privileged helper operations are whitelisted and authenticated.
- Child processes use argument arrays rather than shell-concatenated commands.
- Recovery is bounded and destructive device operations require explicit user
  action.
- Device output is treated as untrusted input.
- Pairing credentials and authentication secrets are excluded from exports.
