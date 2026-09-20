# Diagnostics, security disclosure, and logging

## Complete diagnostic contract

The **Diagnostics** screen is a full-disclosure view, not a summary-only score.
**Run Diagnostics** automatically enables verbose output and displays the
versioned `SecurityDiagnosticsCatalog`. For every standard security assertion,
the UI and export state:

- stable check ID, title, category, and when it executes;
- measured result (`PASS`, `INFO`, `WARNING`, `DEGRADED`, `FAIL`, or `UNKNOWN`),
  result source, severity, and duration;
- purpose, exact method, and expected condition;
- data accessed, evidence retained, and privileges used;
- whether the check mutates state (`NO` for every standard diagnostic check);
- network scope and secret-handling behavior;
- complete structured observations, redacted raw evidence, root cause, failure
  kind, remediation, and known limitations.

A catalog entry with no structured measurement is printed as **`NOT_RUN`**. It
is never inferred to be `PASS` because a downstream component happens to work.
The First-Failing-Transition engine remains the source for dependency-aware root
cause analysis; the disclosure view does not turn downstream symptoms into
independent root causes.

Disclosure schema: `1`. Disclosure content version: `2026.09.20.1`.

## Security checks disclosed

The current catalog covers device identity/discovery; exact-device USB;
wireless pairing; 0-Sky paired-Mac registry; Apple trust; RemoteXPC; CoreDevice
developer services; Research DDI; debugserver reachability; host LLDB; local
port forwarding; pinned key-only root SSH; legacy root/mobile default
credentials; VNC null/empty authentication on device-loopback ports 5900 and
5800; owned bridge services; 0-Sky Link; 0-Sky Control; Cryptex; bootstrap;
Frida host, device, exact version compatibility, and attach disclosure; host
and device storage; required host dependencies; process-ownership boundaries;
and diagnostic redaction/collection policy.

The standard run is observational. In particular, it does not mount or replace
a DDI, attach to a process, change a password, replace a Cryptex, modify a
bootstrap, reboot a device, or scan a LAN. Recovery is a separate, tiered user
action.

## Default-credential privacy

The SSH default-credential check compares only root/mobile password-hash fields
on the authorized device against the fixed legacy-default hash. The plaintext
password is not transmitted or logged, and hash fields never leave the device.
The VNC check runs on the selected device's loopback interface only; it records
booleans and protocol metadata, never configured VNC credentials, challenges,
or responses.

## Diagnostic export

**Export Diagnostic Report** creates a new collision-safe mode-0700 directory
named `0sky-diagnostic-YYYYMMDD-HHMMSS[-unique]`. Existing reports are never
overwritten. Every file is mode 0600:

- `summary.txt` — readiness and first failure;
- `host.json`, `device.json`, `services.json`, `pairing.json`, `network.json`;
- `health.json` and `srd-health.json` — normalized result objects;
- `security-checks.json` — complete machine-readable methodology plus results;
- `security-disclosure.txt` — complete human-readable methodology plus results;
- `collection-policy.json` — included/excluded data and redaction contract;
- `bridge.log` and `operations.log` — redacted structured logs/output;
- `hashes.sha256` — SHA-256 for every other report file.

Redaction removes password/token/secret/authorization values, key blobs, token
headers, device identifiers where applicable, IP/SSID data where applicable,
and user home names. The host computer name is replaced with `Mac (redacted)`.
Keychain contents and private-key bytes are never requested by the exporter.
Pairing records and credentials are never exported. Only selected-device 0-Sky
state belongs in a report; unrelated files and process inventory are not
collected. User-generated output can contain novel sensitive formats, so a
bundle should still be reviewed before external disclosure.

## Structured logs and clearing

The UI uses structured categories: `device`, `pairing`, `wireless`, `usb`,
`ssh`, `coredevice`, `remotexpc`, `service`, `script`, `health`, `repair`, and
`security`, with INFO/PASS/WARN/ERROR/DEBUG levels. Script stdout and stderr are
streamed independently, timestamped, bounded, and redacted before display.

**Clear 0-Sky Bridge Logs** clears only shared rotating Bridge logs and the GUI's
in-memory view. Research-session evidence is preserved. The Researcher Console
exposes approved named operations only; Copy/Save uses the already-redacted
transcript and saved files are mode 0600.
