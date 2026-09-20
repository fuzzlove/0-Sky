import Foundation

/// Public, versioned disclosure of every security-relevant assertion made by
/// the Diagnostics screen. This describes the test itself, not just its result.
public struct SecurityCheckDisclosure: Identifiable, Codable, Hashable, Sendable {
    public let id: String
    public let title: String
    public let category: String
    public let execution: String
    public let purpose: String
    public let method: String
    public let expected: String
    public let evidenceCollected: [String]
    public let dataAccessed: [String]
    public let privileges: String
    public let mutatesState: Bool
    public let networkScope: String
    public let secretHandling: String
    public let limitations: [String]

    public init(
        id: String, title: String, category: String,
        execution: String = "Active during a complete diagnostic run",
        purpose: String, method: String, expected: String,
        evidenceCollected: [String], dataAccessed: [String],
        privileges: String, mutatesState: Bool = false,
        networkScope: String = "None",
        secretHandling: String = "No secret is collected or exported.",
        limitations: [String] = []
    ) {
        self.id = id; self.title = title; self.category = category
        self.execution = execution; self.purpose = purpose; self.method = method
        self.expected = expected; self.evidenceCollected = evidenceCollected
        self.dataAccessed = dataAccessed; self.privileges = privileges
        self.mutatesState = mutatesState; self.networkScope = networkScope
        self.secretHandling = secretHandling; self.limitations = limitations
    }
}

public struct SecurityDiagnosticRecord: Identifiable, Codable, Sendable {
    public var id: String { disclosure.id }
    public let disclosure: SecurityCheckDisclosure
    public let result: HealthResult?
    public let resultSource: String
}

public enum SecurityDiagnosticsCatalog {
    public static let schemaVersion = 1
    public static let disclosureVersion = "2026.09.20.1"
    public static let noResultExplanation = "No structured result was produced by this run; this is disclosed as NOT_RUN, never PASS."

    private static let active = "Active during a complete diagnostic run"
    private static let legacy = "Active in the connection-health pass; reported separately from adapter health"
    private static let disclosed = "Security control disclosure only; not independently attested by this diagnostic run"

    public static let checks: [SecurityCheckDisclosure] = [
        .init(id: "DEVICE", title: "Device discovery and target identity", category: "Identity", execution: legacy,
              purpose: "Establish that the selected Apple device is currently discoverable without treating another device as the target.",
              method: "Merge CoreDevice, usbmux and RemoteXPC discovery by validated stable identifier; reject malformed identifiers and report the observed transport.",
              expected: "The selected device is visible over an authenticated USB or previously verified wireless relationship.",
              evidenceCollected: ["presence", "transport type", "product metadata when available"],
              dataAccessed: ["CoreDevice/usbmux discovery metadata"], privileges: "Unprivileged Mac user",
              limitations: ["Discovery does not itself prove Apple trust, SSH trust, or SRD eligibility."]),
        .init(id: "USB", title: "Exact-device USB transport", category: "Transport",
              purpose: "Confirm a physical transport exists for the exact selected device.",
              method: "Read the normalized discovery record and require usbConnected=true for the selected stable identifier.",
              expected: "Exact selected device visible over USB.", evidenceCollected: ["connected boolean"],
              dataAccessed: ["normalized device discovery state"], privileges: "Unprivileged Mac user",
              limitations: ["Cable presence alone is not pairing or trust proof."]),
        .init(id: "WIFI_PAIRING", title: "Wireless pairing relationship", category: "Transport and trust", execution: legacy,
              purpose: "Verify that Wi-Fi use is based on a previously authenticated device relationship.",
              method: "Evaluate durable wireless capability evidence and, when connected, run the typed wireless transport verification for this device and Mac identity.",
              expected: "A device-bound wireless pairing relationship is independently verified.",
              evidenceCollected: ["capability state", "transport result", "selected-device binding"],
              dataAccessed: ["local non-secret pairing receipt", "Apple device transport metadata"], privileges: "Unprivileged Mac user",
              networkScope: "Selected device relationship only",
              limitations: ["A reachable IP address or Bonjour advertisement is not accepted as trust."]),
        .init(id: "PAIRING", title: "0-Sky paired-Mac registry", category: "Identity and authorization", execution: legacy,
              purpose: "Prove that this Mac is one of the device-authorized 0-Sky computers without removing other computers.",
              method: "Verify the device-token HMAC, schema, device identifier, SSH public-key fingerprint, Mac Ed25519 identity fingerprint, and active host entry in the bounded schema-2 registry.",
              expected: "Authenticated registry is valid and contains the exact live Mac identity.",
              evidenceCollected: ["registry schema", "paired-host count", "active-host match booleans", "freshness booleans"],
              dataAccessed: ["device pairing marker", "worker heartbeat", "authorized public-key fingerprints"], privileges: "Authenticated root SSH for live verification",
              networkScope: "Pinned exact-device SSH connection",
              secretHandling: "The bridge token is read and used only on-device. Pairing records, tokens and private keys are never returned.",
              limitations: ["The diagnostic does not export Apple Lockdown pairing records."]),
        .init(id: "TRUST", title: "Apple trust and Mac identity", category: "Identity and authorization", execution: legacy,
              purpose: "Separate Apple trust, exact-device SSH trust and 0-Sky Mac enrollment into independently required conditions.",
              method: "Require a live Apple Lockdown validation, selected UDID match, pinned device SSH host key and matching Mac identity evidence.",
              expected: "This Mac is trusted by the selected device and every identity binding matches.",
              evidenceCollected: ["Lockdown validated boolean", "UDID-match boolean", "host-key-match boolean", "Mac-identity-match boolean"],
              dataAccessed: ["live pairing result", "local fingerprints"], privileges: "Unprivileged Mac user plus authenticated device channel",
              limitations: ["A physical Trust prompt and passcode approval remain user-mediated."]),
        .init(id: "REMOTEXPC", title: "RemoteXPC exact-device availability", category: "Developer transport",
              purpose: "Confirm the selected SRD appears through the RemoteXPC stack used for research services.",
              method: "Run the pinned pymobiledevice3 remote browse operation with a five-second browse bound and require the selected validated identifier in successful output.",
              expected: "Authenticated RemoteXPC discovery contains the selected device.",
              evidenceCollected: ["exit code", "bounded redacted stdout/stderr"], dataAccessed: ["RemoteXPC browse metadata"],
              privileges: "Unprivileged Mac user", networkScope: "Apple RemoteXPC discovery",
              limitations: ["Presence does not imply DDI, debugserver or LLDB readiness."]),
        .init(id: "DEVELOPER_SERVICES", title: "CoreDevice developer services", category: "Developer services",
              purpose: "Confirm the installed Xcode toolchain exposes CoreDevice developer-service support.",
              method: "Invoke the fixed devicectl version/find probe through the managed process runner.",
              expected: "devicectl is present and executes successfully.", evidenceCollected: ["exit code", "duration", "redacted tool output"],
              dataAccessed: ["local Xcode toolchain"], privileges: "Unprivileged Mac user",
              limitations: ["Tool presence alone does not prove the selected device DDI is usable."]),
        .init(id: "DDI", title: "Research DDI services", category: "Developer services",
              purpose: "Measure compatible Developer Disk Image services without silently mounting or replacing a DDI.",
              method: "Run `devicectl device info ddiServices` for the exact validated device with `--no-auto-mount-ddis`; parse the bounded JSON result.",
              expected: "Compatible DDI services are reported for the selected device.",
              evidenceCollected: ["exit code", "parsed service JSON", "duration"], dataAccessed: ["CoreDevice DDI service metadata"],
              privileges: "Unprivileged Mac user", mutatesState: false,
              limitations: ["The probe deliberately does not auto-mount, install or replace a DDI."]),
        .init(id: "DEBUGSERVER", title: "Debug service reachability", category: "Debugging",
              purpose: "Prove that mounted developer services expose a usable debugging path.",
              method: "Run CoreDevice-aware LLDB in batch mode, select the exact device, enumerate attachable processes, then quit without attaching.",
              expected: "LLDB selects the device and lists processes successfully.", evidenceCollected: ["exit code", "probe identifier", "bounded redacted LLDB output"],
              dataAccessed: ["device process names exposed by developer services"], privileges: "Apple developer-service authorization",
              networkScope: "CoreDevice connection to selected device",
              limitations: ["No process is attached, suspended, read or modified; enumeration is reachability proof only."]),
        .init(id: "LLDB", title: "Host LLDB availability", category: "Debugging",
              purpose: "Confirm the host debugger executable can run.", method: "Execute fixed `xcrun lldb --version` with a 15-second timeout.",
              expected: "Host LLDB returns a version successfully.", evidenceCollected: ["available boolean", "redacted version output", "exit code"],
              dataAccessed: ["local Xcode toolchain"], privileges: "Unprivileged Mac user",
              limitations: ["This is distinct from device debug-service reachability."]),
        .init(id: "PORT_FORWARD", title: "Local SSH forwarding port", category: "Network boundary", execution: legacy,
              purpose: "Verify the instance-scoped local port accepts a TCP connection.",
              method: "Open one bounded TCP connection to the configured loopback forwarding port.",
              expected: "Configured loopback port accepts a connection.", evidenceCollected: ["open/closed result"],
              dataAccessed: ["local loopback socket"], privileges: "Unprivileged Mac user", networkScope: "127.0.0.1 only",
              limitations: ["An open port is not accepted as SSH authentication proof."]),
        .init(id: "SSH", title: "Pinned root SSH proof", category: "Authenticated transport",
              purpose: "Verify key-only access to the exact device and measured effective UID 0.",
              method: "Use `/usr/bin/ssh` with BatchMode, IdentitiesOnly, StrictHostKeyChecking, a per-device HostKeyAlias and known-hosts file; disable password and keyboard-interactive authentication; require `id -u` to equal zero.",
              expected: "Pinned SSH succeeds and returns the fixed root-ready marker.", evidenceCollected: ["exit code", "root-ready marker", "duration", "redacted errors"],
              dataAccessed: ["local SSH public/private identity path", "per-device known-host pin", "remote effective UID"],
              privileges: "Authenticated device root; Bridge itself remains an unprivileged Mac process",
              networkScope: "Loopback USB forward or exact CoreDevice hostname only",
              secretHandling: "The private key path is passed directly to OpenSSH and is redacted from logs; key bytes are never read by the exporter.",
              limitations: ["SSH success does not imply DDI or research-tool readiness."]),
        .init(id: "DEFAULT_CREDENTIALS", title: "Legacy SSH account credentials", category: "Credential security",
              purpose: "Warn when root or mobile still uses the legacy default credential.",
              method: "Over authenticated root SSH, read only the password-hash fields for root/mobile and compare them on-device to the fixed legacy default hash. The plaintext password is never sent, stored or logged.",
              expected: "Neither root nor mobile matches the legacy default hash.",
              evidenceCollected: ["measured boolean", "root-default boolean", "mobile-default boolean", "account count"],
              dataAccessed: ["root/mobile hash fields in readable master.passwd files"], privileges: "Authenticated device root",
              networkScope: "Pinned exact-device SSH connection",
              secretHandling: "Password hashes and plaintext credentials are never returned. Only match booleans are emitted.",
              limitations: ["This checks the known legacy default only; it does not grade password strength or test arbitrary passwords."]),
        .init(id: "VNC_DEFAULT_CREDENTIALS", title: "VNC null/default access", category: "Credential security",
              purpose: "Detect unauthenticated RFB, empty-password VNC, or unauthenticated HTTP-VNC exposure.",
              method: "Run a bounded device-local probe against loopback ports 5900 and 5800. Negotiate RFB security types and calculate the empty-password challenge response in memory; issue one HTTP/1.0 request to port 5800.",
              expected: "No RFB None authentication, empty-password success, or unauthenticated HTTP-VNC endpoint.",
              evidenceCollected: ["port-open booleans", "RFB protocol", "None-auth boolean", "empty-password boolean", "HTTP status/auth boolean"],
              dataAccessed: ["device loopback ports 5900 and 5800"], privileges: "Authenticated device root to launch the local probe",
              networkScope: "Device loopback only; no LAN scan",
              secretHandling: "No configured VNC password, challenge, response or key material is logged or exported.",
              limitations: ["This checks null/empty access, not password strength or third-party VNC ports."]),
        .init(id: "BRIDGE_DAEMON", title: "Owned bridge services", category: "Service integrity", execution: legacy,
              purpose: "Confirm every per-device 0-Sky host service is installed and running.",
              method: "Read only the allowlisted instance LaunchAgent/service labels and owned process state.",
              expected: "All required instance-scoped services are installed and running.", evidenceCollected: ["service label", "installed boolean", "state", "PID when owned"],
              dataAccessed: ["0-Sky service definitions and launchctl state"], privileges: "Unprivileged Mac user",
              limitations: ["Unrelated system processes are neither enumerated nor terminated."]),
        .init(id: "0SKY_LINK", title: "0-Sky Link authenticated status", category: "Device control plane", execution: legacy,
              purpose: "Verify Link reports a fresh authenticated worker and privileged bridge readiness.",
              method: "Through pinned SSH, read the device-local token on-device and call only the loopback pairing-status endpoint; require paired, worker_fresh and privileged_bridge_ready.",
              expected: "Fresh authenticated Link status is ready.", evidenceCollected: ["pairing readiness booleans", "protocol compatibility", "worker freshness"],
              dataAccessed: ["device loopback pairing status"], privileges: "Authenticated device root",
              networkScope: "Device loopback endpoint through pinned SSH",
              secretHandling: "The bridge token never crosses the SSH channel and is not printed.",
              limitations: ["Link readiness is separate from Control, DDI and Frida readiness."]),
        .init(id: "0SKY_CONTROL", title: "0-Sky Control runtime", category: "Device control plane", execution: legacy,
              purpose: "Measure Control installation, process state and authenticated runtime reachability independently.",
              method: "Call the token-authenticated device-loopback runtime endpoint through pinned SSH and require registered-or-mounted, running and ok fields.",
              expected: "Control is installed, running and reachable.", evidenceCollected: ["registered/mounted", "running", "reachable", "version"],
              dataAccessed: ["device loopback runtime status"], privileges: "Authenticated device root",
              networkScope: "Device loopback endpoint through pinned SSH", secretHandling: "The bridge token remains on-device.",
              limitations: ["A registered app is not assumed to be running or reachable."]),
        .init(id: "CRYTEX", title: "Cryptex mount state", category: "Research runtime",
              purpose: "Confirm at least one research Cryptex mount is present without changing it.",
              method: "Over pinned SSH, inspect the bounded cryptexd mount root and return only mounted state and a redacted basename.",
              expected: "A research Cryptex is mounted.", evidenceCollected: ["mounted boolean", "redacted mount basename"],
              dataAccessed: ["cryptexd mount directory names"], privileges: "Authenticated device root",
              limitations: ["The diagnostic never replaces a Cryptex; replacement remains Tier 3."]),
        .init(id: "BOOTSTRAP", title: "Rootless bootstrap", category: "Research runtime",
              purpose: "Verify the /var/jb environment, Python runtime and dpkg database are usable.",
              method: "Check `/var/jb`, executable Python and a readable dpkg status database; count installed-status entries.",
              expected: "Bootstrap root, Python and package database are present.", evidenceCollected: ["Python boolean", "installed-package count"],
              dataAccessed: ["bootstrap paths and dpkg status records"], privileges: "Authenticated device root",
              limitations: ["Package contents are not exported and destructive repair is not automatic."]),
        .init(id: "FRIDA_HOST", title: "Frida host tool", category: "Research tooling",
              purpose: "Confirm an approved host Frida executable is installed and version-readable.",
              method: "Select an allowlisted project/Homebrew path and run only `--version` with a ten-second timeout.",
              expected: "Host Frida returns a non-empty version.", evidenceCollected: ["available boolean", "version", "exit code"],
              dataAccessed: ["allowlisted host executable"], privileges: "Unprivileged Mac user",
              limitations: ["This does not attach to a process."]),
        .init(id: "FRIDA_DEVICE", title: "Frida device server", category: "Research tooling",
              purpose: "Confirm a known device server path is executable, running and version-readable.",
              method: "Through pinned SSH, inspect allowlisted rootless/Cryptex paths, execute `--version`, and match the exact process command without broad process killing.",
              expected: "Device Frida server is installed, running and version-readable.", evidenceCollected: ["available", "running", "version", "redacted path"],
              dataAccessed: ["allowlisted executable paths", "process command list"], privileges: "Authenticated device root",
              limitations: ["A running server does not prove attach permission."]),
        .init(id: "FRIDA_VERSION", title: "Frida version compatibility", category: "Research tooling",
              purpose: "Prevent attach failures caused by a host/device version mismatch.",
              method: "Compare independently measured host and device version strings for exact equality.",
              expected: "Host and device Frida versions match.", evidenceCollected: ["host version", "device version", "compatibility boolean"],
              dataAccessed: ["version strings only"], privileges: "Unprivileged host plus authenticated device SSH",
              limitations: ["Exact version equality is intentionally stricter than assumed protocol compatibility."]),
        .init(id: "FRIDA_ATTACH", title: "Frida attach capability", category: "Research tooling",
              purpose: "Disclose whether a live attach operation was proven.",
              method: "No attach is performed by the standard diagnostic because attaching can change target timing or state. Dependency analysis may report this as downstream of DDI/tool readiness.",
              expected: "A separately authorized attach test succeeds when explicitly requested.", evidenceCollected: ["No live attach evidence in the standard diagnostic"],
              dataAccessed: ["None during standard diagnostics"], privileges: "Would require explicit research attach authorization",
              limitations: ["NOT_RUN is expected unless a dedicated attach adapter is added."]),
        .init(id: "DEVICE_STORAGE", title: "Device evidence storage", category: "Availability",
              purpose: "Ensure enough device storage remains for stable research and evidence capture.",
              method: "Through pinned SSH, parse available KiB for `/private/var` and compare with the 512 MiB minimum.",
              expected: "At least 512 MiB is available.", evidenceCollected: ["available KiB", "minimum KiB"],
              dataAccessed: ["filesystem free-space counters"], privileges: "Authenticated device root",
              limitations: ["No files are listed or deleted."]),
        .init(id: "HOST_DISK_SPACE", title: "Host evidence storage", category: "Availability", execution: legacy,
              purpose: "Ensure the Mac has space for logs and research evidence.",
              method: "Read filesystem free-size attributes for the current user's home filesystem and compare with 2 GiB.",
              expected: "At least 2 GiB is available.", evidenceCollected: ["free MiB"], dataAccessed: ["filesystem capacity metadata"],
              privileges: "Unprivileged Mac user", limitations: ["No filenames or unrelated file contents are read."]),
        .init(id: "HOST_DEPENDENCIES", title: "Required host tools", category: "Host integrity", execution: disclosed,
              purpose: "Disclose the external tools on which security checks depend.",
              method: "The Dependencies panel checks approved paths for Python 3.12, dpkg/dpkg-deb, OpenSSH, Xcode/CoreDevice and project tools. Individual adapters still return UNKNOWN or TOOL_MISSING when their tool cannot execute.",
              expected: "Every required tool exists at an approved path and the invoked adapter succeeds.",
              evidenceCollected: ["availability and version metadata where supported"], dataAccessed: ["approved executable paths"], privileges: "Unprivileged Mac user",
              limitations: ["Path presence is not treated as a cryptographic attestation of third-party binaries."]),
        .init(id: "PROCESS_OWNERSHIP", title: "Process ownership boundary", category: "Bridge security", execution: disclosed,
              purpose: "Prevent recovery and cancellation from terminating unrelated processes.",
              method: "Record each spawned PID, process type, device, start time, command identifier and `0-Sky` ownership; terminate only registered owned PIDs.",
              expected: "Only explicitly owned processes are eligible for termination.", evidenceCollected: ["owned-process metadata"],
              dataAccessed: ["0-Sky spawned process records"], privileges: "Unprivileged Mac user",
              limitations: ["This control is enforced by process management; it is not a scan of all host processes."]),
        .init(id: "DIAGNOSTIC_REDACTION", title: "Diagnostic collection and redaction", category: "Privacy", execution: disclosed,
              purpose: "Explain exactly what diagnostics collect and exclude.",
              method: "Serialize normalized results, service state, redacted command results and structured logs into a mode-0700 directory with mode-0600 files; generate SHA-256 hashes. Apply structured and text redaction before every write.",
              expected: "No password, private key, pairing secret, bridge token, Apple account credential, raw home username or pairing record is exported.",
              evidenceCollected: ["normalized health results", "security-check catalog", "service states", "redacted logs and operations", "SHA-256 hashes"],
              dataAccessed: ["0-Sky in-memory diagnostic state only"], privileges: "Unprivileged Mac user",
              secretHandling: "Keychain contents, private-key bytes, tokens, passwords and Apple pairing records are not requested. Secret-shaped fields are replaced with `<redacted>`.",
              limitations: ["User-generated tool output can contain novel sensitive formats; exports should still be reviewed before disclosure."]),
    ]

    public static func records(
        health: BridgeHealthSnapshot?, srdHealth: SRDHealthReport?
    ) -> [SecurityDiagnosticRecord] {
        var measured: [String: (HealthResult, String)] = [:]
        for result in health?.results ?? [] {
            measured[result.name] = (result, "connection-health")
        }
        for result in srdHealth?.results ?? [] {
            measured[result.name] = (result, "typed-adapter")
        }
        return checks.map { item in
            let value = measured[item.id]
            return SecurityDiagnosticRecord(
                disclosure: item, result: value?.0,
                resultSource: value?.1 ?? "not-run"
            )
        }
    }

    public static func verboseText(
        health: BridgeHealthSnapshot?, srdHealth: SRDHealthReport?
    ) -> String {
        let values = records(health: health, srdHealth: srdHealth)
        var lines = [
            "0-Sky Security Diagnostic Full Disclosure",
            "Disclosure version: \(disclosureVersion)",
            "Generated: \(ISO8601DateFormatter().string(from: Date()))",
            "",
            "This document discloses every security assertion in the standard diagnostic, how it is measured, what data it reads, privileges used, mutations, network scope, evidence retained, secret handling, and limitations.",
            "A missing result is NOT_RUN and is never treated as PASS.",
            "",
        ]
        for record in values {
            let item = record.disclosure
            lines += [
                "================================================================================",
                "CHECK_ID=\(item.id)", "TITLE=\(item.title)", "CATEGORY=\(item.category)",
                "EXECUTION=\(item.execution)",
                "RESULT=\(record.result?.status.rawValue ?? "NOT_RUN")",
                "RESULT_SOURCE=\(record.resultSource)",
                "SEVERITY=\(record.result?.severity.rawValue ?? "NOT_RUN")",
                "PURPOSE=\(item.purpose)", "METHOD=\(item.method)",
                "EXPECTED=\(record.result?.expected ?? item.expected)",
                "PRIVILEGES=\(item.privileges)",
                "MUTATES_STATE=\(item.mutatesState ? "YES" : "NO")",
                "NETWORK_SCOPE=\(item.networkScope)",
                "DATA_ACCESSED=\(item.dataAccessed.joined(separator: " | "))",
                "EVIDENCE_COLLECTED=\(item.evidenceCollected.joined(separator: " | "))",
                "SECRET_HANDLING=\(item.secretHandling)",
                "OBSERVED=\(render(record.result?.observed ?? [:]))",
                "ROOT_CAUSE=\(record.result?.rootCause ?? "")",
                "FAILURE_KIND=\(record.result?.failureKind?.rawValue ?? "")",
                "DURATION_MS=\(record.result.map { String($0.durationMS) } ?? "")",
                "REMEDIATION=\(record.result?.remediation.joined(separator: " | ") ?? "")",
                "RAW_EVIDENCE=\(record.result?.rawEvidence.joined(separator: " | ") ?? "")",
                "LIMITATIONS=\(item.limitations.joined(separator: " | "))",
                "",
            ]
        }
        return DiagnosticRedactor.redact(lines.joined(separator: "\n"))
    }

    private static func render(_ object: [String: JSONValue]) -> String {
        object.keys.sorted().map { "\($0)=\(render(object[$0] ?? .null))" }.joined(separator: "; ")
    }

    public static func render(_ value: JSONValue) -> String {
        switch value {
        case .string(let value): DiagnosticRedactor.redact(value)
        case .number(let value): String(value)
        case .bool(let value): value ? "true" : "false"
        case .null: "null"
        case .array(let values): "[" + values.map(render).joined(separator: ", ") + "]"
        case .object(let values): "{" + render(values) + "}"
        }
    }
}
