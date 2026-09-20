import CryptoKit
import Foundation

public actor DiagnosticExporter {
    private let root: URL

    public init(root: URL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/0-Sky/diagnostics")) {
        self.root = root
    }

    public func export(
        host: HostSummary,
        device: SkyDevice?,
        services: [ServiceStatus],
        pairing: [String: String],
        network: [String: String],
        health: BridgeHealthSnapshot?,
        srdHealth: SRDHealthReport?,
        logs: [BridgeLogEntry],
        operations: [BridgeOperationResult]
    ) throws -> URL {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        let baseDirectory = root.appendingPathComponent(
            "0sky-diagnostic-\(formatter.string(from: Date()))",
            isDirectory: true
        )
        var directory = baseDirectory
        if FileManager.default.fileExists(atPath: directory.path) {
            directory = root.appendingPathComponent(
                "\(baseDirectory.lastPathComponent)-\(UUID().uuidString.lowercased().prefix(8))",
                isDirectory: true
            )
        }
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let summary = DiagnosticRedactor.redact([
            "0-Sky Bridge diagnostic report",
            "Generated: \(ISO8601DateFormatter().string(from: Date()))",
            "Health: \(health?.state.rawValue ?? "UNKNOWN")",
            "FIRST_FAILING_TRANSITION=\(health?.firstFailingTransition.map(HealthResult.displayName(for:)) ?? "")",
            "ROOT_CAUSE=\(health?.rootCause ?? "")",
            "RECOMMENDED_ACTION=\(health?.recommendedAction ?? "")",
            "SECURITY_DISCLOSURE_VERSION=\(SecurityDiagnosticsCatalog.disclosureVersion)",
            "SECURITY_CHECK_COUNT=\(SecurityDiagnosticsCatalog.checks.count)",
            "",
        ].joined(separator: "\n"))
        try writeData(summary.data(using: .utf8)!, named: "summary.txt", in: directory)
        let safeHost = HostSummary(
            computerName: "Mac (redacted)",
            osVersion: host.osVersion,
            architecture: host.architecture,
            bridgeVersion: host.bridgeVersion,
            helperState: host.helperState
        )
        try writeJSON(safeHost, named: "host.json", in: directory)
        try writeJSON(device, named: "device.json", in: directory)
        try writeJSON(services, named: "services.json", in: directory)
        try writeJSONObject(pairing, named: "pairing.json", in: directory)
        try writeJSONObject(network, named: "network.json", in: directory)
        try writeJSON(health, named: "health.json", in: directory)
        try writeJSON(srdHealth, named: "srd-health.json", in: directory)
        let securityRecords = SecurityDiagnosticsCatalog.records(
            health: health, srdHealth: srdHealth
        )
        try writeJSON(securityRecords, named: "security-checks.json", in: directory)
        try writeData(
            Data(SecurityDiagnosticsCatalog.verboseText(
                health: health, srdHealth: srdHealth
            ).utf8),
            named: "security-disclosure.txt", in: directory
        )
        try writeJSONObject([
            "schema_version": 1,
            "disclosure_version": SecurityDiagnosticsCatalog.disclosureVersion,
            "mode": "complete-security-diagnostics",
            "check_count": SecurityDiagnosticsCatalog.checks.count,
            "missing_result_behavior": "NOT_RUN; never PASS",
            "included": [
                "normalized host metadata", "selected device metadata",
                "service state", "normalized health results",
                "complete security-check methodology", "redacted structured logs",
                "redacted operation output", "SHA-256 file hashes",
            ],
            "excluded": [
                "passwords", "password hashes", "private key bytes",
                "authentication tokens", "pairing secrets and records",
                "Apple account credentials", "unrelated personal device data",
            ],
            "redaction": "Structured secret keys and secret-shaped text are redacted before write. Review user-generated tool output before external disclosure.",
        ] as [String: Any], named: "collection-policy.json", in: directory)
        try writeJSON(logs, named: "bridge.log", in: directory)
        let safeOperations = operations.map {
            BridgeOperationResult(
                identifier: $0.identifier, startedAt: $0.startedAt, finishedAt: $0.finishedAt,
                exitCode: $0.exitCode,
                stdout: DiagnosticRedactor.redact($0.stdout),
                stderr: DiagnosticRedactor.redact($0.stderr),
                timedOut: $0.timedOut, cancelled: $0.cancelled
            )
        }
        try writeJSON(safeOperations, named: "operations.log", in: directory)
        try writeHashes(in: directory)
        return directory
    }

    private func write<T: Encodable>(_ value: T, named name: String, in directory: URL) throws {
        let encoded = try JSONEncoder.sky.encode(value)
        let redacted = DiagnosticRedactor.redact(String(decoding: encoded, as: UTF8.self))
        try writeData(Data(redacted.utf8), named: name, in: directory)
    }

    private func writeJSON<T: Encodable>(_ value: T, named name: String, in directory: URL) throws {
        try write(value, named: name, in: directory)
    }

    private func writeJSONObject(_ value: Any, named name: String, in directory: URL) throws {
        let redacted = DiagnosticRedactor.redactJSONObject(value)
        let data = try JSONSerialization.data(withJSONObject: redacted, options: [.prettyPrinted, .sortedKeys])
        try writeData(data, named: name, in: directory)
    }

    private func writeData(_ data: Data, named name: String, in directory: URL) throws {
        let destination = directory.appendingPathComponent(name)
        try data.write(to: destination, options: .withoutOverwriting)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: destination.path
        )
    }

    private func writeHashes(in directory: URL) throws {
        let names = try FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )
        .filter { $0.lastPathComponent != "hashes.sha256" }
        .sorted { $0.lastPathComponent < $1.lastPathComponent }
        let lines = try names.compactMap { url -> String? in
            let values = try url.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true else { return nil }
            let digest = SHA256.hash(data: try Data(contentsOf: url))
                .map { String(format: "%02x", $0) }.joined()
            return "\(digest)  \(url.lastPathComponent)"
        }
        try writeData(Data((lines.joined(separator: "\n") + "\n").utf8),
                      named: "hashes.sha256", in: directory)
    }
}
