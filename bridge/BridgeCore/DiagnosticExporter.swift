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
        logs: [BridgeLogEntry],
        operations: [BridgeOperationResult]
    ) throws -> URL {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        let directory = root.appendingPathComponent(
            "0sky-diagnostic-\(formatter.string(from: Date()))",
            isDirectory: true
        )
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
        try data.write(to: destination, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: destination.path
        )
    }
}
