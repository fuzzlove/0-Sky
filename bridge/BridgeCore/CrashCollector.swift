import CryptoKit
import Foundation

public enum CrashArtifactKind: String, Codable, Sendable {
    case application, daemon, springBoard, watchdog, jetsam, panic, unknown
}

public struct CrashArtifact: Codable, Hashable, Sendable {
    public let originalPathHash: String
    public let filename: String
    public let kind: CrashArtifactKind
    public let capturedAt: Date
    public let size: Int
}

public protocol CrashReportProviding: Sendable {
    func listRecentCrashReports(profile: DeviceProfile, since: Date) async -> BridgeOperationResult
    func readCrashReport(profile: DeviceProfile, path: String) async -> BridgeOperationResult
}

extension SSHManager: CrashReportProviding {}

public actor CrashCollector {
    private let source: any CrashReportProviding
    private let recorder: ResearchSessionRecorder
    private let events: EventBus
    private var captured: [UUID: Set<String>] = [:]

    public init(ssh: any CrashReportProviding, recorder: ResearchSessionRecorder, events: EventBus) {
        self.source = ssh; self.recorder = recorder; self.events = events
    }

    public func collect(profile: DeviceProfile, session: ResearchSession) async -> [CrashArtifact] {
        let listing = await source.listRecentCrashReports(profile: profile, since: session.manifest.startedAt)
        guard listing.succeeded else {
            await publishFailure(profile: profile, session: session, operation: "list",
                                 result: listing, reason: "Crash report discovery failed.")
            return []
        }
        var results: [CrashArtifact] = []
        let paths = listing.stdout.split(separator: "\n").map(String.init).filter(Self.validPath)
        for path in paths.prefix(100) {
            let pathHash = SHA256.hash(data: Data(path.utf8)).map { String(format: "%02x", $0) }.joined()
            guard !captured[session.id, default: []].contains(pathHash) else { continue }
            let report = await source.readCrashReport(profile: profile, path: path)
            guard report.succeeded, !report.stdout.isEmpty else {
                await publishFailure(profile: profile, session: session, operation: "read",
                                     result: report, reason: "A session crash report could not be read.")
                continue
            }
            let kind = Self.kind(path)
            let base = URL(fileURLWithPath: path).lastPathComponent
            let name = "\(String(pathHash.prefix(12)))-\(Self.safeName(base))"
            do {
                _ = try await recorder.captureArtifact(
                    data: Data(report.stdout.utf8), category: "crashes", name: name
                )
                captured[session.id, default: []].insert(pathHash)
                let artifact = CrashArtifact(originalPathHash: pathHash, filename: name, kind: kind,
                                             capturedAt: Date(), size: report.stdout.utf8.count)
                results.append(artifact)
                await events.publish(BridgeEvent(
                    event: .crashDetected, deviceID: profile.udid, sessionID: session.id,
                    severity: kind == .panic ? .critical : .warning, component: "crash_collector",
                    message: "Session-relevant \(kind.rawValue) report captured.",
                    evidence: ["file": .string(name), "kind": .string(kind.rawValue)]
                ))
            } catch EvidenceError.fileExists {
                // A prior capture may have completed before in-memory state was
                // restored. Treat it as captured without overwriting evidence.
                captured[session.id, default: []].insert(pathHash)
            } catch {
                await events.publish(BridgeEvent(
                    event: .serviceFailed, deviceID: profile.udid, sessionID: session.id,
                    severity: .warning, component: "crash_collector",
                    message: "Crash evidence capture failed.",
                    observed: ["failure": .string(DiagnosticRedactor.redact(error.localizedDescription))],
                    expected: ["condition": .string("session-relevant crash report captured without overwrite")]
                ))
            }
        }
        return results
    }

    private func publishFailure(profile: DeviceProfile, session: ResearchSession,
                                operation: String, result: BridgeOperationResult,
                                reason: String) async {
        await events.publish(BridgeEvent(
            event: .serviceFailed, deviceID: profile.udid, sessionID: session.id,
            severity: .warning, component: "crash_collector", message: reason,
            observed: [
                "operation": .string(operation),
                "exit_code": .number(Double(result.exitCode)),
                "failure": .string(DiagnosticRedactor.redact(result.stderr)),
            ],
            expected: ["condition": .string("bounded session crash collection succeeds")]
        ))
    }

    private static func validPath(_ path: String) -> Bool {
        guard path.count <= 1_024, !path.contains("\0"), !path.contains("\r"),
              !path.split(separator: "/").contains("..") else { return false }
        return path.hasPrefix("/var/mobile/Library/Logs/CrashReporter/")
            || path.hasPrefix("/Library/Logs/CrashReporter/")
    }

    private static func kind(_ path: String) -> CrashArtifactKind {
        let value = path.lowercased()
        if value.contains("panic") { return .panic }
        if value.contains("jetsam") { return .jetsam }
        if value.contains("watchdog") { return .watchdog }
        if value.contains("springboard") { return .springBoard }
        if value.contains("daemon") { return .daemon }
        if value.hasSuffix(".ips") || value.hasSuffix(".crash") { return .application }
        return .unknown
    }

    private static func safeName(_ value: String) -> String {
        let cleaned = value.replacingOccurrences(of: #"[^A-Za-z0-9._-]+"#, with: "-", options: .regularExpression)
        return String(cleaned.prefix(120)).isEmpty ? "report.ips" : String(cleaned.prefix(120))
    }
}
