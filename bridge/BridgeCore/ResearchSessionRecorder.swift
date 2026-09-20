import CryptoKit
import Foundation

public enum EvidenceExportProfile: String, Codable, CaseIterable, Sendable {
    case internalResearch = "Internal Research"
    case vendorDisclosure = "Vendor Disclosure"
    case publicSanitized = "Public Sanitized"
}

public struct ResearchSessionManifest: Codable, Sendable {
    public let sessionID: UUID
    public let sessionName: String
    public let startedAt: Date
    public var endedAt: Date?
    public let zeroSkyVersion: String
    public let macOSVersion: String
    public let macHardware: String
    public let xcodeVersion: String?
    public let xcodeBuild: String?
    public let deviceModel: String?
    public let productType: String?
    public let deviceOS: String?
    public let deviceBuild: String?
    public let deviceIdentifier: String
    public let activeTransport: ConnectionKind
    public let bridgeVersion: String
    public let toolVersions: [String: String]
    public let researchConfiguration: [String: String]
}

public struct CommandRecord: Codable, Sendable {
    public let timestamp: Date
    public let component: String
    public let commandIdentifier: String
    public let redactedArguments: [String]
    public let exitCode: Int32
    public let durationMS: Int
    public let stdoutReference: String?
    public let stderrReference: String?

    public init(timestamp: Date = Date(), component: String, commandIdentifier: String,
                redactedArguments: [String] = [], exitCode: Int32, durationMS: Int,
                stdoutReference: String? = nil, stderrReference: String? = nil) {
        self.timestamp = timestamp; self.component = component
        self.commandIdentifier = commandIdentifier; self.redactedArguments = redactedArguments
        self.exitCode = exitCode; self.durationMS = durationMS
        self.stdoutReference = stdoutReference; self.stderrReference = stderrReference
    }
}

public struct ResearchSession: Codable, Sendable {
    public let id: UUID
    public let directory: URL
    public let manifest: ResearchSessionManifest
}

public enum EvidenceError: LocalizedError {
    case sessionAlreadyActive, noActiveSession, invalidName, unsafePath, fileExists, oversizedArtifact
    public var errorDescription: String? {
        switch self {
        case .sessionAlreadyActive: "A research session is already active."
        case .noActiveSession: "No research session is active."
        case .invalidName: "The session or artifact name is invalid."
        case .unsafePath: "The evidence path is outside the active session or is a symbolic link."
        case .fileExists: "Evidence collection never overwrites an existing file."
        case .oversizedArtifact: "The artifact exceeds the configured evidence size limit."
        }
    }
}

public actor ResearchSessionRecorder {
    public static let maximumArtifactBytes: Int64 = 256 * 1024 * 1024
    private let root: URL
    private let events: EventBus
    private var active: ResearchSession?
    private var subscription: UUID?
    private let encoder: JSONEncoder

    public init(root: URL, events: EventBus) {
        self.root = root.standardizedFileURL
        self.events = events
        self.encoder = JSONEncoder.sky
    }

    public func current() -> ResearchSession? { active }

    @discardableResult
    public func start(
        name: String, device: SkyDevice, host: HostSummary,
        toolVersions: [String: String] = [:], researchConfiguration: [String: String] = [:]
    ) async throws -> ResearchSession {
        guard active == nil else { throw EvidenceError.sessionAlreadyActive }
        let safeName = try Self.safeComponent(name, fallback: "research")
        try Self.createSecureDirectory(root)
        let id = UUID()
        let stamp = Self.directoryTimestamp.string(from: Date())
        let devicePart = Self.identifierFragment(device.udid)
        let directory = root.appendingPathComponent("\(stamp)_\(devicePart)_\(safeName)", isDirectory: true)
        guard !FileManager.default.fileExists(atPath: directory.path) else { throw EvidenceError.fileExists }
        try Self.createSecureDirectory(directory)
        for child in ["logs", "crashes", "artifacts", "reports"] {
            try Self.createSecureDirectory(directory.appendingPathComponent(child, isDirectory: true))
        }
        let manifest = ResearchSessionManifest(
            sessionID: id, sessionName: safeName, startedAt: Date(), endedAt: nil,
            zeroSkyVersion: host.bridgeVersion, macOSVersion: host.osVersion,
            macHardware: host.architecture, xcodeVersion: toolVersions["xcode"],
            xcodeBuild: toolVersions["xcode_build"], deviceModel: device.name,
            productType: device.productType, deviceOS: device.osVersion,
            deviceBuild: device.buildVersion, deviceIdentifier: device.udid,
            activeTransport: device.connection, bridgeVersion: host.bridgeVersion,
            toolVersions: Self.redactDictionary(toolVersions),
            researchConfiguration: Self.redactDictionary(researchConfiguration)
        )
        try writeJSON(manifest, to: directory.appendingPathComponent("manifest.json"))
        try writeJSON(host, to: directory.appendingPathComponent("host.json"))
        try writeJSON(device, to: directory.appendingPathComponent("device.json"))
        try writeJSON(toolVersions, to: directory.appendingPathComponent("tools.json"))
        try writeJSON([String: String](), to: directory.appendingPathComponent("health.json"))
        try writeJSON([BridgeEvent](), to: directory.appendingPathComponent("timeline.json"))
        for empty in ["events.jsonl", "commands.jsonl"] {
            try write(Data(), to: directory.appendingPathComponent(empty))
        }
        let session = ResearchSession(id: id, directory: directory, manifest: manifest)
        active = session
        subscription = await events.subscribe { [weak self] event in
            await self?.record(event: event)
        }
        await events.publish(BridgeEvent(
            event: .researchSessionStarted, deviceID: device.udid, sessionID: id,
            component: "session_recorder", message: "Research session started."
        ))
        return session
    }

    public func record(event: BridgeEvent) {
        guard let session = active,
              event.deviceID == nil || event.deviceID == session.manifest.deviceIdentifier else { return }
        do { try appendJSONLine(event, to: session.directory.appendingPathComponent("events.jsonl")) }
        catch { /* Recording failure remains visible when stop/hash verification fails. */ }
    }

    public func record(command: CommandRecord) throws {
        guard let session = active else { throw EvidenceError.noActiveSession }
        let safe = CommandRecord(
            timestamp: command.timestamp, component: DiagnosticRedactor.redact(command.component),
            commandIdentifier: DiagnosticRedactor.redact(command.commandIdentifier),
            redactedArguments: Self.redactArguments(command.redactedArguments),
            exitCode: command.exitCode, durationMS: command.durationMS,
            stdoutReference: command.stdoutReference.map(DiagnosticRedactor.redact),
            stderrReference: command.stderrReference.map(DiagnosticRedactor.redact)
        )
        try appendJSONLine(safe, to: session.directory.appendingPathComponent("commands.jsonl"))
    }

    public func recordHealth(_ report: SRDHealthReport) throws {
        guard let session = active else { throw EvidenceError.noActiveSession }
        try replaceJSON(report, at: session.directory.appendingPathComponent("health.json"))
    }

    @discardableResult
    public func captureArtifact(
        from source: URL, category: String = "artifacts", preferredName: String? = nil
    ) async throws -> URL {
        guard let session = active else { throw EvidenceError.noActiveSession }
        guard ["artifacts", "crashes", "logs", "reports"].contains(category) else { throw EvidenceError.unsafePath }
        let values = try source.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true else { throw EvidenceError.unsafePath }
        guard Int64(values.fileSize ?? 0) <= Self.maximumArtifactBytes else { throw EvidenceError.oversizedArtifact }
        let filename = try Self.safeComponent(preferredName ?? source.lastPathComponent, fallback: "artifact")
        let destination = session.directory.appendingPathComponent(category).appendingPathComponent(filename)
        guard !FileManager.default.fileExists(atPath: destination.path) else { throw EvidenceError.fileExists }
        try FileManager.default.copyItem(at: source, to: destination)
        try Self.secureFile(destination)
        await events.publish(BridgeEvent(
            event: .artifactCaptured, deviceID: session.manifest.deviceIdentifier,
            sessionID: session.id, component: "evidence", message: "Session artifact captured.",
            evidence: ["category": .string(category), "file": .string(filename)]
        ))
        return destination
    }

    @discardableResult
    public func captureArtifact(data: Data, category: String = "artifacts", name: String) async throws -> URL {
        guard let session = active else { throw EvidenceError.noActiveSession }
        guard ["artifacts", "crashes", "logs", "reports"].contains(category) else { throw EvidenceError.unsafePath }
        guard Int64(data.count) <= Self.maximumArtifactBytes else { throw EvidenceError.oversizedArtifact }
        let filename = try Self.safeComponent(name, fallback: "artifact")
        let destination = session.directory.appendingPathComponent(category).appendingPathComponent(filename)
        try write(data, to: destination)
        await events.publish(BridgeEvent(
            event: .artifactCaptured, deviceID: session.manifest.deviceIdentifier, sessionID: session.id,
            component: "evidence", message: "Session artifact captured.",
            evidence: ["category": .string(category), "file": .string(filename)]
        ))
        return destination
    }

    @discardableResult
    public func stop() async throws -> URL {
        guard let session = active else { throw EvidenceError.noActiveSession }
        await events.publish(BridgeEvent(
            event: .researchSessionStopped, deviceID: session.manifest.deviceIdentifier,
            sessionID: session.id, component: "session_recorder", message: "Research session stopped."
        ))
        if let subscription { await events.unsubscribe(subscription) }
        self.subscription = nil
        var manifest = session.manifest
        manifest.endedAt = Date()
        try replaceJSON(manifest, at: session.directory.appendingPathComponent("manifest.json"))
        let recorded = try readJSONLines(BridgeEvent.self, from: session.directory.appendingPathComponent("events.jsonl"))
        try replaceJSON(recorded, at: session.directory.appendingPathComponent("timeline.json"))
        try writeTimeline(recorded, to: session.directory.appendingPathComponent("timeline.txt"))
        try writeHashes(in: session.directory)
        active = nil
        return session.directory
    }

    public func export(sessionDirectory: URL, profile: EvidenceExportProfile,
                       destinationDirectory: URL? = nil) throws -> URL {
        let source = sessionDirectory.standardizedFileURL
        guard Self.isDescendant(source, of: root),
              FileManager.default.fileExists(atPath: source.appendingPathComponent("manifest.json").path) else {
            throw EvidenceError.unsafePath
        }
        let manifest = try JSONDecoder.sky.decode(
            ResearchSessionManifest.self, from: Data(contentsOf: source.appendingPathComponent("manifest.json"))
        )
        let exportRoot = (destinationDirectory ?? root.appendingPathComponent("exports", isDirectory: true)).standardizedFileURL
        try Self.createSecureDirectory(exportRoot)
        let output = exportRoot.appendingPathComponent("0sky-session-\(manifest.sessionID.uuidString.lowercased()).zip")
        guard !FileManager.default.fileExists(atPath: output.path) else { throw EvidenceError.fileExists }

        let staging = exportRoot.appendingPathComponent(".export-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: staging) }
        try Self.copyTreeNoSymlinks(from: source, to: staging)
        if profile != .internalResearch { try Self.sanitizeTree(staging, profile: profile) }
        try writeHashes(in: staging)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        process.arguments = ["-c", "-k", "--sequesterRsrc", "--keepParent", staging.path, output.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw BridgeCoreError.operationFailed("Evidence archive creation failed.")
        }
        try Self.secureFile(output)
        return output
    }

    // MARK: safe I/O

    private func writeJSON<T: Encodable>(_ value: T, to destination: URL) throws {
        try write(encoder.encode(value), to: destination)
    }

    private func replaceJSON<T: Encodable>(_ value: T, at destination: URL) throws {
        let data = try encoder.encode(value)
        try data.write(to: destination, options: .atomic)
        try Self.secureFile(destination)
    }

    private func write(_ data: Data, to destination: URL) throws {
        guard !FileManager.default.fileExists(atPath: destination.path) else { throw EvidenceError.fileExists }
        try data.write(to: destination, options: .withoutOverwriting)
        try Self.secureFile(destination)
    }

    private func appendJSONLine<T: Encodable>(_ value: T, to destination: URL) throws {
        var data = try encoder.encode(value); data.append(0x0A)
        let handle = try FileHandle(forWritingTo: destination)
        defer { try? handle.close() }
        try handle.seekToEnd(); try handle.write(contentsOf: data)
    }

    private func readJSONLines<T: Decodable>(_ type: T.Type, from source: URL) throws -> [T] {
        String(decoding: try Data(contentsOf: source), as: UTF8.self).split(separator: "\n").compactMap {
            try? JSONDecoder.sky.decode(type, from: Data($0.utf8))
        }
    }

    private func writeTimeline(_ events: [BridgeEvent], to destination: URL) throws {
        let formatter = DateFormatter(); formatter.dateFormat = "HH:mm:ss"; formatter.locale = Locale(identifier: "en_US_POSIX")
        let body = events.sorted { $0.timestamp < $1.timestamp }.map {
            "\(formatter.string(from: $0.timestamp)) \($0.message) [\($0.event.rawValue)]"
        }.joined(separator: "\n") + "\n"
        try write(Data(body.utf8), to: destination)
    }

    private func writeHashes(in directory: URL) throws {
        let hashFile = directory.appendingPathComponent("hashes.sha256")
        try? FileManager.default.removeItem(at: hashFile)
        let enumerator = FileManager.default.enumerator(
            at: directory, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        )
        var lines: [String] = []
        while let url = enumerator?.nextObject() as? URL {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true, url != hashFile else { continue }
            let relative = String(url.path.dropFirst(directory.path.count + 1))
            let digest = SHA256.hash(data: try Data(contentsOf: url)).map { String(format: "%02x", $0) }.joined()
            lines.append("\(digest)  \(relative)")
        }
        try write(Data((lines.sorted().joined(separator: "\n") + "\n").utf8), to: hashFile)
    }

    public static func redactArguments(_ arguments: [String]) -> [String] {
        let secretOptions = ["--password", "--token", "--secret", "--authorization", "--identity", "-i"]
        var result: [String] = []; var redactNext = false
        for argument in arguments {
            if redactNext { result.append("<redacted>"); redactNext = false; continue }
            let lower = argument.lowercased()
            if secretOptions.contains(lower) { result.append(argument); redactNext = true }
            else if secretOptions.contains(where: { lower.hasPrefix("\($0)=") }) {
                result.append("\(argument.split(separator: "=", maxSplits: 1)[0])=<redacted>")
            } else { result.append(DiagnosticRedactor.redact(argument)) }
        }
        return result
    }

    private static func redactDictionary(_ value: [String: String]) -> [String: String] {
        DiagnosticRedactor.redactJSONObject(value) as? [String: String] ?? [:]
    }

    private static func safeComponent(_ input: String, fallback: String) throws -> String {
        let cleaned = input.precomposedStringWithCanonicalMapping
            .replacingOccurrences(of: #"[^A-Za-z0-9._-]+"#, with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: ".-"))
        let value = String(cleaned.prefix(80))
        guard !value.isEmpty, value != ".", value != "..", !value.contains("/") else {
            if input.isEmpty { return fallback }; throw EvidenceError.invalidName
        }
        return value
    }

    private static func identifierFragment(_ identifier: String) -> String {
        String(SHA256.hash(data: Data(identifier.utf8)).map { String(format: "%02x", $0) }.joined().prefix(12))
    }

    private static func createSecureDirectory(_ url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }

    private static func secureFile(_ url: URL) throws {
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    private static func isDescendant(_ candidate: URL, of parent: URL) -> Bool {
        let base = parent.resolvingSymlinksInPath().standardizedFileURL.path + "/"
        return candidate.resolvingSymlinksInPath().standardizedFileURL.path.hasPrefix(base)
    }

    private static func copyTreeNoSymlinks(from source: URL, to destination: URL) throws {
        try createSecureDirectory(destination)
        let enumerator = FileManager.default.enumerator(at: source, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        while let item = enumerator?.nextObject() as? URL {
            let values = try item.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            if values.isSymbolicLink == true { enumerator?.skipDescendants(); continue }
            let relative = item.path.dropFirst(source.path.count + 1)
            let target = destination.appendingPathComponent(String(relative), isDirectory: values.isDirectory == true)
            if values.isDirectory == true { try createSecureDirectory(target) }
            else { try FileManager.default.copyItem(at: item, to: target); try secureFile(target) }
        }
    }

    private static func sanitizeTree(_ root: URL, profile: EvidenceExportProfile) throws {
        let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        while let url = files?.nextObject() as? URL {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true else { continue }
            guard let text = String(data: try Data(contentsOf: url), encoding: .utf8) else { continue }
            let safe = DiagnosticRedactor.redactForExport(text, publicProfile: profile == .publicSanitized)
            try Data(safe.utf8).write(to: url, options: .atomic); try secureFile(url)
        }
        // Credentials/pairing records are prohibited under every profile.
        for forbidden in ["pairing.json", "pairing_record.plist", "id_rsa", "id_ed25519"] {
            let file = root.appendingPathComponent(forbidden)
            if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
        }
    }

    private static let directoryTimestamp: DateFormatter = {
        let value = DateFormatter(); value.dateFormat = "yyyy-MM-dd'T'HHmmss"; value.locale = Locale(identifier: "en_US_POSIX")
        value.timeZone = TimeZone(secondsFromGMT: 0); return value
    }()
}

public extension JSONDecoder {
    static var sky: JSONDecoder {
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601; return decoder
    }
}
