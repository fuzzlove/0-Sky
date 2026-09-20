import Foundation

public actor StructuredEventLog {
    private let directory: URL
    private let maximumBytes: UInt64
    private let archiveCount: Int
    private var token: UUID?

    public init(directory: URL, maximumBytes: UInt64 = 5 * 1_024 * 1_024, archiveCount: Int = 3) {
        self.directory = directory.standardizedFileURL
        self.maximumBytes = max(4_096, maximumBytes)
        self.archiveCount = max(1, archiveCount)
    }

    public func attach(to bus: EventBus) async throws {
        guard token == nil else { return }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        token = await bus.subscribe { [weak self] event in await self?.append(event) }
    }

    public func detach(from bus: EventBus) async {
        if let token { await bus.unsubscribe(token) }
        token = nil
    }

    public func append(_ event: BridgeEvent) {
        do {
            let destination = directory.appendingPathComponent("bridge-events.jsonl")
            if ((try? destination.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(UInt64.init) ?? 0) >= maximumBytes {
                try rotate(destination)
            }
            let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.sortedKeys]
            var data = try encoder.encode(event); data.append(0x0A)
            if !FileManager.default.fileExists(atPath: destination.path) {
                try data.write(to: destination, options: .withoutOverwriting)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
            } else {
                let values = try destination.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
                guard values.isRegularFile == true, values.isSymbolicLink != true else { return }
                let handle = try FileHandle(forWritingTo: destination); defer { try? handle.close() }
                try handle.seekToEnd(); try handle.write(contentsOf: data)
            }
        } catch {
            // Event persistence is best-effort and must never crash the bridge.
            // The in-memory EventBus history remains available to clients.
        }
    }

    /// Clears only 0-Sky-owned bridge log files. Research-session evidence is
    /// stored under a separate root and is intentionally never touched here.
    /// Fixed filenames plus regular-file/symlink checks prevent this maintenance
    /// operation from becoming an arbitrary file deletion primitive.
    @discardableResult
    public func clear() throws -> Int {
        if FileManager.default.fileExists(atPath: directory.path) {
            let directoryValues = try directory.resourceValues(
                forKeys: [.isDirectoryKey, .isSymbolicLinkKey]
            )
            guard directoryValues.isDirectory == true, directoryValues.isSymbolicLink != true else {
                throw BridgeCoreError.invalidPath("refusing to clear an unsafe log directory")
            }
        }
        var names = ["bridge-events.jsonl", "pairing-events.jsonl", "transport-events.jsonl"]
        names.append(contentsOf: (1...archiveCount).map { "bridge-events.\($0).jsonl" })
        let existing = try names.compactMap { name -> URL? in
            let candidate = directory.appendingPathComponent(name, isDirectory: false)
            guard FileManager.default.fileExists(atPath: candidate.path) else { return nil }
            let values = try candidate.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true else {
                throw BridgeCoreError.invalidPath("refusing to clear non-regular log file: \(name)")
            }
            return candidate
        }
        for candidate in existing {
            let handle = try FileHandle(forWritingTo: candidate)
            defer { try? handle.close() }
            try handle.truncate(atOffset: 0)
            try handle.synchronize()
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: candidate.path)
        }
        return existing.count
    }

    private func rotate(_ active: URL) throws {
        let manager = FileManager.default
        let oldest = directory.appendingPathComponent("bridge-events.\(archiveCount).jsonl")
        try? manager.removeItem(at: oldest)
        if archiveCount > 1 {
            for index in stride(from: archiveCount - 1, through: 1, by: -1) {
                let source = directory.appendingPathComponent("bridge-events.\(index).jsonl")
                let destination = directory.appendingPathComponent("bridge-events.\(index + 1).jsonl")
                if manager.fileExists(atPath: source.path) { try manager.moveItem(at: source, to: destination) }
            }
        }
        if manager.fileExists(atPath: active.path) {
            try manager.moveItem(at: active, to: directory.appendingPathComponent("bridge-events.1.jsonl"))
        }
    }
}
