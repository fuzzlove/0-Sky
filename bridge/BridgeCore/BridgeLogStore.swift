import Foundation
import OSLog

public actor BridgeLogStore {
    private let subsystem = "com.liquidsky.0sky.bridge"
    private let maximumEntries: Int
    private var entries: [BridgeLogEntry] = []

    public init(maximumEntries: Int = 10_000) {
        self.maximumEntries = maximumEntries
    }

    public func append(
        category: LogCategory,
        level: LogLevel,
        message: String,
        deviceID: String? = nil
    ) {
        let safe = DiagnosticRedactor.redact(message)
        let entry = BridgeLogEntry(
            category: category, level: level, message: safe, deviceID: deviceID
        )
        entries.append(entry)
        if entries.count > maximumEntries {
            entries.removeFirst(entries.count - maximumEntries)
        }
        let logger = Logger(subsystem: subsystem, category: category.rawValue)
        switch level {
        case .error: logger.error("\(safe, privacy: .public)")
        case .warning: logger.warning("\(safe, privacy: .public)")
        case .debug: logger.debug("\(safe, privacy: .public)")
        default: logger.info("\(safe, privacy: .public)")
        }
    }

    public func all(deviceID: String? = nil) -> [BridgeLogEntry] {
        guard let deviceID else { return entries }
        return entries.filter { $0.deviceID == nil || $0.deviceID == deviceID }
    }

    public func clear() { entries.removeAll(keepingCapacity: true) }
}
