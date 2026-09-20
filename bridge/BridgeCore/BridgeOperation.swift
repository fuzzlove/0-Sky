import Foundation

public protocol BridgeOperation: AnyObject, Sendable {
    var identifier: String { get }
    var displayName: String { get }
    func preflight() async throws
    func execute() async throws -> BridgeOperationResult
    func cancel()
}

public struct ScriptSpecification: Sendable {
    public let identifier: String
    public let executableURL: URL
    public let arguments: [String]
    public let environment: [String: String]
    public let workingDirectory: URL?
    public let timeout: Duration
    public let requiresPrivilege: Bool
    public let maximumOutputBytes: Int

    public init(
        identifier: String,
        executableURL: URL,
        arguments: [String] = [],
        environment: [String: String] = [:],
        workingDirectory: URL? = nil,
        timeout: Duration = .seconds(60),
        requiresPrivilege: Bool = false,
        maximumOutputBytes: Int = 8 * 1_024 * 1_024
    ) {
        self.identifier = identifier
        self.executableURL = executableURL
        self.arguments = arguments
        self.environment = environment
        self.workingDirectory = workingDirectory
        self.timeout = timeout
        self.requiresPrivilege = requiresPrivilege
        self.maximumOutputBytes = max(1_024, maximumOutputBytes)
    }
}

public enum ScriptStream: String, Sendable {
    case stdout
    case stderr
}

public struct ScriptOutputEvent: Sendable {
    public let operationID: UUID
    public let stream: ScriptStream
    public let line: String
    public let timestamp: Date
}

public final class ScriptBridgeOperation: BridgeOperation, @unchecked Sendable {
    public let identifier: String
    public let displayName: String
    private let runner: ScriptRunner
    private let specification: ScriptSpecification
    private let eventHandler: @Sendable (ScriptOutputEvent) -> Void
    private let lock = NSLock()
    private var operationID: UUID?

    public init(
        displayName: String,
        runner: ScriptRunner,
        specification: ScriptSpecification,
        eventHandler: @escaping @Sendable (ScriptOutputEvent) -> Void = { _ in }
    ) {
        self.identifier = specification.identifier
        self.displayName = displayName
        self.runner = runner
        self.specification = specification
        self.eventHandler = eventHandler
    }

    public func preflight() async throws {
        try await runner.preflight(specification)
    }

    public func execute() async throws -> BridgeOperationResult {
        let id = UUID()
        lock.withLock { operationID = id }
        defer { lock.withLock { operationID = nil } }
        return try await runner.run(specification, operationID: id, onEvent: eventHandler)
    }

    public func cancel() {
        let id = lock.withLock { operationID }
        guard let id else { return }
        Task { await runner.cancel(id) }
    }
}

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T {
        lock(); defer { unlock() }
        return body()
    }
}
