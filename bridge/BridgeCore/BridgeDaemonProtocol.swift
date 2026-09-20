import Foundation
import ServiceManagement

private final class XPCConnectionReference: @unchecked Sendable {
    let value: NSXPCConnection
    init(_ value: NSXPCConnection) { self.value = value }
}

private final class XPCReplyGate<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, any Error>?

    init(_ continuation: CheckedContinuation<Value, any Error>) {
        self.continuation = continuation
    }

    /// Returns true only for the result that won the reply/timeout race.
    @discardableResult
    func finish(_ result: Result<Value, any Error>) -> Bool {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(with: result)
        return pending != nil
    }
}

@objc public protocol BridgeDaemonProtocol {
    func serviceVersion(reply: @escaping (String) -> Void)
    func snapshot(refresh: Bool, reply: @escaping (Data?, String?) -> Void)
    func recover(deviceID: String, reply: @escaping (Data?, String?) -> Void)
    func removeDevice(deviceID: String, reply: @escaping (Data?, String?) -> Void)
    func startResearchSession(name: String, deviceID: String,
                              reply: @escaping (Data?, String?) -> Void)
    func stopResearchSession(reply: @escaping (Data?, String?) -> Void)
    func exportLastResearchSession(profile: String,
                                   reply: @escaping (String?, String?) -> Void)
    func clearLogs(reply: @escaping (Bool, String?) -> Void)
}

public struct BridgeDaemonSnapshot: Codable, Sendable {
    public let serviceVersion: String
    public let serviceStartedAt: Date
    public let generatedAt: Date
    public let devices: [SkyDevice]
    public let health: [String: BridgeHealthSnapshot]
    public let srdHealth: [String: SRDHealthReport]
    public let activeSession: ResearchSession?
    public let lastError: String?

    public init(serviceVersion: String, serviceStartedAt: Date, generatedAt: Date = Date(),
                devices: [SkyDevice], health: [String: BridgeHealthSnapshot],
                srdHealth: [String: SRDHealthReport] = [:],
                activeSession: ResearchSession?, lastError: String? = nil) {
        self.serviceVersion = serviceVersion; self.serviceStartedAt = serviceStartedAt
        self.generatedAt = generatedAt; self.devices = devices; self.health = health
        self.srdHealth = srdHealth; self.activeSession = activeSession
        self.lastError = lastError.map(DiagnosticRedactor.redact)
    }
}

public final class BridgeDaemonClient: @unchecked Sendable {
    public static let machServiceName = "com.liquidsky.0sky.bridge.service"
    private let connectionLock = NSLock()
    private var retainedConnection: NSXPCConnection?
    public init() {}

    deinit {
        connectionLock.lock()
        let connection = retainedConnection
        retainedConnection = nil
        connectionLock.unlock()
        connection?.invalidate()
    }

    public static func registrationStatus() -> String {
        switch SMAppService.agent(plistName: "com.liquidsky.0sky.bridge.service.plist").status {
        case .enabled: "Enabled"
        case .requiresApproval: "Approval Required"
        case .notRegistered: "Not Registered"
        case .notFound: "Not Found"
        @unknown default: "Unknown"
        }
    }

    public func version() async throws -> String {
        try await withProxy(timeoutSeconds: 10) { proxy, finish in
            proxy.serviceVersion { finish(.success($0)) }
        }
    }

    public func snapshot(refresh: Bool = true) async throws -> BridgeDaemonSnapshot {
        let data: Data = try await withProxy(timeoutSeconds: refresh ? 45 : 15) { proxy, finish in
            proxy.snapshot(refresh: refresh) { data, error in
                finish(Self.result(data: data, error: error))
            }
        }
        return try JSONDecoder.sky.decode(BridgeDaemonSnapshot.self, from: data)
    }

    public func recover(deviceID: String) async throws -> BridgeHealthSnapshot {
        _ = try BridgeValidation.validateUDID(deviceID)
        let data: Data = try await withProxy(timeoutSeconds: 180) { proxy, finish in
            proxy.recover(deviceID: deviceID) { data, error in
                finish(Self.result(data: data, error: error))
            }
        }
        return try JSONDecoder.sky.decode(BridgeHealthSnapshot.self, from: data)
    }

    public func removeDevice(deviceID: String) async throws -> DeviceRemovalResult {
        _ = try BridgeValidation.validateUDID(deviceID)
        let data: Data = try await withProxy(timeoutSeconds: 90) { proxy, finish in
            proxy.removeDevice(deviceID: deviceID) { data, error in
                finish(Self.result(data: data, error: error))
            }
        }
        return try JSONDecoder.sky.decode(DeviceRemovalResult.self, from: data)
    }

    public func startResearchSession(name: String, deviceID: String) async throws -> ResearchSession {
        _ = try BridgeValidation.validateUDID(deviceID)
        let data: Data = try await withProxy(timeoutSeconds: 60) { proxy, finish in
            proxy.startResearchSession(name: name, deviceID: deviceID) { data, error in
                finish(Self.result(data: data, error: error))
            }
        }
        return try JSONDecoder.sky.decode(ResearchSession.self, from: data)
    }

    public func stopResearchSession() async throws -> URL {
        let data: Data = try await withProxy(timeoutSeconds: 60) { proxy, finish in
            proxy.stopResearchSession { data, error in
                finish(Self.result(data: data, error: error))
            }
        }
        struct Reply: Codable { let path: String }
        return URL(fileURLWithPath: try JSONDecoder.sky.decode(Reply.self, from: data).path)
    }

    public func exportLastResearchSession(profile: EvidenceExportProfile) async throws -> URL {
        try await withProxy(timeoutSeconds: 120) { proxy, finish in
            proxy.exportLastResearchSession(profile: profile.rawValue) { path, error in
                if let path { finish(.success(URL(fileURLWithPath: path))) }
                else { finish(.failure(BridgeCoreError.operationFailed(error ?? "Evidence export failed."))) }
            }
        }
    }

    public func clearLogs() async throws {
        let _: Bool = try await withProxy(timeoutSeconds: 15) { proxy, finish in
            proxy.clearLogs { cleared, error in
                if cleared { finish(.success(true)) }
                else { finish(.failure(BridgeCoreError.operationFailed(error ?? "Log clearing failed."))) }
            }
        }
    }

    private func withProxy<T: Sendable>(
        timeoutSeconds: Double,
        _ body: @escaping (BridgeDaemonProtocol, @escaping @Sendable (Result<T, any Error>) -> Void) -> Void
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            let gate = XPCReplyGate(continuation)
            let connection = self.connection()
            let connectionReference = XPCConnectionReference(connection)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeoutSeconds) {
                if gate.finish(.failure(BridgeCoreError.timeout("bridge service IPC"))) {
                    self.discard(connectionReference.value)
                }
            }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
                if gate.finish(.failure(error)) { self.discard(connection) }
            }) as? BridgeDaemonProtocol else {
                if gate.finish(.failure(BridgeCoreError.operationFailed("Bridge service proxy unavailable."))) {
                    self.discard(connection)
                }
                return
            }
            body(proxy) { gate.finish($0) }
        }
    }

    /// NSXPC code identity validation is intentionally performed once per
    /// client process connection. Retaining the authenticated channel avoids
    /// repeatedly invoking Security.framework for every GUI poll and also
    /// preserves ordering between version/snapshot/session calls.
    private func connection() -> NSXPCConnection {
        connectionLock.lock()
        if let retainedConnection {
            connectionLock.unlock()
            return retainedConnection
        }
        let connection = NSXPCConnection(machServiceName: Self.machServiceName)
        connection.remoteObjectInterface = NSXPCInterface(with: BridgeDaemonProtocol.self)
        connection.interruptionHandler = { [weak self, weak connection] in
            guard let connection else { return }
            self?.discard(connection)
        }
        connection.invalidationHandler = { [weak self, weak connection] in
            guard let connection else { return }
            self?.discard(connection, invalidate: false)
        }
        retainedConnection = connection
        connection.resume()
        connectionLock.unlock()
        return connection
    }

    private func discard(_ candidate: NSXPCConnection, invalidate: Bool = true) {
        connectionLock.lock()
        if retainedConnection === candidate { retainedConnection = nil }
        connectionLock.unlock()
        if invalidate { candidate.invalidate() }
    }

    private static func result(data: Data?, error: String?) -> Result<Data, any Error> {
        if let data { .success(data) }
        else { .failure(BridgeCoreError.operationFailed(error ?? "Bridge service returned no data.")) }
    }
}
