import Foundation

public actor OperationCoordinator {
    private var active: [String: String] = [:]

    public init() {}

    public func withLock<T: Sendable>(
        deviceID: String,
        operation: String,
        body: @Sendable () async throws -> T
    ) async throws -> T {
        _ = try BridgeValidation.validateUDID(deviceID)
        guard active[deviceID] == nil else { throw BridgeCoreError.operationBusy(deviceID) }
        active[deviceID] = operation
        defer { active.removeValue(forKey: deviceID) }
        return try await body()
    }

    public func activeOperation(for deviceID: String) -> String? { active[deviceID] }
}
