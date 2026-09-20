import Foundation
import ServiceManagement

public final class PrivilegedHelperClient: @unchecked Sendable {
    public static let machServiceName = "com.liquidsky.0sky.bridge.helper"
    private let connection: NSXPCConnection

    public init() {
        connection = NSXPCConnection(machServiceName: Self.machServiceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: BridgePrivilegedHelperProtocol.self)
        connection.resume()
    }

    deinit { connection.invalidate() }

    public func version() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
                continuation.resume(throwing: error)
            }) as? BridgePrivilegedHelperProtocol else {
                continuation.resume(throwing: BridgeCoreError.operationFailed("Privileged helper proxy unavailable"))
                return
            }
            proxy.helperVersion { continuation.resume(returning: $0) }
        }
    }

    public static func registrationStatus() -> String {
        if #available(macOS 13.0, *) {
            switch SMAppService.daemon(plistName: "com.liquidsky.0sky.bridge.helper.plist").status {
            case .enabled: return "Enabled"
            case .requiresApproval: return "Approval Required"
            case .notRegistered: return "Not Registered"
            case .notFound: return "Not Found"
            @unknown default: return "Unknown"
            }
        }
        return "Unsupported"
    }
}
