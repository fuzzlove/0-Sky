import Foundation

/// Explicit model for the exact-UDID local SSH forward.  Service lifecycle
/// and socket reachability are intentionally separate measurements.
public actor PortForwardManager {
    private let services: ServiceManager

    public init(services: ServiceManager) { self.services = services }

    public func status(profile: DeviceProfile) async -> (service: ServiceStatus, reachable: Bool) {
        async let service = services.status(kind: .usbmux, profile: profile)
        async let reachable = TCPProbe.open(port: profile.localPort, timeout: 2)
        return await (service, reachable)
    }

    public func restart(profile: DeviceProfile) async throws -> BridgeOperationResult {
        try await services.restart(kind: .usbmux, profile: profile)
    }
}
