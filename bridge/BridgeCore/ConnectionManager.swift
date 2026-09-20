import Foundation

public actor ConnectionManager {
    public static let backoffSeconds: [UInt64] = [1, 2, 5, 10, 30, 60]

    private let stateMachine: BridgeStateMachine
    private let services: ServiceManager
    private let ssh: SSHManager
    private let discovery: DeviceDiscoveryManager
    private let wireless: WirelessPairingManager
    private var reconnectTasks: [String: Task<Bool, Never>] = [:]

    public init(
        stateMachine: BridgeStateMachine,
        services: ServiceManager,
        ssh: SSHManager,
        discovery: DeviceDiscoveryManager,
        wireless: WirelessPairingManager
    ) {
        self.stateMachine = stateMachine
        self.services = services
        self.ssh = ssh
        self.discovery = discovery
        self.wireless = wireless
    }

    public func reconnect(profile: DeviceProfile) async -> Bool {
        if let existing = reconnectTasks[profile.udid] { return await existing.value }
        let task = Task { [stateMachine, services, ssh, discovery, wireless] in
            _ = try? await stateMachine.transition(deviceID: profile.udid, to: .reconnecting)
            for (attempt, delay) in Self.backoffSeconds.enumerated() {
                if Task.isCancelled { return false }
                // 1. Existing transport / SSH tunnel.
                let direct = await ssh.probe(profile)
                if direct.succeeded {
                    _ = try? await stateMachine.transition(deviceID: profile.udid, to: .connected)
                    return true
                }

                // 2. Reassert the already-enrolled wireless relationship.
                if attempt == 0, profile.wirelessEnabled,
                   let fingerprint = profile.macIdentityFingerprint {
                    _ = try? await wireless.run(
                        profile: profile,
                        operation: .connect,
                        hostFingerprint: fingerprint,
                        usbTrustVerified: profile.pairingVerified
                    )
                // 3. Rediscover the exact UDID over USB or Wi-Fi.
                } else if attempt == 1 {
                    let found = await discovery.discover()
                    if !found.contains(where: {
                        $0.udid == profile.udid && ($0.usbConnected || $0.wifiConnected)
                    }) {
                        try? await Task.sleep(for: .seconds(delay))
                        continue
                    }
                // 4. Repair the exact-device local forward.
                } else if attempt == 2 {
                    _ = try? await services.restart(kind: .usbmux, profile: profile)
                // 5. Restart only the project bridge component.
                } else if attempt == 3 {
                    _ = try? await services.restart(kind: .deviceBridge, profile: profile)
                // 6. Restore the request worker/SSH-dependent bridge.
                } else if attempt == 4 {
                    _ = try? await services.restart(kind: .worker, profile: profile)
                // 7. Final project-specific authenticated fallback.
                } else if attempt == 5 {
                    _ = try? await services.restart(kind: .bluetooth, profile: profile)
                }
                try? await Task.sleep(for: .seconds(delay))
            }
            _ = try? await stateMachine.transition(deviceID: profile.udid, to: .degraded)
            return false
        }
        reconnectTasks[profile.udid] = task
        let value = await task.value
        reconnectTasks.removeValue(forKey: profile.udid)
        return value
    }

    public func cancel(deviceID: String) {
        reconnectTasks.removeValue(forKey: deviceID)?.cancel()
    }
}
