import Foundation

public actor RecoveryManager {
    private let health: HealthMonitor
    private let services: ServiceManager
    private let pairing: PairingManager
    private let wireless: WirelessPairingManager
    private let connection: ConnectionManager
    private let events: EventBus?

    public init(
        health: HealthMonitor,
        services: ServiceManager,
        pairing: PairingManager,
        wireless: WirelessPairingManager,
        connection: ConnectionManager,
        events: EventBus? = nil
    ) {
        self.health = health
        self.services = services
        self.pairing = pairing
        self.wireless = wireless
        self.connection = connection
        self.events = events
    }

    public func fix(device: SkyDevice, profile: DeviceProfile) async -> BridgeHealthSnapshot {
        let before = await health.check(device: device, profile: profile)
        guard let failure = before.firstFailingTransition else { return before }
        let correlation = UUID()
        await events?.publish(BridgeEvent(
            event: .recoveryStarted, deviceID: device.udid, component: failure.lowercased(),
            message: "Tier 1 recovery started for first failing transition.",
            correlationID: correlation
        ))
        switch failure {
        case "DEVICE_DISCOVERY":
            _ = await connection.reconnect(profile: profile)
        case "WIRELESS_PAIRING":
            if device.usbConnected, let fingerprint = profile.macIdentityFingerprint {
                _ = try? await wireless.run(
                    profile: profile, operation: .enable,
                    hostFingerprint: fingerprint,
                    usbTrustVerified: profile.pairingVerified
                )
            }
        case "PORT_FORWARD":
            _ = try? await services.restart(kind: .usbmux, profile: profile)
        case "BRIDGE_SERVICES":
            for kind in ServiceManager.Kind.allCases {
                let status = await services.status(kind: kind, profile: profile)
                if !status.installed { _ = try? await services.start(kind: kind, profile: profile) }
                else if status.state != "running" { _ = try? await services.restart(kind: kind, profile: profile) }
            }
        case "SSH", "0SKY_LINK", "0SKY_CONTROL":
            _ = await connection.reconnect(profile: profile)
        case "PAIR_RECORD", "TRUST":
            _ = try? await pairing.run(profile: profile, mode: .verify, requireWorker: false)
        default:
            break
        }
        let after = await health.check(device: device, profile: profile)
        await events?.publish(BridgeEvent(
            event: after.firstFailingTransition == failure ? .recoveryFailed : .recoverySucceeded,
            deviceID: device.udid,
            severity: after.firstFailingTransition == failure ? .warning : .info,
            component: failure.lowercased(),
            message: after.firstFailingTransition == failure
                ? "Recovery did not clear the first failing transition."
                : "Recovery cleared the first failing transition.",
            correlationID: correlation
        ))
        return after
    }
}
