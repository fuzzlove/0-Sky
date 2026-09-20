import Foundation

public actor BridgeStateMachine {
    private var states: [String: BridgeState] = [:]

    public init() {}

    public func state(for deviceID: String) -> BridgeState {
        states[deviceID] ?? .offline
    }

    @discardableResult
    public func transition(deviceID: String, to next: BridgeState) throws -> BridgeState {
        let current = state(for: deviceID)
        guard Self.allowed[current, default: []].contains(next) || current == next else {
            throw BridgeCoreError.invalidTransition(current, next)
        }
        states[deviceID] = next
        return next
    }

    public func restore(deviceID: String, state: BridgeState) {
        states[deviceID] = state
    }

    public func remove(deviceID: String) {
        states.removeValue(forKey: deviceID)
    }

    public static let allowed: [BridgeState: Set<BridgeState>] = [
        .offline: [.discovering, .deviceDetected, .reconnecting],
        .discovering: [.offline, .deviceDetected, .error],
        .deviceDetected: [.waitingForUnlock, .waitingForTrust, .pairing, .paired, .connecting, .offline, .error],
        .waitingForUnlock: [.deviceDetected, .waitingForTrust, .pairing, .offline, .error],
        .waitingForTrust: [.pairing, .paired, .offline, .error],
        .pairing: [.paired, .waitingForUnlock, .waitingForTrust, .error, .offline],
        .paired: [.enablingWireless, .connecting, .connected, .reconnecting, .repairing, .offline, .error],
        .enablingWireless: [.connecting, .paired, .degraded, .error, .offline],
        .connecting: [.connected, .reconnecting, .degraded, .offline, .error],
        .connected: [.reconnecting, .degraded, .repairing, .offline, .error],
        .reconnecting: [.connected, .degraded, .repairing, .offline, .error],
        .degraded: [.reconnecting, .repairing, .connected, .offline, .error],
        .repairing: [.connected, .degraded, .paired, .offline, .error],
        .error: [.discovering, .reconnecting, .repairing, .offline],
    ]
}
