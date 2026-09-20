import Foundation

// MARK: - Normalized event architecture

public enum BridgeEventName: String, Codable, CaseIterable, Sendable {
    case deviceDiscovered = "DEVICE_DISCOVERED"
    case deviceConnected = "DEVICE_CONNECTED"
    case deviceDisconnected = "DEVICE_DISCONNECTED"
    case pairingRequired = "PAIRING_REQUIRED"
    case pairingVerified = "PAIRING_VERIFIED"
    case pairingFailed = "PAIRING_FAILED"
    case trustVerified = "TRUST_VERIFIED"
    case trustFailed = "TRUST_FAILED"
    case usbReady = "USB_READY"
    case usbLost = "USB_LOST"
    case remoteXPCConnecting = "REMOTEXPC_CONNECTING"
    case remoteXPCReady = "REMOTEXPC_READY"
    case remoteXPCFailed = "REMOTEXPC_FAILED"
    case wifiPairingReady = "WIFI_PAIRING_READY"
    case wifiReady = "WIFI_READY"
    case wifiLost = "WIFI_LOST"
    case sshConnecting = "SSH_CONNECTING"
    case sshReady = "SSH_READY"
    case sshFailed = "SSH_FAILED"
    case defaultCredentialsDetected = "DEFAULT_CREDENTIALS_DETECTED"
    case vncDefaultCredentialsDetected = "VNC_DEFAULT_CREDENTIALS_DETECTED"
    case credentialsVerified = "CREDENTIALS_VERIFIED"
    case ddiCheckStarted = "DDI_CHECK_STARTED"
    case ddiReady = "DDI_READY"
    case ddiFailed = "DDI_FAILED"
    case developerServicesReady = "DEVELOPER_SERVICES_READY"
    case developerServicesFailed = "DEVELOPER_SERVICES_FAILED"
    case cryptexReady = "CRYTEX_READY"
    case cryptexFailed = "CRYTEX_FAILED"
    case bootstrapReady = "BOOTSTRAP_READY"
    case bootstrapDegraded = "BOOTSTRAP_DEGRADED"
    case bootstrapFailed = "BOOTSTRAP_FAILED"
    case fridaReady = "FRIDA_READY"
    case fridaVersionMismatch = "FRIDA_VERSION_MISMATCH"
    case fridaFailed = "FRIDA_FAILED"
    case serviceStarted = "SERVICE_STARTED"
    case serviceStopped = "SERVICE_STOPPED"
    case serviceFailed = "SERVICE_FAILED"
    case iosComponentSetupStarted = "IOS_COMPONENT_SETUP_STARTED"
    case iosComponentSetupSucceeded = "IOS_COMPONENT_SETUP_SUCCEEDED"
    case iosComponentSetupFailed = "IOS_COMPONENT_SETUP_FAILED"
    case recoveryStarted = "RECOVERY_STARTED"
    case recoverySucceeded = "RECOVERY_SUCCEEDED"
    case recoveryFailed = "RECOVERY_FAILED"
    case researchSessionStarted = "RESEARCH_SESSION_STARTED"
    case researchSessionStopped = "RESEARCH_SESSION_STOPPED"
    case crashDetected = "CRASH_DETECTED"
    case artifactCaptured = "ARTIFACT_CAPTURED"
    case healthCheckCompleted = "HEALTH_CHECK_COMPLETED"
    case stateChanged = "STATE_CHANGED"
    case commandCompleted = "COMMAND_COMPLETED"
}

public enum EventSeverity: String, Codable, CaseIterable, Sendable {
    case debug, info, warning, error, critical
}

/// A deliberately small JSON value type keeps event metadata structured and
/// Codable without allowing arbitrary, non-Sendable values onto the bus.
public enum JSONValue: Codable, Hashable, Sendable {
    case string(String), number(Double), bool(Bool), object([String: JSONValue]), array([JSONValue]), null

    public init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        if value.decodeNil() { self = .null }
        else if let item = try? value.decode(Bool.self) { self = .bool(item) }
        else if let item = try? value.decode(Double.self) { self = .number(item) }
        else if let item = try? value.decode(String.self) { self = .string(item) }
        else if let item = try? value.decode([String: JSONValue].self) { self = .object(item) }
        else { self = .array(try value.decode([JSONValue].self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var value = encoder.singleValueContainer()
        switch self {
        case .string(let item): try value.encode(item)
        case .number(let item): try value.encode(item)
        case .bool(let item): try value.encode(item)
        case .object(let item): try value.encode(item)
        case .array(let item): try value.encode(item)
        case .null: try value.encodeNil()
        }
    }
}

public struct BridgeEvent: Identifiable, Codable, Hashable, Sendable {
    public let id: UUID
    public let event: BridgeEventName
    public let timestamp: Date
    public let deviceID: String?
    public let sessionID: UUID?
    public let severity: EventSeverity
    public let component: String
    public let message: String
    public let observed: [String: JSONValue]
    public let expected: [String: JSONValue]
    public let evidence: [String: JSONValue]
    public let correlationID: UUID

    public init(
        id: UUID = UUID(), event: BridgeEventName, timestamp: Date = Date(),
        deviceID: String? = nil, sessionID: UUID? = nil,
        severity: EventSeverity = .info, component: String, message: String,
        observed: [String: JSONValue] = [:], expected: [String: JSONValue] = [:],
        evidence: [String: JSONValue] = [:], correlationID: UUID = UUID()
    ) {
        self.id = id
        self.event = event
        self.timestamp = timestamp
        self.deviceID = deviceID
        self.sessionID = sessionID
        self.severity = severity
        self.component = component
        self.message = DiagnosticRedactor.redact(message)
        self.observed = observed
        self.expected = expected
        self.evidence = evidence
        self.correlationID = correlationID
    }
}

public actor EventBus {
    public typealias Handler = @Sendable (BridgeEvent) async -> Void
    private var handlers: [UUID: Handler] = [:]
    private var history: [BridgeEvent] = []
    private let historyLimit: Int

    public init(historyLimit: Int = 10_000) { self.historyLimit = max(1, historyLimit) }

    @discardableResult
    public func subscribe(_ handler: @escaping Handler) -> UUID {
        let token = UUID()
        handlers[token] = handler
        return token
    }

    public func unsubscribe(_ token: UUID) { handlers.removeValue(forKey: token) }

    public func publish(_ event: BridgeEvent) async {
        history.append(event)
        if history.count > historyLimit { history.removeFirst(history.count - historyLimit) }
        for handler in handlers.values { await handler(event) }
    }

    public func events(deviceID: String? = nil, sessionID: UUID? = nil) -> [BridgeEvent] {
        history.filter { event in
            (deviceID == nil || event.deviceID == deviceID)
                && (sessionID == nil || event.sessionID == sessionID)
        }
    }
}

// MARK: - Explicit lifecycle and independent component state

public enum DeviceLifecycleState: String, Codable, CaseIterable, Sendable {
    case disconnected = "DISCONNECTED", discovered = "DISCOVERED"
    case usbConnected = "USB_CONNECTED", pairingRequired = "PAIRING_REQUIRED"
    case paired = "PAIRED", trusted = "TRUSTED"
    case remoteXPCReady = "REMOTEXPC_READY", wifiReady = "WIFI_READY"
    case sshReady = "SSH_READY", developerServicesReady = "DEVELOPER_SERVICES_READY"
    case researchReady = "RESEARCH_READY", degraded = "DEGRADED"
    case recovering = "RECOVERING", failed = "FAILED"
}

public enum ComponentCondition: String, Codable, CaseIterable, Sendable {
    case ready = "READY", degraded = "DEGRADED", failed = "FAILED"
    case unavailable = "UNAVAILABLE", unknown = "UNKNOWN"
}

public struct DeviceComponentState: Codable, Hashable, Sendable {
    public var values: [String: ComponentCondition]
    public init(values: [String: ComponentCondition] = [:]) { self.values = values }
    public subscript(component: String) -> ComponentCondition {
        get { values[component] ?? .unknown }
        set { values[component] = newValue }
    }
}

public actor DeviceStateStore {
    private var lifecycles: [String: DeviceLifecycleState] = [:]
    private var components: [String: DeviceComponentState] = [:]
    private let events: EventBus

    public init(events: EventBus) { self.events = events }

    public func lifecycle(for deviceID: String) -> DeviceLifecycleState {
        lifecycles[deviceID] ?? .disconnected
    }

    public func componentState(for deviceID: String) -> DeviceComponentState {
        components[deviceID] ?? DeviceComponentState()
    }

    public func setComponent(_ component: String, condition: ComponentCondition, deviceID: String) {
        var state = components[deviceID] ?? DeviceComponentState()
        state[component] = condition
        components[deviceID] = state
    }

    @discardableResult
    public func transition(deviceID: String, to next: DeviceLifecycleState,
                           correlationID: UUID = UUID()) async throws -> DeviceLifecycleState {
        let current = lifecycle(for: deviceID)
        guard current == next || Self.allowed[current, default: []].contains(next) else {
            throw BridgeCoreError.operationFailed("Invalid SRD transition \(current.rawValue) → \(next.rawValue)")
        }
        lifecycles[deviceID] = next
        await events.publish(BridgeEvent(
            event: .stateChanged, deviceID: deviceID,
            severity: next == .failed ? .error : .info, component: "state_machine",
            message: "Device lifecycle changed.",
            observed: ["from": .string(current.rawValue), "to": .string(next.rawValue)],
            correlationID: correlationID
        ))
        return next
    }

    public static let allowed: [DeviceLifecycleState: Set<DeviceLifecycleState>] = [
        .disconnected: [.discovered],
        .discovered: [.usbConnected, .pairingRequired, .paired, .disconnected, .failed],
        .usbConnected: [.pairingRequired, .paired, .disconnected, .degraded, .failed],
        .pairingRequired: [.paired, .disconnected, .failed],
        .paired: [.trusted, .pairingRequired, .disconnected, .degraded, .failed],
        .trusted: [.remoteXPCReady, .wifiReady, .sshReady, .disconnected, .degraded, .failed],
        .remoteXPCReady: [.wifiReady, .sshReady, .developerServicesReady, .degraded, .disconnected, .failed],
        .wifiReady: [.sshReady, .remoteXPCReady, .degraded, .disconnected, .failed],
        .sshReady: [.developerServicesReady, .researchReady, .degraded, .recovering, .disconnected, .failed],
        .developerServicesReady: [.researchReady, .degraded, .recovering, .disconnected, .failed],
        .researchReady: [.degraded, .recovering, .disconnected, .failed],
        .degraded: [.recovering, .researchReady, .sshReady, .disconnected, .failed],
        .recovering: [.researchReady, .sshReady, .degraded, .disconnected, .failed],
        .failed: [.recovering, .discovered, .disconnected],
    ]
}
