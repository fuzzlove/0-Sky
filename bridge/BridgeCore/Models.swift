import Foundation

public enum BridgeState: String, Codable, CaseIterable, Sendable {
    case offline = "OFFLINE"
    case discovering = "DISCOVERING"
    case deviceDetected = "DEVICE DETECTED"
    case waitingForUnlock = "WAITING FOR UNLOCK"
    case waitingForTrust = "WAITING FOR TRUST"
    case pairing = "PAIRING"
    case paired = "PAIRED"
    case enablingWireless = "ENABLING WIRELESS"
    case connecting = "CONNECTING"
    case connected = "CONNECTED"
    case reconnecting = "RECONNECTING"
    case degraded = "DEGRADED"
    case repairing = "REPAIRING"
    case error = "ERROR"
}

public enum HealthState: String, Codable, Sendable {
    case healthy = "HEALTHY"
    case degraded = "DEGRADED"
    case failed = "FAILED"
    case unknown = "UNKNOWN"
}

public enum CheckState: String, Codable, Sendable {
    case pass = "PASS"
    case fail = "FAIL"
    case notApplicable = "NA"
    case notRun = "NOT_RUN"
}

public enum ConnectionKind: String, Codable, Sendable {
    case usb = "USB"
    case wifi = "WI_FI"
    case usbAndWifi = "USB_AND_WIFI"
    case bluetooth = "BLUETOOTH"
    case offline = "OFFLINE"
}

public struct SkyDevice: Identifiable, Codable, Hashable, Sendable {
    public let id: String
    public let udid: String
    public var name: String?
    public var productType: String?
    public var osVersion: String?
    public var buildVersion: String?
    public var usbConnected: Bool
    public var wifiConnected: Bool
    public var paired: Bool
    public var trusted: Bool
    public var linkReachable: Bool
    public var controlInstalled: Bool
    public var controlRunning: Bool
    public var controlReachable: Bool
    public var controlVersion: String?
    public var lastSeen: Date
    public var instanceName: String?
    public var localPort: Int?
    public var bridgeState: BridgeState

    public init(
        udid: String,
        name: String? = nil,
        productType: String? = nil,
        osVersion: String? = nil,
        buildVersion: String? = nil,
        usbConnected: Bool = false,
        wifiConnected: Bool = false,
        paired: Bool = false,
        trusted: Bool = false,
        linkReachable: Bool = false,
        controlInstalled: Bool = false,
        controlRunning: Bool = false,
        controlReachable: Bool = false,
        controlVersion: String? = nil,
        lastSeen: Date = Date(),
        instanceName: String? = nil,
        localPort: Int? = nil,
        bridgeState: BridgeState = .deviceDetected
    ) {
        self.id = udid
        self.udid = udid
        self.name = name
        self.productType = productType
        self.osVersion = osVersion
        self.buildVersion = buildVersion
        self.usbConnected = usbConnected
        self.wifiConnected = wifiConnected
        self.paired = paired
        self.trusted = trusted
        self.linkReachable = linkReachable
        self.controlInstalled = controlInstalled
        self.controlRunning = controlRunning
        self.controlReachable = controlReachable
        self.controlVersion = controlVersion
        self.lastSeen = lastSeen
        self.instanceName = instanceName
        self.localPort = localPort
        self.bridgeState = bridgeState
    }

    public var connection: ConnectionKind {
        if usbConnected && wifiConnected { return .usbAndWifi }
        if usbConnected { return .usb }
        if wifiConnected { return .wifi }
        return .offline
    }
}

public struct DeviceProfile: Codable, Hashable, Sendable {
    public var udid: String
    public var name: String?
    public var productType: String?
    public var osVersion: String?
    public var buildVersion: String?
    public var instanceName: String
    public var localPort: Int
    public var pairingVerified: Bool
    public var wirelessEnabled: Bool
    public var lastSeen: Date
    public var sshHost: String
    public var sshHostAlias: String
    public var sshKeyPath: String
    public var knownHostsPath: String
    public var macIdentityFingerprint: String?

    public init(
        udid: String, name: String? = nil, productType: String? = nil,
        osVersion: String? = nil, buildVersion: String? = nil,
        instanceName: String, localPort: Int, pairingVerified: Bool = false,
        wirelessEnabled: Bool = false, lastSeen: Date = Date(),
        sshHost: String = "127.0.0.1", sshHostAlias: String,
        sshKeyPath: String, knownHostsPath: String,
        macIdentityFingerprint: String? = nil
    ) {
        self.udid = udid
        self.name = name
        self.productType = productType
        self.osVersion = osVersion
        self.buildVersion = buildVersion
        self.instanceName = instanceName
        self.localPort = localPort
        self.pairingVerified = pairingVerified
        self.wirelessEnabled = wirelessEnabled
        self.lastSeen = lastSeen
        self.sshHost = sshHost
        self.sshHostAlias = sshHostAlias
        self.sshKeyPath = sshKeyPath
        self.knownHostsPath = knownHostsPath
        self.macIdentityFingerprint = macIdentityFingerprint
    }
}

public enum LogCategory: String, Codable, CaseIterable, Sendable {
    case device, pairing, wireless, usb, ssh, coredevice, remotexpc
    case service, script, health, repair, security
}

public enum LogLevel: String, Codable, CaseIterable, Sendable {
    case info = "INFO"
    case pass = "PASS"
    case warning = "WARN"
    case error = "ERROR"
    case debug = "DEBUG"
}

public struct BridgeLogEntry: Identifiable, Codable, Hashable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let category: LogCategory
    public let level: LogLevel
    public let message: String
    public let deviceID: String?

    public init(
        id: UUID = UUID(), timestamp: Date = Date(), category: LogCategory,
        level: LogLevel, message: String, deviceID: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.category = category
        self.level = level
        self.message = message
        self.deviceID = deviceID
    }
}

public struct BridgeOperationResult: Codable, Sendable {
    public let identifier: String
    public let startedAt: Date
    public let finishedAt: Date
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
    public let timedOut: Bool
    public let cancelled: Bool

    public init(
        identifier: String, startedAt: Date, finishedAt: Date,
        exitCode: Int32, stdout: String, stderr: String,
        timedOut: Bool = false, cancelled: Bool = false
    ) {
        self.identifier = identifier
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
        self.timedOut = timedOut
        self.cancelled = cancelled
    }

    public var succeeded: Bool { exitCode == 0 && !timedOut && !cancelled }
    public var duration: TimeInterval { finishedAt.timeIntervalSince(startedAt) }
}

public struct DependencyStatus: Identifiable, Codable, Hashable, Sendable {
    public var id: String { name }
    public let name: String
    public let path: String?
    public let required: Bool
    public let available: Bool
    public let detail: String
}

public struct ServiceStatus: Identifiable, Codable, Hashable, Sendable {
    public var id: String { label }
    public let label: String
    public let state: String
    public let processIdentifier: Int?
    public let lastExitCode: Int?
    public let installed: Bool
}

/// Independently measured device-side application/service state.  Keeping
/// these fields separate prevents an installed icon from being reported as a
/// live bridge connection.
public struct DeviceIntegrationStatus: Codable, Hashable, Sendable {
    public let linkReachable: Bool
    public let controlInstalled: Bool
    public let controlRunning: Bool
    public let controlReachable: Bool
    public let controlVersion: String?

    public init(
        linkReachable: Bool = false,
        controlInstalled: Bool = false,
        controlRunning: Bool = false,
        controlReachable: Bool = false,
        controlVersion: String? = nil
    ) {
        self.linkReachable = linkReachable
        self.controlInstalled = controlInstalled
        self.controlRunning = controlRunning
        self.controlReachable = controlReachable
        self.controlVersion = controlVersion
    }
}

public struct HealthCheck: Identifiable, Codable, Hashable, Sendable {
    public var id: String { transition }
    public let transition: String
    public let state: CheckState
    public let detail: String
    public let checkedAt: Date
    public let mandatory: Bool

    public init(
        transition: String, state: CheckState, detail: String,
        checkedAt: Date = Date(), mandatory: Bool
    ) {
        self.transition = transition
        self.state = state
        self.detail = detail
        self.checkedAt = checkedAt
        self.mandatory = mandatory
    }
}

public struct BridgeHealthSnapshot: Codable, Sendable {
    public let deviceID: String
    public let state: HealthState
    public let checks: [HealthCheck]
    public let firstFailingTransition: String?
    public let rootCause: String?
    public let recommendedAction: String?
    public let dependentFailures: [String]
    public let readiness: ResearchReadiness
    public let checkedAt: Date

    public init(deviceID: String, checks: [HealthCheck]) {
        self.deviceID = deviceID
        self.checks = checks
        self.checkedAt = Date()
        let results = checks.map(HealthResult.init(legacy:))
        let analysis = FirstFailureAnalyzer().analyze(results)
        let failed = analysis.firstFailingTransition.flatMap { canonical in
            checks.first { $0.mandatory && $0.state == .fail && HealthResult.canonical($0.transition) == canonical }
        } ?? checks.first { $0.mandatory && $0.state == .fail }
        let unknownMandatory = checks.contains { $0.mandatory && $0.state == .notRun }
        self.firstFailingTransition = failed?.transition
        self.rootCause = analysis.primaryRootCause ?? failed?.detail
        self.recommendedAction = failed.map { "Repair \($0.transition) and verify again." }
        self.dependentFailures = analysis.dependentFailures
        if failed != nil {
            self.state = .failed
            self.readiness = .blocked
        } else if unknownMandatory {
            self.state = .unknown
            self.readiness = .unknown
        } else if checks.contains(where: { $0.state == .fail }) {
            self.state = .degraded
            self.readiness = .degraded
        } else if checks.allSatisfy({ $0.state == .pass || $0.state == .notApplicable }) {
            self.state = .healthy
            self.readiness = .healthy
        } else {
            self.state = .unknown
            self.readiness = .unknown
        }
    }

    public var results: [HealthResult] { checks.map(HealthResult.init(legacy:)) }
}

public struct HostSummary: Codable, Sendable {
    public let computerName: String
    public let osVersion: String
    public let architecture: String
    public let bridgeVersion: String
    public let helperState: String

    public init(
        computerName: String,
        osVersion: String,
        architecture: String,
        bridgeVersion: String,
        helperState: String
    ) {
        self.computerName = computerName
        self.osVersion = osVersion
        self.architecture = architecture
        self.bridgeVersion = bridgeVersion
        self.helperState = helperState
    }
}

public enum BridgeCoreError: LocalizedError, Sendable {
    case invalidUDID(String)
    case invalidPath(String)
    case unsafeExecutable(String)
    case dependencyMissing(String)
    case operationBusy(String)
    case operationFailed(String)
    case timeout(String)
    case cancelled(String)
    case invalidTransition(BridgeState, BridgeState)
    case malformedOutput(String)
    case unauthorized(String)

    public var errorDescription: String? {
        switch self {
        case .invalidUDID(let value): return "Invalid device identifier: \(value)"
        case .invalidPath(let value): return "Invalid or unapproved path: \(value)"
        case .unsafeExecutable(let value): return "Executable ownership or permissions are unsafe: \(value)"
        case .dependencyMissing(let value): return "Required dependency is missing: \(value)"
        case .operationBusy(let value): return "Another operation is active for device \(value)"
        case .operationFailed(let value): return value
        case .timeout(let value): return "Operation timed out: \(value)"
        case .cancelled(let value): return "Operation cancelled: \(value)"
        case .invalidTransition(let from, let to): return "Invalid bridge transition \(from.rawValue) → \(to.rawValue)"
        case .malformedOutput(let value): return "Tool returned malformed output: \(value)"
        case .unauthorized(let value): return "Unauthorized operation: \(value)"
        }
    }
}
