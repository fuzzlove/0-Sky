import Foundation

/// Central coordinator for typed health adapters. Results, state, evidence, and
/// GUI clients all consume the same report rather than parsing command output.
public actor SRDHealthEngine {
    private let events: EventBus
    private let states: DeviceStateStore
    private let sessions: ResearchSessionRecorder
    private let graph: DependencyGraph

    public init(events: EventBus, states: DeviceStateStore,
                sessions: ResearchSessionRecorder,
                graph: DependencyGraph = DependencyGraph()) {
        self.events = events; self.states = states; self.sessions = sessions; self.graph = graph
    }

    public func check(deviceID: String, adapters: [any HealthCheckingAdapter]) async -> SRDHealthReport {
        var results: [HealthResult] = []
        for adapter in adapters {
            let result = await adapter.checkHealth()
            results.append(result)
            await states.setComponent(result.name.lowercased(), condition: Self.condition(result.status), deviceID: deviceID)
            await events.publish(BridgeEvent(
                event: Self.event(for: result), deviceID: deviceID,
                severity: Self.severity(result.status), component: result.name.lowercased(),
                message: result.rootCause ?? "\(result.displayName) health check completed.",
                observed: result.observed,
                expected: ["condition": .string(result.expected)]
            ))
        }
        let report = SRDHealthReport(deviceID: deviceID, results: results, graph: graph)
        try? await sessions.recordHealth(report)
        return report
    }

    private static func condition(_ status: HealthStatus) -> ComponentCondition {
        switch status {
        case .pass, .info: .ready
        case .warning, .degraded: .degraded
        case .fail: .failed
        case .unknown: .unknown
        }
    }

    private static func severity(_ status: HealthStatus) -> EventSeverity {
        switch status {
        case .pass, .info: .info
        case .warning, .degraded, .unknown: .warning
        case .fail: .error
        }
    }

    private static func event(for result: HealthResult) -> BridgeEventName {
        switch (result.name, result.status) {
        case ("USB", .pass): .usbReady
        case ("REMOTEXPC", .pass): .remoteXPCReady
        case ("REMOTEXPC", _): .remoteXPCFailed
        case ("SSH", .pass): .sshReady
        case ("SSH", _): .sshFailed
        case ("DEFAULT_CREDENTIALS", .pass): .credentialsVerified
        case ("DEFAULT_CREDENTIALS", .fail): .defaultCredentialsDetected
        case ("VNC_DEFAULT_CREDENTIALS", .pass): .credentialsVerified
        case ("VNC_DEFAULT_CREDENTIALS", .fail): .vncDefaultCredentialsDetected
        case ("DDI", .pass): .ddiReady
        case ("DDI", _): .ddiFailed
        case ("DEVELOPER_SERVICES", .pass): .developerServicesReady
        case ("DEVELOPER_SERVICES", _): .developerServicesFailed
        case ("CRYTEX", .pass): .cryptexReady
        case ("CRYTEX", _): .cryptexFailed
        case ("BOOTSTRAP", .pass): .bootstrapReady
        case ("BOOTSTRAP", .degraded), ("BOOTSTRAP", .warning): .bootstrapDegraded
        case ("BOOTSTRAP", _): .bootstrapFailed
        case ("FRIDA_VERSION", .pass): .fridaReady
        case ("FRIDA_VERSION", .fail): .fridaVersionMismatch
        case ("FRIDA_VERSION", _): .fridaFailed
        default: .healthCheckCompleted
        }
    }
}
