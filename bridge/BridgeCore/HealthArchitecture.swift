import Foundation

public enum HealthStatus: String, Codable, CaseIterable, Sendable {
    case pass = "PASS", info = "INFO", warning = "WARNING"
    case degraded = "DEGRADED", fail = "FAIL", unknown = "UNKNOWN"

    public var isFailure: Bool { self == .fail || self == .degraded }
}

public enum HealthSeverity: String, Codable, CaseIterable, Comparable, Sendable {
    case low = "LOW", medium = "MEDIUM", high = "HIGH", critical = "CRITICAL"
    private var order: Int { Self.allCases.firstIndex(of: self) ?? 0 }
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.order < rhs.order }
}

public enum AdapterFailureKind: String, Codable, Sendable {
    case toolMissing = "TOOL_MISSING", toolFailure = "TOOL_FAILURE"
    case timeout = "TIMEOUT", connectionLost = "CONNECTION_LOST"
    case permissionDenied = "PERMISSION_DENIED", unsupported = "UNSUPPORTED"
    case malformedResponse = "MALFORMED_RESPONSE", unexpected = "UNEXPECTED"
}

public struct HealthResult: Identifiable, Codable, Hashable, Sendable {
    public var id: String { name }
    public let name: String
    public let status: HealthStatus
    public let severity: HealthSeverity
    public let observed: [String: JSONValue]
    public let expected: String
    public let rootCause: String?
    public let remediation: [String]
    public let rawEvidence: [String]
    public let durationMS: Int
    public let failureKind: AdapterFailureKind?
    public let checkedAt: Date

    /// A human-facing label for the canonical component identifier. Canonical
    /// identifiers stay stable for events, dependency analysis, and exports.
    public var displayName: String { Self.displayName(for: name) }

    public static func displayName(for identifier: String) -> String {
        switch identifier.uppercased() {
        case "CRYTEX", "CRYPTEX": "Cryptex"
        case "DEFAULT_CREDENTIALS": "Default Credentials"
        case "VNC_DEFAULT_CREDENTIALS": "VNC Default Credentials"
        default: identifier
        }
    }

    public init(
        name: String, status: HealthStatus, severity: HealthSeverity = .medium,
        observed: [String: JSONValue] = [:], expected: String,
        rootCause: String? = nil, remediation: [String] = [], rawEvidence: [String] = [],
        durationMS: Int = 0, failureKind: AdapterFailureKind? = nil, checkedAt: Date = Date()
    ) {
        self.name = name
        self.status = status
        self.severity = severity
        self.observed = observed
        self.expected = expected
        self.rootCause = rootCause.map(DiagnosticRedactor.redact)
        self.remediation = remediation.map(DiagnosticRedactor.redact)
        self.rawEvidence = rawEvidence.map(DiagnosticRedactor.redact)
        self.durationMS = max(0, durationMS)
        self.failureKind = failureKind
        self.checkedAt = checkedAt
    }
}

public struct DependencyGraph: Codable, Hashable, Sendable {
    /// node -> direct prerequisites
    public let prerequisites: [String: Set<String>]

    public init(prerequisites: [String: Set<String>] = DependencyGraph.defaultPrerequisites) {
        self.prerequisites = prerequisites
    }

    public static let defaultPrerequisites: [String: Set<String>] = [
        "USB": ["DEVICE"], "PAIRING": ["USB"], "TRUST": ["PAIRING"],
        "REMOTEXPC": ["TRUST"], "DEVELOPER_SERVICES": ["REMOTEXPC"],
        "DDI": ["DEVELOPER_SERVICES"], "DEBUGSERVER": ["DDI"], "LLDB": ["DDI"],
        "FRIDA_ATTACH": ["DDI"], "WIFI_PAIRING": ["TRUST"],
        "WIFI_TRANSPORT": ["WIFI_PAIRING"], "PORT_FORWARD": ["USB"],
        "SSH": ["TRUST", "PORT_FORWARD"], "CRYTEX": ["TRUST"],
        "DEFAULT_CREDENTIALS": ["SSH"],
        "VNC_DEFAULT_CREDENTIALS": ["SSH"],
        "BOOTSTRAP": ["CRYTEX"], "FRIDA_DEVICE": ["BOOTSTRAP"],
        "FRIDA_VERSION": ["FRIDA_HOST", "FRIDA_DEVICE"],
        "DEVICE_STORAGE": ["SSH"],
    ]

    public func validate() throws {
        var visiting = Set<String>()
        var visited = Set<String>()
        func visit(_ node: String) throws {
            if visiting.contains(node) { throw BridgeCoreError.malformedOutput("dependency graph cycle at \(node)") }
            guard !visited.contains(node) else { return }
            visiting.insert(node)
            for parent in prerequisites[node, default: []] { try visit(parent) }
            visiting.remove(node)
            visited.insert(node)
        }
        for node in prerequisites.keys { try visit(node) }
    }

    public func ancestors(of node: String) -> Set<String> {
        var result = Set<String>()
        func collect(_ current: String) {
            for parent in prerequisites[current, default: []] where result.insert(parent).inserted {
                collect(parent)
            }
        }
        collect(node)
        return result
    }

    public func depth(of node: String) -> Int {
        let parents = prerequisites[node, default: []]
        return parents.isEmpty ? 0 : 1 + (parents.map(depth).max() ?? 0)
    }
}

public struct FirstFailureAnalysis: Codable, Hashable, Sendable {
    public let firstFailingTransition: String?
    public let primaryRootCause: String?
    public let dependentFailures: [String]
    public let blockedBy: [String]
}

public struct FirstFailureAnalyzer: Sendable {
    public let graph: DependencyGraph
    public init(graph: DependencyGraph = DependencyGraph()) { self.graph = graph }

    public func analyze(_ results: [HealthResult]) -> FirstFailureAnalysis {
        let failures = results.filter { $0.status.isFailure }
        guard !failures.isEmpty else {
            return FirstFailureAnalysis(firstFailingTransition: nil, primaryRootCause: nil,
                                        dependentFailures: [], blockedBy: [])
        }
        let failedNames = Set(failures.map(\.name))
        // A root failure has no failed ancestor. Depth then gives stable ordering when
        // independent roots exist; severity breaks ties without treating children as roots.
        let roots = failures.filter { graph.ancestors(of: $0.name).isDisjoint(with: failedNames) }
        let first = (roots.isEmpty ? failures : roots).sorted {
            let leftDepth = graph.depth(of: $0.name), rightDepth = graph.depth(of: $1.name)
            if leftDepth != rightDepth { return leftDepth < rightDepth }
            if $0.severity != $1.severity { return $0.severity > $1.severity }
            return $0.name < $1.name
        }.first!
        let dependent = failures.filter { $0.name != first.name && graph.ancestors(of: $0.name).contains(first.name) }
        return FirstFailureAnalysis(
            firstFailingTransition: first.name,
            primaryRootCause: first.rootCause
                ?? "\(HealthResult.displayName(for: first.name)) did not meet its expected state.",
            dependentFailures: dependent.map(\.name).sorted(),
            blockedBy: Array(graph.ancestors(of: first.name).intersection(failedNames)).sorted()
        )
    }
}

public enum ResearchReadiness: String, Codable, Sendable {
    case healthy = "HEALTHY", degraded = "DEGRADED", blocked = "BLOCKED", unknown = "UNKNOWN"
}

public struct SRDHealthReport: Codable, Sendable {
    public let deviceID: String
    public let results: [HealthResult]
    public let analysis: FirstFailureAnalysis
    public let readiness: ResearchReadiness
    public let checkedAt: Date

    public init(deviceID: String, results: [HealthResult], graph: DependencyGraph = DependencyGraph()) {
        self.deviceID = deviceID
        self.results = results
        self.analysis = FirstFailureAnalyzer(graph: graph).analyze(results)
        self.checkedAt = Date()
        if results.contains(where: { $0.status == .unknown }) { readiness = .unknown }
        else if results.contains(where: { $0.status == .fail && $0.severity >= .high }) { readiness = .blocked }
        else if results.contains(where: { $0.status.isFailure || $0.status == .warning }) { readiness = .degraded }
        else { readiness = .healthy }
    }
}

public extension HealthResult {
    init(legacy check: HealthCheck) {
        let status: HealthStatus
        switch check.state {
        case .pass: status = .pass
        case .fail: status = .fail
        case .notApplicable: status = .info
        case .notRun: status = .unknown
        }
        self.init(name: HealthResult.canonical(check.transition), status: status,
                  severity: check.mandatory ? .high : .medium,
                  observed: ["detail": .string(check.detail)], expected: "component is ready",
                  rootCause: status == .fail ? check.detail : nil,
                  remediation: status == .fail ? ["repair \(check.transition) and run health checks again"] : [],
                  checkedAt: check.checkedAt)
    }

    static func canonical(_ legacy: String) -> String {
        switch legacy {
        case "DEVICE_DISCOVERY": "DEVICE"
        case "PAIR_RECORD": "PAIRING"
        case "WIRELESS_PAIRING": "WIFI_PAIRING"
        case "BRIDGE_SERVICES": "BRIDGE_DAEMON"
        default: legacy
        }
    }
}
