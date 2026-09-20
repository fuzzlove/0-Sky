import Foundation

public struct BridgeEnvironment: Sendable {
    public let events: EventBus
    public let platformStates: DeviceStateStore
    public let transports: TransportCoordinator
    public let recoveryPolicies: RecoveryPolicyEngine
    public let sessions: ResearchSessionRecorder
    public let ownedProcesses: OwnedProcessRegistry
    public let srdHealth: SRDHealthEngine
    public let structuredLog: StructuredEventLog
    public let crashCollector: CrashCollector
    public let paths: BridgePaths
    public let runner: ScriptRunner
    public let registry: DeviceRegistry
    public let discovery: DeviceDiscoveryManager
    public let states: BridgeStateMachine
    public let coordinator: OperationCoordinator
    public let ssh: SSHManager
    public let pairing: PairingManager
    public let enrollment: DeviceEnrollmentManager
    public let deviceRemoval: DeviceRemovalManager
    public let iosComponents: IOSComponentSetupManager
    public let wireless: WirelessPairingManager
    public let services: ServiceManager
    public let portForward: PortForwardManager
    public let health: HealthMonitor
    public let connection: ConnectionManager
    public let recovery: RecoveryManager
    public let logs: BridgeLogStore
    public let diagnostics: DiagnosticExporter
    public let researcher: ResearcherOperationsManager

    public init(paths: BridgePaths = BridgePaths()) {
        self.paths = paths
        let events = EventBus()
        self.events = events
        let platformStates = DeviceStateStore(events: events)
        self.platformStates = platformStates
        self.transports = TransportCoordinator(events: events)
        self.recoveryPolicies = RecoveryPolicyEngine(events: events)
        let sessions = ResearchSessionRecorder(
            root: paths.supportRoot.appendingPathComponent("research_sessions", isDirectory: true),
            events: events
        )
        self.sessions = sessions
        self.srdHealth = SRDHealthEngine(
            events: events, states: platformStates, sessions: sessions
        )
        self.structuredLog = StructuredEventLog(
            directory: paths.supportRoot.appendingPathComponent("logs", isDirectory: true)
        )
        let ownedProcesses = OwnedProcessRegistry()
        self.ownedProcesses = ownedProcesses
        var executableRoots = ScriptRunner.defaultExecutableRoots
        if let repository = paths.repositoryRoot { executableRoots.append(repository) }
        if let kit = paths.bundledKitRoot { executableRoots.append(kit) }
        let runner = ScriptRunner(
            approvedExecutableRoots: executableRoots,
            approvedWorkingRoots: ScriptRunner.defaultWorkingRoots
                + [paths.supportRoot]
                + (paths.repositoryRoot.map { [$0] } ?? [])
                + (paths.bundledKitRoot.map { [$0] } ?? []),
            events: events,
            sessions: sessions,
            ownedProcesses: ownedProcesses
        )
        self.runner = runner
        let registry = DeviceRegistry(supportURL: paths.supportRoot)
        self.registry = registry
        var backends: [any DeviceDiscoveryBackend] = [
            CoreDeviceDiscoveryBackend(runner: runner)
        ]
        if let python = Self.findPymobilePython(supportRoot: paths.supportRoot) {
            backends.append(PymobileDeviceDiscoveryBackend(pythonURL: python, runner: runner))
            backends.append(RemoteXPCDiscoveryBackend(pythonURL: python, runner: runner))
        }
        let discovery = DeviceDiscoveryManager(backends: backends, registry: registry)
        self.discovery = discovery
        let states = BridgeStateMachine()
        self.states = states
        let coordinator = OperationCoordinator()
        self.coordinator = coordinator
        let ssh = SSHManager(runner: runner)
        self.ssh = ssh
        self.crashCollector = CrashCollector(ssh: ssh, recorder: sessions, events: events)
        let pairing = PairingManager(runner: runner, paths: paths, coordinator: coordinator)
        self.pairing = pairing
        self.enrollment = DeviceEnrollmentManager(
            runner: runner, paths: paths, registry: registry, coordinator: coordinator
        )
        self.deviceRemoval = DeviceRemovalManager(
            runner: runner, paths: paths, registry: registry,
            coordinator: coordinator, events: events
        )
        self.iosComponents = IOSComponentSetupManager(
            runner: runner, paths: paths, coordinator: coordinator, events: events
        )
        let wireless = WirelessPairingManager(
            runner: runner, paths: paths, coordinator: coordinator
        )
        self.wireless = wireless
        let services = ServiceManager(runner: runner)
        self.services = services
        self.portForward = PortForwardManager(services: services)
        let health = HealthMonitor(
            pairing: pairing, wireless: wireless, ssh: ssh, services: services
        )
        self.health = health
        let connection = ConnectionManager(
            stateMachine: states, services: services, ssh: ssh,
            discovery: discovery, wireless: wireless
        )
        self.connection = connection
        self.recovery = RecoveryManager(
            health: health, services: services, pairing: pairing,
            wireless: wireless, connection: connection, events: events
        )
        self.logs = BridgeLogStore()
        self.diagnostics = DiagnosticExporter()
        self.researcher = ResearcherOperationsManager(runner: runner, paths: paths)
    }

    private static func findPymobilePython(supportRoot: URL) -> URL? {
        let instances = supportRoot.appendingPathComponent("instances")
        let directories = (try? FileManager.default.contentsOfDirectory(
            at: instances, includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )) ?? []
        for directory in directories.sorted(by: { $0.path < $1.path }) {
            let candidate = directory.appendingPathComponent("venv/bin/python3")
            if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate }
        }
        for path in ["/opt/homebrew/bin/python3", "/usr/bin/python3"] {
            if FileManager.default.isExecutableFile(atPath: path) {
                return URL(fileURLWithPath: path)
            }
        }
        return nil
    }
}

public enum HostInspector {
    public static func summary(helperState: String = "Not Registered") -> HostSummary {
        let process = ProcessInfo.processInfo
        return HostSummary(
            computerName: Host.current().localizedName ?? "Mac",
            osVersion: process.operatingSystemVersionString,
            architecture: architecture,
            bridgeVersion: "1.0.0",
            helperState: helperState
        )
    }

    private static var architecture: String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "x86_64"
        #else
        return "unknown"
        #endif
    }
}
