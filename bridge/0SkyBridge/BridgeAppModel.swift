import BridgeCore
import Combine
import CryptoKit
import Foundation
import AppKit
import OSLog
import ServiceManagement
import UserNotifications

struct PairingWorkflowStep: Identifiable {
    enum State: Equatable { case complete, active, pending, failed }
    let id: Int
    let title: String
    let state: State
}

@MainActor
final class BridgeAppModel: ObservableObject {
    private static let serviceLogger = Logger(
        subsystem: "com.liquidsky.0sky.bridge",
        category: "bridge-service"
    )
    @Published var devices: [SkyDevice] = []
    @Published var selectedDeviceID: String?
    @Published var dependencies: [DependencyStatus] = []
    @Published var services: [ServiceStatus] = []
    @Published var health: BridgeHealthSnapshot?
    @Published var srdHealthReport: SRDHealthReport?
    @Published var logEntries: [BridgeLogEntry] = []
    @Published var operations: [BridgeOperationResult] = []
    @Published var isBusy = false
    @Published var statusMessage = "Discovering devices…"
    @Published var lastError: String?
    @Published var showSetupAssistant = false
    @Published var setupAssistantStartStep = 0
    @Published var verboseLogging = true
    @Published var automaticReconnect = true
    @Published var startAtLogin = false
    @Published var selectedHasProfile = false
    @Published var workflowActive = false
    @Published var connectionMetrics: ConnectionMetrics?
    @Published var activeResearchSession: ResearchSession?
    @Published var lastResearchSessionDirectory: URL?
    @Published var bridgeServiceStatus = BridgeDaemonClient.registrationStatus()
    @Published var iosSetupActive = false
    @Published var iosSetupProgress: [String] = []
    @Published var iosSetupError: String?
    @Published var iosSetupCompleted = false
    @Published var iosSetupStartedAt: Date?
    @Published var iosSetupLastActivity: Date?

    let environment: BridgeEnvironment
    let daemonClient = BridgeDaemonClient()
    @Published var host: HostSummary
    private var monitorTask: Task<Void, Never>?
    private var reconnectTasks: [String: Task<Void, Never>] = [:]
    private var workspaceObservers: [NSObjectProtocol] = []
    private var refreshCount = 0
    private var previousConnections: [String: ConnectionKind] = [:]
    private var previousHealthStates: [String: HealthState] = [:]

    init(environment: BridgeEnvironment = BridgeEnvironment()) {
        self.environment = environment
        self.host = HostInspector.summary(
            helperState: PrivilegedHelperClient.registrationStatus()
        )
        self.dependencies = DependencyManager().inspect(paths: environment.paths)
        self.startAtLogin = SMAppService.mainApp.status == .enabled
    }

    deinit { monitorTask?.cancel() }

    var selectedDevice: SkyDevice? {
        guard let selectedDeviceID else { return nil }
        return devices.first { $0.udid == selectedDeviceID }
    }

    var defaultCredentialsDetected: Bool {
        srdHealthReport?.results.contains {
            ($0.name == "DEFAULT_CREDENTIALS" || $0.name == "VNC_DEFAULT_CREDENTIALS")
                && $0.status == .fail
        } == true
    }
    var overallReady: Bool { health?.state == .healthy && !defaultCredentialsDetected }
    var requiredActionResult: HealthResult? {
        if let credentials = srdHealthReport?.results.first(where: {
            $0.name == "DEFAULT_CREDENTIALS" && $0.status == .fail
        }) {
            return credentials
        }
        if let vncCredentials = srdHealthReport?.results.first(where: {
            $0.name == "VNC_DEFAULT_CREDENTIALS" && $0.status == .fail
        }) {
            return vncCredentials
        }
        if let snapshot = health,
           snapshot.state != .healthy,
           let first = snapshot.firstFailingTransition {
            let canonical = HealthResult.canonical(first)
            if let result = snapshot.results.first(where: { $0.name == canonical }) {
                return result
            }
        }
        if let report = srdHealthReport,
           let first = report.analysis.firstFailingTransition,
           let result = report.results.first(where: { $0.name == first }) {
            return result
        }
        if let report = srdHealthReport,
           let unresolved = report.results.first(where: {
               $0.status == .unknown || $0.status == .fail || $0.status == .degraded
           }) {
            return unresolved
        }
        if let snapshot = health, snapshot.state != .healthy,
           let unresolved = snapshot.results.first(where: {
               $0.status == .unknown || $0.status == .fail || $0.status == .degraded
           }) {
            return unresolved
        }
        guard let snapshot = health,
              let first = snapshot.firstFailingTransition else { return nil }
        let canonical = HealthResult.canonical(first)
        return snapshot.results.first { $0.name == canonical }
    }
    var canSafelyRecoverRequiredAction: Bool {
        guard let failure = health?.firstFailingTransition else { return false }
        return [
            "DEVICE_DISCOVERY", "WIRELESS_PAIRING", "PORT_FORWARD", "BRIDGE_SERVICES",
            "SSH", "0SKY_LINK", "0SKY_CONTROL", "PAIR_RECORD", "TRUST",
        ].contains(failure)
    }
    var hasMissingDependencies: Bool {
        dependencies.contains { $0.required && !$0.available }
    }

    func start() {
        guard monitorTask == nil else { return }
        Task { try? await environment.structuredLog.attach(to: environment.events) }
        installWorkspaceObservers()
        ensurePersistentLaunch()
        Task { await ensureBridgeServiceRegistration() }
        ensurePrivilegedHelperRegistration()
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        monitorTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                self.refreshCount += 1
                await self.refresh(runHealth: self.refreshCount % 3 == 0)
                try? await Task.sleep(for: .seconds(5))
            }
        }
        Task { await refresh(runHealth: true) }
    }

    func stop() {
        monitorTask?.cancel()
        monitorTask = nil
        reconnectTasks.values.forEach { $0.cancel() }
        reconnectTasks.removeAll()
        for observer in workspaceObservers {
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
        workspaceObservers.removeAll()
        Task { await environment.runner.cancelAll() }
    }

    func setStartAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
            startAtLogin = enabled
        } catch {
            startAtLogin = SMAppService.mainApp.status == .enabled
            lastError = "Login item update failed: \(error.localizedDescription)"
        }
    }

    func registerPrivilegedHelper() {
        do {
            try SMAppService.daemon(plistName: "com.liquidsky.0sky.bridge.helper.plist").register()
            statusMessage = "Privileged helper registration submitted. Approve it in System Settings if requested."
            host = HostInspector.summary(helperState: PrivilegedHelperClient.registrationStatus())
        } catch {
            lastError = "Privileged helper registration failed: \(error.localizedDescription)"
        }
    }

    func select(_ id: String?) {
        selectedDeviceID = id
        Task { await refreshDetails() }
    }

    func openSetupAssistant(step: Int = 0) {
        setupAssistantStartStep = max(0, min(10, step))
        showSetupAssistant = true
    }

    func refresh(runHealth: Bool = false) async {
        dependencies = DependencyManager().inspect(paths: environment.paths)
        let serviceSnapshot = try? await daemonClient.snapshot(refresh: true)
        let found: [SkyDevice]
        if let serviceSnapshot { found = serviceSnapshot.devices }
        else { found = await environment.discovery.discover() }
        bridgeServiceStatus = serviceSnapshot == nil ? BridgeDaemonClient.registrationStatus() : "Connected"
        let oldConnections = previousConnections
        devices = found
        for index in devices.indices {
            let device = devices[index]
            var state = await environment.states.state(for: device.udid)
            if device.connection == .offline, reconnectTasks[device.udid] == nil {
                state = .offline
                await environment.states.restore(deviceID: device.udid, state: state)
            } else if state == .offline || state == .discovering {
                state = device.paired ? .paired : .deviceDetected
                await environment.states.restore(deviceID: device.udid, state: state)
            }
            devices[index].bridgeState = state
        }
        previousConnections = Dictionary(uniqueKeysWithValues: found.map { ($0.udid, $0.connection) })
        if selectedDeviceID == nil || !found.contains(where: { $0.udid == selectedDeviceID }) {
            selectedDeviceID = found.first?.udid
        }
        if let selectedDeviceID, let serviceSnapshot {
            health = serviceSnapshot.health[selectedDeviceID]
            srdHealthReport = serviceSnapshot.srdHealth[selectedDeviceID]
            activeResearchSession = serviceSnapshot.activeSession
        }
        statusMessage = found.isEmpty ? "No iPhone or iPad detected." : "\(found.count) device profile(s) available."
        for device in found {
            if oldConnections[device.udid] == nil {
                await environment.events.publish(BridgeEvent(
                    event: .deviceDiscovered, deviceID: device.udid, component: "device_manager",
                    message: "Device discovered.", observed: ["transport": .string(device.connection.rawValue)]
                ))
                await environment.logs.append(
                    category: .device, level: .info,
                    message: "Detected \(device.productType ?? "Apple device") over \(device.connection.rawValue).",
                    deviceID: device.udid
                )
            } else if oldConnections[device.udid] != device.connection {
                await environment.events.publish(BridgeEvent(
                    event: device.connection == .offline ? .deviceDisconnected : .deviceConnected,
                    deviceID: device.udid,
                    severity: device.connection == .offline ? .warning : .info,
                    component: "transport", message: "Device transport changed.",
                    observed: ["transport": .string(device.connection.rawValue)]
                ))
                await environment.logs.append(
                    category: device.wifiConnected ? .wireless : .usb,
                    level: device.connection == .offline ? .warning : .pass,
                    message: "Connection changed to \(device.connection.rawValue).",
                    deviceID: device.udid
                )
            }
            if oldConnections[device.udid] == .offline && device.connection != .offline {
                notify(title: "0-Sky device connected", body: device.name ?? device.udid)
            }
            if let previous = oldConnections[device.udid], previous != .offline,
               device.connection == .offline {
                notify(title: "Bridge connection lost", body: device.name ?? device.udid)
            }
            if automaticReconnect, device.paired, device.connection == .offline {
                scheduleAutomaticReconnect(device)
            }
            let measured = await environment.transports.update(
                deviceID: device.udid, usb: device.usbConnected, wifi: device.wifiConnected,
                reason: device.connection == .offline ? "device discovery reported no active transport" : nil
            )
            if device.udid == selectedDeviceID { connectionMetrics = measured }
        }
        if runHealth { await refreshDetails() }
    }

    func refreshDetails() async {
        guard let device = selectedDevice,
              let profile = await environment.registry.profile(for: device.udid) else {
            services = []
            health = nil
            selectedHasProfile = false
            workflowActive = selectedDevice != nil
            return
        }
        selectedHasProfile = true
        workflowActive = true
        async let serviceValues = environment.services.allStatuses(profile: profile)
        async let healthValue = environment.health.check(device: device, profile: profile)
        async let integrationValue = environment.health.integrationStatus(profile: profile)
        services = await serviceValues
        health = await healthValue
        srdHealthReport = await environment.srdHealth.check(deviceID: device.udid, adapters: [
            USBAdapter(device: device),
            RemoteXPCAdapter(manager: environment.researcher, profile: profile),
            SSHAdapter(manager: environment.ssh, profile: profile),
            DeveloperServicesAdapter(manager: environment.researcher),
            DDIAdapter(manager: environment.researcher, profile: profile),
            CryptexAdapter(ssh: environment.ssh, profile: profile),
            BootstrapAdapter(ssh: environment.ssh, profile: profile),
            FridaHostAdapter(runner: environment.runner),
            FridaDeviceAdapter(ssh: environment.ssh, profile: profile),
            FridaAdapter(runner: environment.runner, ssh: environment.ssh, profile: profile),
            DefaultCredentialsAdapter(ssh: environment.ssh, profile: profile),
            VNCDefaultCredentialsAdapter(ssh: environment.ssh, profile: profile),
            DebugserverAdapter(manager: environment.researcher, profile: profile),
            LLDBAdapter(runner: environment.runner),
            DeviceStorageAdapter(ssh: environment.ssh, profile: profile),
        ])
        if let health {
            await environment.events.publish(BridgeEvent(
                event: .healthCheckCompleted, deviceID: device.udid,
                severity: health.state == .healthy ? .info : .warning,
                component: "health", message: "SRD health check completed.",
                observed: [
                    "readiness": .string(health.readiness.rawValue),
                    "first_failure": .string(health.firstFailingTransition ?? "none")
                ]
            ))
        }
        let integration = await integrationValue
        let measuredBridgeState: BridgeState = health?.state == .healthy ? .connected : .degraded
        await environment.states.restore(deviceID: device.udid, state: measuredBridgeState)
        if let index = devices.firstIndex(where: { $0.udid == device.udid }) {
            devices[index].linkReachable = integration.linkReachable
            devices[index].controlInstalled = integration.controlInstalled
            devices[index].controlRunning = integration.controlRunning
            devices[index].controlReachable = integration.controlReachable
            devices[index].controlVersion = integration.controlVersion
            devices[index].bridgeState = measuredBridgeState
        }
        if let state = health?.state, previousHealthStates[device.udid] != state {
            previousHealthStates[device.udid] = state
            await environment.logs.append(
                category: .health,
                level: state == .healthy ? .pass : (state == .failed ? .error : .warning),
                message: state == .healthy
                    ? "All mandatory bridge checks passed."
                    : "Health is \(state.rawValue); first failure: \(HealthResult.displayName(for: health?.firstFailingTransition ?? "unknown")).",
                deviceID: device.udid
            )
        }
        await reloadLogs()
    }

    func enrollSelectedDevice() {
        guard let device = selectedDevice else { return }
        Task { await perform("Set Up New Device") { [environment] in
            try await environment.enrollment.enroll(device: device) { event in
                Task { await environment.logs.append(
                    category: .pairing,
                    level: event.stream == .stderr ? .warning : .info,
                    message: DiagnosticRedactor.redact(event.line),
                    deviceID: device.udid
                ) }
            }
        } }
    }

    func setupCompleteIOSProject() {
        guard let device = selectedDevice else {
            lastError = "Select the new SRD before installing the 0-Sky iOS Project."
            return
        }
        guard !iosSetupActive else { return }
        iosSetupActive = true
        iosSetupCompleted = false
        iosSetupError = nil
        iosSetupProgress = ["Preflight: validating the selected USB SRD and bundled project kit…"]
        iosSetupStartedAt = Date()
        iosSetupLastActivity = Date()
        isBusy = true
        lastError = nil
        statusMessage = "Install Complete 0-Sky iOS Project…"

        Task {
            do {
                let setup = try await environment.iosComponents.setupCompleteProject(
                    device: device, confirmed: true
                ) { [weak self, environment] event in
                    let line = DiagnosticRedactor.redact(event.line)
                    Task { @MainActor [weak self] in
                        self?.appendIOSSetupProgress(line)
                    }
                    Task {
                        await environment.logs.append(
                            category: .service,
                            level: event.stream == .stderr ? .warning : .info,
                            message: line,
                            deviceID: device.udid
                        )
                    }
                }
                operations.append(setup)
                if setup.succeeded {
                    _ = try? await environment.registry.reload()
                    appendIOSSetupProgress("Complete project installation and postcondition checks passed.")
                    iosSetupCompleted = true
                    statusMessage = "Install Complete 0-Sky iOS Project completed."
                } else {
                    let detail = setup.stderr.isEmpty ? setup.stdout : setup.stderr
                    let message = DiagnosticRedactor.redact(detail).trimmingCharacters(in: .whitespacesAndNewlines)
                    iosSetupError = message.isEmpty
                        ? "The setup controller exited with status \(setup.exitCode)."
                        : message
                    appendIOSSetupProgress("Setup stopped with exit status \(setup.exitCode).")
                    statusMessage = "Install Complete 0-Sky iOS Project failed."
                }
            } catch {
                let message = DiagnosticRedactor.redact(error.localizedDescription)
                iosSetupError = message
                appendIOSSetupProgress("Setup failed: \(message)")
                statusMessage = "Install Complete 0-Sky iOS Project failed."
            }
            iosSetupActive = false
            isBusy = false

            // A full health pass can take tens of seconds. Do not keep the
            // installer UI in its busy state while post-install health is
            // measured; report setup completion first and refresh separately.
            if iosSetupCompleted {
                Task { await self.refresh(runHealth: true) }
            }
        }
    }

    private func appendIOSSetupProgress(_ rawLine: String) {
        let line = rawLine
            .replacingOccurrences(of: "\u{001B}", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !line.isEmpty else { return }
        iosSetupProgress.append(line)
        if iosSetupProgress.count > 250 {
            iosSetupProgress.removeFirst(iosSetupProgress.count - 250)
        }
        iosSetupLastActivity = Date()
        statusMessage = line
    }

    var requiredIOSComponentPlan: IOSComponentSetupPlan {
        IOSComponentSetupManager.plan(.completeProject)
    }

    func verifyPairing() { runPairing(mode: .verify, name: "Verify Pairing") }
    func pairDevice() { runPairing(mode: .pair, name: "Pair Device") }
    func repairPinnedHostKey() {
        runPairing(mode: .repairHostKey, name: "Repair Pinned Device Host Key")
    }

    private func runPairing(mode: PairingManager.Mode, name: String) {
        guard let device = selectedDevice else { return }
        Task {
            await environment.states.restore(deviceID: device.udid, state: .pairing)
            updateDisplayedState(device.udid, .pairing)
            await perform(name) { [environment] in
            guard let profile = await environment.registry.profile(for: device.udid) else {
                throw BridgeCoreError.operationFailed("This device has no 0-Sky profile.")
            }
            return try await environment.pairing.run(
                profile: profile, mode: mode, requireWorker: mode == .verify
            ) { event in
                Task { await environment.logs.append(
                    category: .pairing,
                    level: event.stream == .stderr ? .warning : .info,
                    message: DiagnosticRedactor.redact(event.line),
                    deviceID: device.udid
                ) }
            }
            }
            let state: BridgeState = lastError == nil ? .paired : .waitingForTrust
            await environment.states.restore(deviceID: device.udid, state: state)
            updateDisplayedState(device.udid, state)
        }
    }

    func enableWireless() { runWireless(.enable, name: "Enable Wi-Fi Pairing") }
    func verifyWireless() { runWireless(.verify, name: "Verify Wi-Fi Connection") }

    private func runWireless(_ operation: WirelessPairingManager.Operation, name: String) {
        guard let device = selectedDevice else { return }
        Task {
            await environment.states.restore(deviceID: device.udid, state: .enablingWireless)
            updateDisplayedState(device.udid, .enablingWireless)
            await perform(name) { [environment] in
            guard let profile = await environment.registry.profile(for: device.udid) else {
                throw BridgeCoreError.operationFailed("This device has no 0-Sky profile.")
            }
            return try await environment.wireless.run(
                profile: profile,
                operation: operation,
                hostFingerprint: profile.macIdentityFingerprint ?? "",
                usbTrustVerified: profile.pairingVerified
            )
            }
            let state: BridgeState = lastError == nil
                ? (health?.state == .healthy ? .connected : .connecting) : .degraded
            await environment.states.restore(deviceID: device.udid, state: state)
            updateDisplayedState(device.udid, state)
            if operation == .enable, lastError == nil, device.usbConnected {
                statusMessage = "Wi-Fi pairing is enabled. Disconnect USB, then select Verify Wi-Fi Connection."
            }
        }
    }

    func reconnect() {
        guard let device = selectedDevice else { return }
        Task {
            isBusy = true
            defer { isBusy = false }
            guard let profile = await environment.registry.profile(for: device.udid) else { return }
            let connected = await environment.connection.reconnect(profile: profile)
            statusMessage = connected ? "Connection restored." : "Reconnection is still in periodic health-check mode."
            await refreshDetails()
        }
    }

    func fixBridge() {
        guard let device = selectedDevice else { return }
        Task {
            isBusy = true
            defer { isBusy = false }
            if let serviceHealth = try? await daemonClient.recover(deviceID: device.udid) {
                health = serviceHealth
            } else {
                guard let profile = await environment.registry.profile(for: device.udid) else { return }
                health = await environment.recovery.fix(device: device, profile: profile)
            }
            statusMessage = health?.state == .healthy
                ? "The affected bridge component was repaired and verified."
                : "Repair stopped at \(HealthResult.displayName(for: health?.firstFailingTransition ?? "an unknown transition"))."
            await reloadLogs()
        }
    }

    func serviceAction(_ action: String, service: ServiceManager.Kind) {
        guard let device = selectedDevice else { return }
        Task { await perform("\(action.capitalized) \(service.rawValue)") { [environment] in
            guard let profile = await environment.registry.profile(for: device.udid) else {
                throw BridgeCoreError.operationFailed("This device has no 0-Sky profile.")
            }
            switch action {
            case "start": return try await environment.services.start(kind: service, profile: profile)
            case "stop": return try await environment.services.stop(kind: service, profile: profile)
            default: return try await environment.services.restart(kind: service, profile: profile)
            }
        } }
    }

    func runDiagnostics() { Task { await refresh(runHealth: true) } }

    func addressRequiredAction() {
        verboseLogging = true
        runDiagnostics()
    }

    func clearLogs() {
        Task {
            isBusy = true
            defer { isBusy = false }
            var serviceWarning: String?
            do {
                // Ask the persistent owner to close out its in-memory view and
                // clear shared files first, then clear this GUI client's view.
                try await daemonClient.clearLogs()
            } catch {
                // The shared files and GUI view can still be safely cleared if
                // the persistent service is temporarily unavailable.
                serviceWarning = DiagnosticRedactor.redact(error.localizedDescription)
            }
            do {
                await environment.logs.clear()
                _ = try await environment.structuredLog.clear()
                logEntries = []
                statusMessage = serviceWarning == nil
                    ? "0-Sky Bridge logs cleared. Research-session evidence was preserved."
                    : "Local logs cleared; the persistent service was unavailable. Research-session evidence was preserved."
            } catch {
                lastError = "Could not clear 0-Sky Bridge logs: \(DiagnosticRedactor.redact(error.localizedDescription))"
            }
        }
    }

    func installMissingDependencies() {
        do {
            let installer = try environment.paths.dependencyInstaller()
            guard NSWorkspace.shared.open(installer) else {
                throw BridgeCoreError.operationFailed(
                    "Terminal could not open the dependency installer."
                )
            }
            statusMessage = "Dependency installer opened in Terminal. Return here when it finishes; status refreshes automatically."
        } catch {
            lastError = "Could not open dependency installer: \(error.localizedDescription)"
        }
    }

    func cancelCurrentOperations() {
        Task {
            if iosSetupActive {
                appendIOSSetupProgress("Cancellation requested; stopping the owned setup process…")
                statusMessage = "Cancelling iOS component setup…"
            }
            await environment.runner.cancelAll()
            if !iosSetupActive {
                isBusy = false
                statusMessage = "Operation cancelled. Owned processes were terminated."
            }
        }
    }

    func checkCoreDevice() {
        Task { await perform("Check CoreDevice") { [environment] in
            try await environment.researcher.checkCoreDevice()
        } }
    }

    func checkDeveloperServices() {
        Task { await perform("Check Developer Services") { [environment] in
            try await environment.researcher.checkDeveloperServices()
        } }
    }

    func checkRemoteXPC() {
        guard let device = selectedDevice else { return }
        Task { await perform("Check RemoteXPC") { [environment] in
            guard let profile = await environment.registry.profile(for: device.udid) else {
                throw BridgeCoreError.operationFailed("This device has no 0-Sky profile.")
            }
            return try await environment.researcher.checkRemoteXPC(profile: profile)
        } }
    }

    func testDevicePorts() {
        guard let device = selectedDevice else { return }
        Task { await perform("Test Device Ports") { [environment] in
            guard let profile = await environment.registry.profile(for: device.udid) else {
                throw BridgeCoreError.operationFailed("This device has no 0-Sky profile.")
            }
            return await environment.researcher.testForwardedPort(profile: profile)
        } }
    }

    func restartDiscovery() {
        Task {
            let start = Date()
            await refresh(runHealth: false)
            operations.append(BridgeOperationResult(
                identifier: "research.restart-discovery",
                startedAt: start, finishedAt: Date(), exitCode: 0,
                stdout: "Discovery backends reran and normalized \(devices.count) device record(s).\n",
                stderr: ""
            ))
        }
    }

    func copyOperationOutput() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(operationTranscript, forType: .string)
    }

    func saveOperationOutput() {
        let panel = NSSavePanel()
        let timestamp = Date().ISO8601Format()
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: "-", with: "")
        panel.nameFieldStringValue = "0sky-operations-\(timestamp).log"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try DiagnosticRedactor.redact(operationTranscript).write(
                to: url, atomically: true, encoding: .utf8
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: url.path
            )
        } catch { lastError = "Could not save operation output: \(error.localizedDescription)" }
    }

    func exportDiagnostics() {
        Task {
            do {
                let pairingObject: [String: String] = health.map {
                    ["state": $0.state.rawValue,
                     "firstFailingTransition": $0.firstFailingTransition ?? ""]
                } ?? [:]
                let networkObject: [String: String] = selectedDevice.map {
                    ["connection": $0.connection.rawValue,
                     "usbConnected": String($0.usbConnected),
                     "wifiConnected": String($0.wifiConnected),
                     "localForwardPort": $0.localPort.map(String.init) ?? ""]
                } ?? [:]
                let location = try await environment.diagnostics.export(
                    host: host, device: selectedDevice, services: services,
                    pairing: pairingObject, network: networkObject, health: health,
                    logs: logEntries, operations: operations
                )
                NSWorkspace.shared.activateFileViewerSelecting([location])
                statusMessage = "Diagnostic report exported."
            } catch { lastError = error.localizedDescription }
        }
    }

    func startResearchSession(name: String = "research") {
        guard let device = selectedDevice else { return }
        Task {
            do {
                let session: ResearchSession
                if bridgeServiceStatus == "Connected" {
                    session = try await daemonClient.startResearchSession(name: name, deviceID: device.udid)
                } else {
                    session = try await environment.sessions.start(
                        name: name, device: device, host: host,
                        toolVersions: ["bridge": host.bridgeVersion],
                        researchConfiguration: ["automatic_reconnect": String(automaticReconnect)]
                    )
                }
                activeResearchSession = session
                statusMessage = "Research session recording started."
            } catch { lastError = error.localizedDescription }
        }
    }

    func stopResearchSession() {
        Task {
            do {
                let directory = bridgeServiceStatus == "Connected"
                    ? try await daemonClient.stopResearchSession()
                    : try await environment.sessions.stop()
                lastResearchSessionDirectory = directory
                activeResearchSession = nil
                statusMessage = "Research session stopped and evidence hashes generated."
            } catch { lastError = error.localizedDescription }
        }
    }

    func exportResearchBundle(profile: EvidenceExportProfile = .vendorDisclosure) {
        guard let directory = lastResearchSessionDirectory else {
            lastError = "Stop a research session before exporting it."
            return
        }
        Task {
            do {
                let archive = bridgeServiceStatus == "Connected"
                    ? try await daemonClient.exportLastResearchSession(profile: profile)
                    : try await environment.sessions.export(sessionDirectory: directory, profile: profile)
                NSWorkspace.shared.activateFileViewerSelecting([archive])
                statusMessage = "Research evidence bundle exported."
            } catch { lastError = error.localizedDescription }
        }
    }

    private func perform(
        _ displayName: String,
        operation: @escaping @Sendable () async throws -> BridgeOperationResult
    ) async {
        isBusy = true
        lastError = nil
        statusMessage = "\(displayName)…"
        defer { isBusy = false }
        do {
            let result = try await operation()
            operations.append(result)
            statusMessage = result.succeeded ? "\(displayName) completed." : "\(displayName) failed."
            if !result.succeeded { lastError = DiagnosticRedactor.redact(result.stderr) }
            // Release the global busy state before the potentially long health
            // refresh so a completed command never appears permanently stuck.
            isBusy = false
            await refresh(runHealth: true)
        } catch {
            lastError = DiagnosticRedactor.redact(error.localizedDescription)
            statusMessage = "\(displayName) failed."
        }
    }

    var operationTranscript: String {
        operations.map { result in
            """
            STARTED=\(result.startedAt.ISO8601Format())
            OPERATION=\(result.identifier)
            EXIT_STATUS=\(result.exitCode)
            DURATION_SECONDS=\(String(format: "%.3f", result.duration))
            STDOUT:
            \(result.stdout)
            STDERR:
            \(result.stderr)
            """
        }.joined(separator: "\n---\n")
    }

    private func reloadLogs() async {
        logEntries = await environment.logs.all(deviceID: selectedDeviceID)
    }

    private func updateDisplayedState(_ udid: String, _ state: BridgeState) {
        if let index = devices.firstIndex(where: { $0.udid == udid }) {
            devices[index].bridgeState = state
        }
    }

    var pairingWorkflow: [PairingWorkflowStep] {
        guard let device = selectedDevice else { return [] }
        let check: (String) -> CheckState? = { transition in
            self.health?.checks.first(where: { $0.transition == transition })?.state
        }
        let profile = selectedHasProfile
        let transport = device.usbConnected || device.wifiConnected
        let values: [(String, Bool)] = [
            ("Device detected", true),
            ("Device identity read", device.productType != nil || device.name != nil),
            ("Host profile created", profile),
            ("Device unlocked", check("TRUST") == .pass),
            ("Host pairing record created", check("PAIR_RECORD") == .pass),
            ("Device trusted", check("TRUST") == .pass),
            ("USB communication verified", check("USB") == .pass),
            ("Wi-Fi pairing enabled", check("WIRELESS_PAIRING") == .pass),
            ("Wi-Fi reconnect verified", device.wifiConnected),
            ("0-Sky Link detected", check("0SKY_LINK") == .pass),
            ("0-Sky Control installed", device.controlInstalled),
            ("0-Sky Control running", device.controlRunning),
            ("0-Sky Control reachable", device.controlReachable),
            ("SSH verified", check("SSH") == .pass),
            ("Bridge health checked", health != nil),
            ("READY", health?.state == .healthy && transport),
        ]
        let firstIncomplete = values.firstIndex { !$0.1 }
        return values.enumerated().map { index, value in
            PairingWorkflowStep(
                id: index,
                title: value.0,
                state: value.1 ? .complete : (index == firstIncomplete ? .active : .pending)
            )
        }
    }

    private func scheduleAutomaticReconnect(_ device: SkyDevice) {
        guard reconnectTasks[device.udid] == nil else { return }
        reconnectTasks[device.udid] = Task { [weak self] in
            guard let self,
                  let profile = await self.environment.registry.profile(for: device.udid) else {
                self?.reconnectTasks.removeValue(forKey: device.udid)
                return
            }
            let connected = await self.environment.connection.reconnect(profile: profile)
            self.reconnectTasks.removeValue(forKey: device.udid)
            if connected {
                self.notify(title: "0-Sky Link restored", body: device.name ?? device.udid)
                await self.refresh(runHealth: device.udid == self.selectedDeviceID)
            }
        }
    }

    private func ensurePersistentLaunch() {
        guard SMAppService.mainApp.status != .enabled else {
            startAtLogin = true
            return
        }
        do {
            try SMAppService.mainApp.register()
            startAtLogin = SMAppService.mainApp.status == .enabled
            if !startAtLogin {
                statusMessage = "Approve 0-Sky Bridge under Login Items to keep automatic reconnection active after login."
            }
        } catch {
            lastError = "Persistent launch registration failed: \(error.localizedDescription)"
        }
    }

    private func ensureBridgeServiceRegistration() async {
        let service = SMAppService.agent(plistName: "com.liquidsky.0sky.bridge.service.plist")
        let fingerprintKey = "bridgeServiceExecutableFingerprintV2"
        let fingerprint = bridgeServiceExecutableFingerprint()
        let installedFingerprint = UserDefaults.standard.string(forKey: fingerprintKey)
        let executableChanged = fingerprint != nil && fingerprint != installedFingerprint
        // `notFound` means there is no Background Task Management record yet,
        // not that the plist is absent from this bundle.  A first install (and
        // some development upgrades) therefore needs the same registration
        // attempt as `notRegistered`.
        if executableChanged && service.status == .enabled {
            do {
                // Service Management binds a launch item to the executable's
                // code requirement. Refresh that record after an app update so
                // launchd never retries a stale LWCR indefinitely.
                let unregisterError: (any Error)? = await withCheckedContinuation { continuation in
                    service.unregister { continuation.resume(returning: $0) }
                }
                if let unregisterError { throw unregisterError }
                // `unregister` completion can precede deletion of the BTM
                // record. Allow that transaction to settle before registering
                // the new code requirement.
                try await Task.sleep(for: .seconds(1))
                try service.register()
                try await Task.sleep(for: .milliseconds(250))
                Self.serviceLogger.notice("Persistent bridge service registration refreshed after update")
            } catch {
                let message = DiagnosticRedactor.redact(error.localizedDescription)
                Self.serviceLogger.error("Persistent bridge service update registration failed: \(message, privacy: .public)")
                statusMessage = "Persistent bridge service update failed: \(message)"
            }
        } else if service.status == .notRegistered || service.status == .notFound {
            do {
                try service.register()
                Self.serviceLogger.notice("Persistent bridge service registration requested")
            } catch {
                let message = DiagnosticRedactor.redact(error.localizedDescription)
                Self.serviceLogger.error("Persistent bridge service registration failed: \(message, privacy: .public)")
                statusMessage = "Persistent bridge service registration failed: \(message)"
            }
        }
        if service.status == .enabled {
            try? await Task.sleep(for: .milliseconds(500))
        }
        var reachable = (try? await daemonClient.version()) != nil
        // Ad-hoc development signatures have a changing code hash. On some
        // macOS builds, BTM invalidates the old launch constraint only after
        // launchd's first failed repair. Perform one bounded delayed retry;
        // Developer-ID releases normally pass the first verification.
        if !reachable, executableChanged, service.status == .enabled {
            statusMessage = "Refreshing the persistent bridge service after an application update…"
            try? await Task.sleep(for: .seconds(35))
            do {
                let unregisterError: (any Error)? = await withCheckedContinuation { continuation in
                    service.unregister { continuation.resume(returning: $0) }
                }
                if let unregisterError { throw unregisterError }
                try await Task.sleep(for: .seconds(2))
                try service.register()
                try await Task.sleep(for: .seconds(1))
                reachable = (try? await daemonClient.version()) != nil
                Self.serviceLogger.notice("Persistent bridge service bounded update retry completed")
            } catch {
                let message = DiagnosticRedactor.redact(error.localizedDescription)
                Self.serviceLogger.error("Persistent bridge service bounded retry failed: \(message, privacy: .public)")
            }
        }
        bridgeServiceStatus = reachable ? "Connected" : BridgeDaemonClient.registrationStatus()
        if reachable, let fingerprint {
            UserDefaults.standard.set(fingerprint, forKey: fingerprintKey)
        }
        Self.serviceLogger.notice("Persistent bridge service status: \(self.bridgeServiceStatus, privacy: .public)")
        if service.status == .requiresApproval {
            statusMessage = "Approve 0-Sky Bridge under System Settings → General → Login Items to enable its persistent service."
        }
    }

    private func bridgeServiceExecutableFingerprint() -> String? {
        let url = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/0SkyBridgeService", isDirectory: false)
        guard let data = try? Data(contentsOf: url, options: [.mappedIfSafe]) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func ensurePrivilegedHelperRegistration() {
        let service = SMAppService.daemon(
            plistName: "com.liquidsky.0sky.bridge.helper.plist"
        )
        guard service.status == .notRegistered else {
            host = HostInspector.summary(helperState: PrivilegedHelperClient.registrationStatus())
            return
        }
        do {
            try service.register()
            host = HostInspector.summary(helperState: PrivilegedHelperClient.registrationStatus())
            if service.status == .requiresApproval {
                statusMessage = "Approve the 0-Sky Bridge helper in System Settings → Login Items."
            }
        } catch {
            host = HostInspector.summary(helperState: PrivilegedHelperClient.registrationStatus())
            statusMessage = "Privileged helper is not active: \(error.localizedDescription)"
        }
    }

    private func installWorkspaceObservers() {
        guard workspaceObservers.isEmpty else { return }
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.didWakeNotification, NSWorkspace.didMountNotification] {
            workspaceObservers.append(center.addObserver(
                forName: name, object: nil, queue: .main
            ) { [weak self] _ in
                Task { @MainActor in await self?.refresh(runHealth: true) }
            })
        }
        workspaceObservers.append(center.addObserver(
            forName: NSWorkspace.willSleepNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                await self.environment.runner.cancelAll()
            }
        })
    }

    private func notify(title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        )
    }

}
