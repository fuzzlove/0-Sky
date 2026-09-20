import BridgeCore
import Combine
import CryptoKit
import Foundation
import AppKit
import OSLog
import ServiceManagement
import UserNotifications
import UniformTypeIdentifiers

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
    @Published var selectedPairedHostCount = 0
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
    @Published var activeOperationName: String?
    @Published var activeOperationStartedAt: Date?
    @Published var cancellationInProgress = false

    let environment: BridgeEnvironment
    let daemonClient = BridgeDaemonClient()
    @Published var host: HostSummary
    private var monitorTask: Task<Void, Never>?
    private var reconnectTasks: [String: Task<Void, Never>] = [:]
    private var workspaceObservers: [NSObjectProtocol] = []
    private var refreshCount = 0
    private var previousConnections: [String: ConnectionKind] = [:]
    private var previousHealthStates: [String: HealthState] = [:]
    private var activeOperationTask: Task<Void, Never>?
    private var activeOperationToken: UUID?

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
            selectedPairedHostCount = 0
            workflowActive = selectedDevice != nil
            return
        }
        selectedHasProfile = true
        selectedPairedHostCount = profile.pairedHostCount
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

    @discardableResult
    private func launchTrackedOperation(
        _ name: String,
        action: @escaping @MainActor () async -> Void
    ) -> Bool {
        guard activeOperationTask == nil else {
            lastError = "\(activeOperationName ?? "Another operation") is already running. Stop it before starting a new operation."
            return false
        }
        let token = UUID()
        activeOperationToken = token
        activeOperationName = name
        activeOperationStartedAt = Date()
        cancellationInProgress = false
        isBusy = true
        activeOperationTask = Task { [weak self] in
            await action()
            guard let self, self.activeOperationToken == token else { return }
            self.activeOperationTask = nil
            self.activeOperationToken = nil
            self.activeOperationName = nil
            self.activeOperationStartedAt = nil
            self.cancellationInProgress = false
            self.isBusy = false
        }
        return true
    }

    func enrollSelectedDevice() {
        guard let device = selectedDevice else { return }
        launchTrackedOperation("Set Up New Device") { [weak self] in
            guard let self else { return }
            await self.perform("Set Up New Device") { [environment] in
            try await environment.enrollment.enroll(device: device) { event in
                Task { await environment.logs.append(
                    category: .pairing,
                    level: event.stream == .stderr ? .warning : .info,
                    message: DiagnosticRedactor.redact(event.line),
                    deviceID: device.udid
                ) }
            }
            }
        }
    }

    func setupCompleteIOSProject() {
        guard let device = selectedDevice else {
            lastError = "Select the new SRD before installing the 0-Sky iOS Project."
            return
        }
        guard !iosSetupActive else { return }
        guard activeOperationTask == nil else {
            lastError = "\(activeOperationName ?? "Another operation") is already running. Stop it before starting iOS setup."
            return
        }
        iosSetupActive = true
        iosSetupCompleted = false
        iosSetupError = nil
        iosSetupProgress = ["Preflight: validating the selected USB SRD and bundled project kit…"]
        iosSetupStartedAt = Date()
        iosSetupLastActivity = Date()
        lastError = nil
        statusMessage = "Install Complete 0-Sky iOS Project…"

        launchTrackedOperation("Install Complete 0-Sky iOS Project") { [weak self] in
            guard let self else { return }
            do {
                let setup = try await self.environment.iosComponents.setupCompleteProject(
                    device: device, confirmed: true
                ) { [weak self, environment = self.environment] event in
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
                self.operations.append(setup)
                if setup.succeeded {
                    _ = try? await self.environment.registry.reload()
                    self.appendIOSSetupProgress("Complete project installation and postcondition checks passed.")
                    self.iosSetupCompleted = true
                    self.statusMessage = "Install Complete 0-Sky iOS Project completed."
                } else {
                    let detail = setup.stderr.isEmpty ? setup.stdout : setup.stderr
                    let message = DiagnosticRedactor.redact(detail).trimmingCharacters(in: .whitespacesAndNewlines)
                    self.iosSetupError = message.isEmpty
                        ? "The setup controller exited with status \(setup.exitCode)."
                        : message
                    self.appendIOSSetupProgress("Setup stopped with exit status \(setup.exitCode).")
                    self.statusMessage = "Install Complete 0-Sky iOS Project failed."
                }
            } catch {
                let message = DiagnosticRedactor.redact(error.localizedDescription)
                self.iosSetupError = message
                self.appendIOSSetupProgress("Setup failed: \(message)")
                self.statusMessage = "Install Complete 0-Sky iOS Project failed."
            }
            self.iosSetupActive = false

            // A full health pass can take tens of seconds. Do not keep the
            // installer UI in its busy state while post-install health is
            // measured; report setup completion first and refresh separately.
            if self.iosSetupCompleted {
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
    func pairDevice() { runPairing(mode: .pair, name: "Pair This Mac") }
    func repairPinnedHostKey() {
        runPairing(mode: .repairHostKey, name: "Repair Pinned Device Host Key")
    }

    private func runPairing(mode: PairingManager.Mode, name: String) {
        guard let device = selectedDevice else { return }
        launchTrackedOperation(name) { [weak self] in
            guard let self else { return }
            await self.environment.states.restore(deviceID: device.udid, state: .pairing)
            self.updateDisplayedState(device.udid, .pairing)
            await self.perform(name) { [environment = self.environment] in
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
            let state: BridgeState = self.lastError == nil ? .paired : .waitingForTrust
            await self.environment.states.restore(deviceID: device.udid, state: state)
            self.updateDisplayedState(device.udid, state)
            if self.lastError == nil {
                _ = try? await self.environment.registry.reload()
                await self.refreshDetails()
            }
        }
    }

    func exportAdditionalMacPairingRequest() {
        guard let device = selectedDevice else { return }
        let panel = NSSavePanel()
        panel.title = "Create Pairing Request for This Mac"
        panel.nameFieldStringValue = "0sky-additional-mac-pairing-request.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        launchTrackedOperation("Create Additional Mac Pairing Request") { [weak self] in
            guard let self else { return }
            await self.perform("Create Additional Mac Pairing Request") {
                try await self.environment.pairing.exportAdditionalMacRequest(
                    deviceID: device.udid, destination: destination
                ) { event in
                    Task { await self.environment.logs.append(
                        category: .pairing,
                        level: event.stream == .stderr ? .warning : .info,
                        message: DiagnosticRedactor.redact(event.line),
                        deviceID: device.udid
                    ) }
                }
            }
            if self.lastError == nil {
                self.statusMessage = "Public-only pairing request created. Transfer it to an already paired Mac for approval."
            }
        }
    }

    func approveAdditionalMacPairingRequest() {
        guard let device = selectedDevice, device.usbConnected else {
            lastError = "Connect the selected device by USB before authorizing another Mac."
            return
        }
        let panel = NSOpenPanel()
        panel.title = "Choose Additional Mac Pairing Request"
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let request = panel.url else { return }
        let alert = NSAlert()
        alert.messageText = "Authorize an additional computer?"
        alert.informativeText = "This adds the signed request's public SSH key to the selected USB-connected device. Existing paired computers remain authorized."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Authorize Additional Computer")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        launchTrackedOperation("Authorize Additional Mac") { [weak self] in
            guard let self else { return }
            await self.perform("Authorize Additional Mac") {
                guard let profile = await self.environment.registry.profile(for: device.udid) else {
                    throw BridgeCoreError.operationFailed("This device has no existing trusted-Mac profile.")
                }
                return try await self.environment.pairing.approveAdditionalMacRequest(
                    profile: profile, request: request
                ) { event in
                    Task { await self.environment.logs.append(
                        category: .pairing,
                        level: event.stream == .stderr ? .warning : .info,
                        message: DiagnosticRedactor.redact(event.line),
                        deviceID: device.udid
                    ) }
                }
            }
            if self.lastError == nil {
                self.statusMessage = "Additional computer authorized. On that Mac, connect this device over USB and choose Set Up New Device, then Pair This Mac."
            }
        }
    }

    func enableWireless() { runWireless(.enable, name: "Enable Wi-Fi Pairing") }
    func verifyWireless() { runWireless(.verify, name: "Verify Wi-Fi Connection") }

    private func runWireless(_ operation: WirelessPairingManager.Operation, name: String) {
        guard let device = selectedDevice else { return }
        launchTrackedOperation(name) { [weak self] in
            guard let self else { return }
            await self.environment.states.restore(deviceID: device.udid, state: .enablingWireless)
            self.updateDisplayedState(device.udid, .enablingWireless)
            await self.perform(name) { [environment = self.environment] in
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
            let state: BridgeState = self.lastError == nil
                ? (self.health?.state == .healthy ? .connected : .connecting) : .degraded
            await self.environment.states.restore(deviceID: device.udid, state: state)
            self.updateDisplayedState(device.udid, state)
            if operation == .enable, self.lastError == nil, device.usbConnected {
                self.statusMessage = "Wi-Fi pairing is enabled. Disconnect USB, then select Verify Wi-Fi Connection."
            }
        }
    }

    func reconnect() {
        guard let device = selectedDevice else { return }
        launchTrackedOperation("Reconnect") { [weak self] in
            guard let self,
                  let profile = await self.environment.registry.profile(for: device.udid) else { return }
            let connected = await self.environment.connection.reconnect(profile: profile)
            self.statusMessage = connected ? "Connection restored." : "Reconnection is still in periodic health-check mode."
            await self.refreshDetails()
        }
    }

    func fixBridge() {
        guard let device = selectedDevice else { return }
        launchTrackedOperation("Run Safe Recovery") { [weak self] in
            guard let self else { return }
            if let serviceHealth = try? await self.daemonClient.recover(deviceID: device.udid) {
                self.health = serviceHealth
            } else {
                guard let profile = await self.environment.registry.profile(for: device.udid) else { return }
                self.health = await self.environment.recovery.fix(device: device, profile: profile)
            }
            self.statusMessage = self.health?.state == .healthy
                ? "The affected bridge component was repaired and verified."
                : "Repair stopped at \(HealthResult.displayName(for: self.health?.firstFailingTransition ?? "an unknown transition"))."
            await self.reloadLogs()
        }
    }

    func serviceAction(_ action: String, service: ServiceManager.Kind) {
        guard let device = selectedDevice else { return }
        let name = "\(action.capitalized) \(service.rawValue)"
        launchTrackedOperation(name) { [weak self] in
            guard let self else { return }
            await self.perform(name) { [environment = self.environment] in
            guard let profile = await environment.registry.profile(for: device.udid) else {
                throw BridgeCoreError.operationFailed("This device has no 0-Sky profile.")
            }
            switch action {
            case "start": return try await environment.services.start(kind: service, profile: profile)
            case "stop": return try await environment.services.stop(kind: service, profile: profile)
            default: return try await environment.services.restart(kind: service, profile: profile)
            }
            }
        }
    }

    func runDiagnostics() {
        // Complete diagnostics always retain and present the verbose,
        // versioned security-method disclosure. A preference must never turn
        // an unmeasured condition into a silent PASS.
        verboseLogging = true
        statusMessage = "Running complete security diagnostics with full disclosure…"
        launchTrackedOperation("Run Diagnostics") { [weak self] in
            await self?.refresh(runHealth: true)
        }
    }

    func manualRefresh() {
        launchTrackedOperation("Refresh Devices and Health") { [weak self] in
            await self?.refresh(runHealth: true)
        }
    }

    func addressRequiredAction() {
        verboseLogging = true
        runDiagnostics()
    }

    func clearLogs() {
        launchTrackedOperation("Clear Logs") { [weak self] in
            guard let self else { return }
            var serviceWarning: String?
            do {
                // Ask the persistent owner to close out its in-memory view and
                // clear shared files first, then clear this GUI client's view.
                try await self.daemonClient.clearLogs()
            } catch {
                // The shared files and GUI view can still be safely cleared if
                // the persistent service is temporarily unavailable.
                serviceWarning = DiagnosticRedactor.redact(error.localizedDescription)
            }
            do {
                await self.environment.logs.clear()
                _ = try await self.environment.structuredLog.clear()
                self.logEntries = []
                self.statusMessage = serviceWarning == nil
                    ? "0-Sky Bridge logs cleared. Research-session evidence was preserved."
                    : "Local logs cleared; the persistent service was unavailable. Research-session evidence was preserved."
            } catch {
                self.lastError = "Could not clear 0-Sky Bridge logs: \(DiagnosticRedactor.redact(error.localizedDescription))"
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
            statusMessage = "0-Sky Requirements Installer opened in Terminal. It installs Python 3.12, dpkg, USB tools, and the pinned environment; status refreshes automatically."
        } catch {
            lastError = "Could not open dependency installer: \(error.localizedDescription)"
        }
    }

    func cancelCurrentOperations() {
        guard let token = activeOperationToken else {
            Task { await environment.runner.cancelAll() }
            isBusy = false
            statusMessage = "No active operation remains."
            return
        }
        cancellationInProgress = true
        if iosSetupActive {
            appendIOSSetupProgress("Cancellation requested; stopping the owned setup process…")
        }
        statusMessage = "Stopping \(activeOperationName ?? "active operation")…"
        activeOperationTask?.cancel()
        Task { [weak self] in
            guard let self else { return }
            await self.environment.runner.cancelAll()
            try? await Task.sleep(for: .seconds(3))
            guard self.activeOperationToken == token else { return }
            self.forceStopCurrentOperation()
        }
    }

    func forceStopCurrentOperation() {
        activeOperationTask?.cancel()
        activeOperationTask = nil
        activeOperationToken = nil
        let name = activeOperationName ?? "Operation"
        activeOperationName = nil
        activeOperationStartedAt = nil
        cancellationInProgress = false
        isBusy = false
        if iosSetupActive {
            iosSetupActive = false
            iosSetupError = "Setup was stopped by the user. No evidence or prior session data was removed."
            appendIOSSetupProgress("Setup force-stopped by the user.")
        }
        statusMessage = "\(name) stopped. Owned processes are being terminated."
        Task { await environment.runner.cancelAll() }
    }

    func checkCoreDevice() {
        launchTrackedOperation("Check CoreDevice") { [weak self] in
            guard let self else { return }
            await self.perform("Check CoreDevice") { [environment = self.environment] in
                try await environment.researcher.checkCoreDevice()
            }
        }
    }

    func checkDeveloperServices() {
        launchTrackedOperation("Check Developer Services") { [weak self] in
            guard let self else { return }
            await self.perform("Check Developer Services") { [environment = self.environment] in
                try await environment.researcher.checkDeveloperServices()
            }
        }
    }

    func checkRemoteXPC() {
        guard let device = selectedDevice else { return }
        launchTrackedOperation("Check RemoteXPC") { [weak self] in
            guard let self else { return }
            await self.perform("Check RemoteXPC") { [environment = self.environment] in
            guard let profile = await environment.registry.profile(for: device.udid) else {
                throw BridgeCoreError.operationFailed("This device has no 0-Sky profile.")
            }
            return try await environment.researcher.checkRemoteXPC(profile: profile)
            }
        }
    }

    func testDevicePorts() {
        guard let device = selectedDevice else { return }
        launchTrackedOperation("Test Device Ports") { [weak self] in
            guard let self else { return }
            await self.perform("Test Device Ports") { [environment = self.environment] in
            guard let profile = await environment.registry.profile(for: device.udid) else {
                throw BridgeCoreError.operationFailed("This device has no 0-Sky profile.")
            }
            return await environment.researcher.testForwardedPort(profile: profile)
            }
        }
    }

    func restartDiscovery() {
        launchTrackedOperation("Restart Device Discovery") { [weak self] in
            guard let self else { return }
            let start = Date()
            await self.refresh(runHealth: false)
            self.operations.append(BridgeOperationResult(
                identifier: "research.restart-discovery",
                startedAt: start, finishedAt: Date(), exitCode: 0,
                stdout: "Discovery backends reran and normalized \(self.devices.count) device record(s).\n",
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
        launchTrackedOperation("Export Diagnostic Report") { [weak self] in
            guard let self else { return }
            do {
                let pairingObject: [String: String] = self.health.map {
                    ["state": $0.state.rawValue,
                     "firstFailingTransition": $0.firstFailingTransition ?? ""]
                } ?? [:]
                let networkObject: [String: String] = self.selectedDevice.map {
                    ["connection": $0.connection.rawValue,
                     "usbConnected": String($0.usbConnected),
                     "wifiConnected": String($0.wifiConnected),
                     "localForwardPort": $0.localPort.map(String.init) ?? ""]
                } ?? [:]
                let location = try await self.environment.diagnostics.export(
                    host: self.host, device: self.selectedDevice, services: self.services,
                    pairing: pairingObject, network: networkObject, health: self.health,
                    srdHealth: self.srdHealthReport,
                    logs: self.logEntries, operations: self.operations
                )
                NSWorkspace.shared.activateFileViewerSelecting([location])
                self.statusMessage = "Diagnostic report exported."
            } catch { self.lastError = error.localizedDescription }
        }
    }

    func startResearchSession(name: String = "research") {
        guard let device = selectedDevice else { return }
        launchTrackedOperation("Start Research Session") { [weak self] in
            guard let self else { return }
            do {
                let session: ResearchSession
                if self.bridgeServiceStatus == "Connected" {
                    session = try await self.daemonClient.startResearchSession(name: name, deviceID: device.udid)
                } else {
                    session = try await self.environment.sessions.start(
                        name: name, device: device, host: self.host,
                        toolVersions: ["bridge": self.host.bridgeVersion],
                        researchConfiguration: ["automatic_reconnect": String(self.automaticReconnect)]
                    )
                }
                self.activeResearchSession = session
                self.statusMessage = "Research session recording started."
            } catch { self.lastError = error.localizedDescription }
        }
    }

    func stopResearchSession() {
        launchTrackedOperation("Stop Research Session") { [weak self] in
            guard let self else { return }
            do {
                let directory = self.bridgeServiceStatus == "Connected"
                    ? try await self.daemonClient.stopResearchSession()
                    : try await self.environment.sessions.stop()
                self.lastResearchSessionDirectory = directory
                self.activeResearchSession = nil
                self.statusMessage = "Research session stopped and evidence hashes generated."
            } catch { self.lastError = error.localizedDescription }
        }
    }

    func exportResearchBundle(profile: EvidenceExportProfile = .vendorDisclosure) {
        guard let directory = lastResearchSessionDirectory else {
            lastError = "Stop a research session before exporting it."
            return
        }
        launchTrackedOperation("Export Research Bundle") { [weak self] in
            guard let self else { return }
            do {
                let archive = self.bridgeServiceStatus == "Connected"
                    ? try await self.daemonClient.exportLastResearchSession(profile: profile)
                    : try await self.environment.sessions.export(sessionDirectory: directory, profile: profile)
                NSWorkspace.shared.activateFileViewerSelecting([archive])
                self.statusMessage = "Research evidence bundle exported."
            } catch { self.lastError = error.localizedDescription }
        }
    }

    private func perform(
        _ displayName: String,
        operation: @escaping @Sendable () async throws -> BridgeOperationResult
    ) async {
        lastError = nil
        statusMessage = "\(displayName)…"
        do {
            let result = try await operation()
            operations.append(result)
            statusMessage = result.succeeded ? "\(displayName) completed." : "\(displayName) failed."
            if !result.succeeded { lastError = DiagnosticRedactor.redact(result.stderr) }
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
