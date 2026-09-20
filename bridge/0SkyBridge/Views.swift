import BridgeCore
import SwiftUI
import AppKit

struct DashboardView: View {
    @ObservedObject var model: BridgeAppModel
    let addressRequiredAction: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                StatusHero(
                    title: "0-Sky Bridge",
                    status: model.overallReady ? "CONNECTED" : "ACTION REQUIRED",
                    detail: model.overallReady
                        ? "Device transport, trust, SSH, 0-Sky Link, and 0-Sky Control are verified."
                        : (model.requiredActionResult?.rootCause
                            ?? model.health?.rootCause
                            ?? "\(model.requiredActionResult?.displayName ?? "A required component") needs attention."),
                    ready: model.overallReady,
                    action: addressRequiredAction
                )
                if model.defaultCredentialsDetected {
                    DefaultCredentialsWarning(model: model, action: addressRequiredAction)
                }
                LazyVGrid(columns: [.init(.adaptive(minimum: 300), spacing: 16)], spacing: 16) {
                    HostCard(model: model)
                    DeviceCard(device: model.selectedDevice)
                    HealthCard(snapshot: model.health, report: model.srdHealthReport)
                    ConnectionCard(metrics: model.connectionMetrics)
                    FirstFailureCard(snapshot: model.health, report: model.srdHealthReport)
                    RecoveryCard(model: model)
                    ResearchSessionCard(model: model)
                    ServiceCard(services: model.services)
                    IntegrationCard(device: model.selectedDevice)
                    DependencyCard(model: model)
                }
                HStack {
                    Button("Fix Bridge") { model.fixBridge() }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .disabled(model.isBusy || model.selectedDevice == nil)
                    Button("Reconnect") { model.reconnect() }
                        .controlSize(.large)
                    Button("Run Diagnostics") { model.runDiagnostics() }
                        .controlSize(.large)
                    Button("Set Up iOS Components") { model.openSetupAssistant(step: 7) }
                        .controlSize(.large)
                        .disabled(model.selectedDevice == nil)
                    Spacer()
                    Text(DiagnosticRedactor.redact(model.statusMessage)).foregroundStyle(.secondary)
                }
            }
            .padding(24)
        }
        .navigationTitle("Dashboard")
    }
}

struct StatusHero: View {
    let title: String
    let status: String
    let detail: String
    let ready: Bool
    let action: () -> Void
    var body: some View {
        HStack(spacing: 18) {
            Image(systemName: ready ? "link.circle.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 44))
                .foregroundStyle(ready ? .green : .orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.largeTitle.bold())
                Text(status).font(.title2.bold()).foregroundStyle(ready ? .green : .orange)
                Text(detail).foregroundStyle(.secondary).textSelection(.enabled)
            }
            Spacer()
            if !ready {
                Button("Address Required Action", systemImage: "arrow.right.circle.fill", action: action)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
            }
        }
        .padding(22)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
    }
}

struct Card<Content: View>: View {
    let title: String
    let icon: String
    @ViewBuilder let content: Content
    init(_ title: String, icon: String, @ViewBuilder content: () -> Content) {
        self.title = title; self.icon = icon; self.content = content()
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: icon).font(.headline)
            Divider()
            content
            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 180, alignment: .topLeading)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
    }
}

struct KeyValue: View {
    let key: String
    let value: String
    init(_ key: String, _ value: String) { self.key = key; self.value = value }
    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(key).foregroundStyle(.secondary)
            Spacer()
            Text(value).fontDesign(.monospaced).textSelection(.enabled)
        }.font(.callout)
    }
}

struct HostCard: View {
    @ObservedObject var model: BridgeAppModel
    var body: some View {
        Card("Host", icon: "desktopcomputer") {
            KeyValue("Mac", model.host.computerName)
            KeyValue("macOS", model.host.osVersion)
            KeyValue("Architecture", model.host.architecture)
            KeyValue("Bridge Version", model.host.bridgeVersion)
            KeyValue("Bridge Service", model.bridgeServiceStatus)
            KeyValue("Privileged Helper", model.host.helperState)
        }
    }
}

struct DeviceCard: View {
    let device: SkyDevice?
    var body: some View {
        Card("Current Device", icon: "iphone") {
            if let device {
                KeyValue("Name", device.name ?? "Unknown")
                KeyValue("Product Type", device.productType ?? "Unknown")
                KeyValue("UDID", device.udid)
                KeyValue("OS", device.osVersion ?? "Unknown")
                KeyValue("Build", device.buildVersion ?? "Unknown")
                KeyValue("Connection", device.connection.rawValue)
            } else { Text("No device selected").foregroundStyle(.secondary) }
        }
    }
}

struct HealthCard: View {
    let snapshot: BridgeHealthSnapshot?
    var report: SRDHealthReport? = nil
    var body: some View {
        Card("SRD Health", icon: "heart.text.square") {
            KeyValue("State", snapshot?.state.rawValue ?? "UNKNOWN")
            KeyValue("Research Readiness", report?.readiness.rawValue ?? snapshot?.readiness.rawValue ?? "UNKNOWN")
            ForEach(snapshot?.checks.prefix(5).map { $0 } ?? []) { check in
                HStack {
                    Image(systemName: check.state == .pass ? "checkmark.circle.fill" :
                            (check.state == .fail ? "xmark.circle.fill" : "minus.circle"))
                        .foregroundStyle(check.state == .pass ? .green :
                                (check.state == .fail ? .red : .secondary))
                    Text(HealthResult.displayName(for: check.transition)).font(.caption)
                }
            }
        }
    }
}

struct ConnectionCard: View {
    let metrics: ConnectionMetrics?
    var body: some View {
        Card("Connection", icon: "network") {
            KeyValue("Primary", metrics?.primary.rawValue ?? "UNKNOWN")
            KeyValue("Fallback", metrics?.fallback.rawValue ?? "NONE")
            KeyValue("USB", metrics?.usb.rawValue ?? "UNKNOWN")
            KeyValue("Wi-Fi", metrics?.wifi.rawValue ?? "UNKNOWN")
            KeyValue("SSH", metrics?.ssh.rawValue ?? "UNKNOWN")
            KeyValue("RemoteXPC", metrics?.remoteXPC.rawValue ?? "UNKNOWN")
            KeyValue("Reconnect Count", metrics.map { String($0.reconnectCount) } ?? "0")
        }
    }
}

struct FirstFailureCard: View {
    let snapshot: BridgeHealthSnapshot?
    var report: SRDHealthReport? = nil
    var body: some View {
        Card("First Failure", icon: "arrow.triangle.branch") {
            KeyValue(
                "Transition",
                HealthResult.displayName(
                    for: report?.analysis.firstFailingTransition
                        ?? snapshot?.firstFailingTransition
                        ?? "None"
                )
            )
            Text(report?.analysis.primaryRootCause ?? snapshot?.rootCause ?? "No upstream failure has been identified.")
                .font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
            if let dependent = report?.analysis.dependentFailures ?? snapshot?.dependentFailures, !dependent.isEmpty {
                Text("Dependent failures: \(dependent.map(HealthResult.displayName(for:)).joined(separator: ", "))")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

struct ResearchSessionCard: View {
    @ObservedObject var model: BridgeAppModel
    var body: some View {
        Card("Research Session", icon: "record.circle") {
            KeyValue("Recording", model.activeResearchSession == nil ? "NO" : "YES")
            if let session = model.activeResearchSession {
                KeyValue("Session", session.id.uuidString)
                Button("Stop Research Session") { model.stopResearchSession() }
                    .buttonStyle(.borderedProminent)
            } else {
                Button("Start Research Session") { model.startResearchSession() }
                    .buttonStyle(.borderedProminent)
                Button("Export Research Bundle") { model.exportResearchBundle() }
                    .disabled(model.lastResearchSessionDirectory == nil)
            }
        }
    }
}

struct RecoveryCard: View {
    @ObservedObject var model: BridgeAppModel
    var body: some View {
        Card("Recovery", icon: "wrench.and.screwdriver") {
            KeyValue("Repair Tier", "Tier 1 — Automatically Safe")
            KeyValue("Retry Policy", "Bounded / cooldown")
            Text("Only 0-Sky-owned forwarding, workers, discovery, RemoteXPC, Wi-Fi, and SSH are repaired automatically.")
                .font(.caption).foregroundStyle(.secondary)
            Button("Run Safe Recovery") { model.fixBridge() }
                .buttonStyle(.borderedProminent)
                .disabled(model.isBusy || model.selectedDevice == nil)
            Text("Tier 2 requires confirmation. Tier 3 is never automatic.")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }
}

struct ServiceCard: View {
    let services: [ServiceStatus]
    var body: some View {
        Card("Services", icon: "gearshape.2") {
            if services.isEmpty { Text("Not checked").foregroundStyle(.secondary) }
            ForEach(services) { service in
                HStack {
                    Circle().fill(service.state == "running" ? .green : .red).frame(width: 8, height: 8)
                Text(DiagnosticRedactor.redact(
                    service.label.components(separatedBy: ".crypstore-").last ?? service.label
                ))
                        .lineLimit(1).font(.caption)
                    Spacer()
                    Text(service.state.uppercased()).font(.caption2.bold())
                }
            }
        }
    }
}

struct IntegrationCard: View {
    let device: SkyDevice?
    var body: some View {
        Card("0-Sky Integration", icon: "point.3.connected.trianglepath.dotted") {
            KeyValue("0-Sky Link", device?.linkReachable == true ? "Running" : "Unknown")
            KeyValue("Control Installed", device?.controlInstalled == true ? "YES" : "Unknown")
            KeyValue("Control Running", device?.controlRunning == true ? "YES" : "Unknown")
            KeyValue("Control Reachable", device?.controlReachable == true ? "YES" : "Unknown")
            KeyValue("Control Version", device?.controlVersion ?? "Unknown")
        }
    }
}

struct DependencyCard: View {
    @ObservedObject var model: BridgeAppModel
    var body: some View {
        Card("Dependencies", icon: "shippingbox") {
            ForEach(model.dependencies.prefix(8)) { dependency in
                HStack {
                    Image(systemName: dependency.available ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundStyle(dependency.available ? .green : (dependency.required ? .red : .orange))
                    Text(dependency.name).font(.caption)
                    Spacer()
                }
            }
            if model.hasMissingDependencies {
                Button("Install Missing Dependencies") {
                    model.installMissingDependencies()
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isBusy)
            }
        }
    }
}

struct DevicesView: View {
    @ObservedObject var model: BridgeAppModel
    let addressRequiredAction: () -> Void
    @State private var confirmHostKeyRepair = false
    var body: some View {
        HSplitView {
            List(model.devices, selection: Binding(
                get: { model.selectedDeviceID }, set: { model.select($0) }
            )) { device in
                VStack(alignment: .leading) {
                    Text(device.name ?? device.productType ?? "Apple Device").font(.headline)
                    Text(device.udid).font(.caption.monospaced()).foregroundStyle(.secondary)
                    Text(device.connection.rawValue).font(.caption2.bold())
                }
                .tag(device.udid)
                .contextMenu {
                    DeviceContextActions(
                        model: model,
                        device: device,
                        openDetails: { model.select(device.udid) },
                        addressIssues: {
                            model.select(device.udid)
                            addressRequiredAction()
                        },
                        requestHostKeyRepair: {
                            model.select(device.udid)
                            confirmHostKeyRepair = true
                        }
                    )
                }
            }.frame(minWidth: 300)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let device = model.selectedDevice {
                        Text(device.name ?? "Device").font(.largeTitle.bold())
                        if model.defaultCredentialsDetected {
                            DefaultCredentialsWarning(model: model, action: addressRequiredAction)
                        }
                        DeviceCard(device: device)
                        PairingWorkflowView(steps: model.pairingWorkflow)
                        HealthDetails(snapshot: model.health)
                        HStack {
                            if !model.selectedHasProfile {
                                Button("Set Up New Device") { model.enrollSelectedDevice() }
                                    .buttonStyle(.borderedProminent)
                            }
                            Button("Pair Device") { model.pairDevice() }
                                .disabled(!model.selectedHasProfile)
                            Button("Verify Pairing") { model.verifyPairing() }
                                .disabled(!model.selectedHasProfile)
                            Button("Repair Pinned Host Key") { confirmHostKeyRepair = true }
                                .disabled(!model.selectedHasProfile || !device.usbConnected)
                            Button("Enable Wi-Fi Pairing") { model.enableWireless() }
                                .disabled(!model.selectedHasProfile)
                            Button("Verify Wi-Fi Connection") { model.verifyWireless() }
                                .disabled(!model.selectedHasProfile)
                            Button("Set Up iOS Components") { model.openSetupAssistant(step: 7) }
                                .buttonStyle(.borderedProminent)
                                .disabled((!model.selectedHasProfile && !device.usbConnected) || model.isBusy)
                            if model.isBusy { Button("Cancel") { model.cancelCurrentOperations() } }
                        }
                    } else { ContentUnavailableView("No Device", systemImage: "iphone.slash") }
                }.padding(24)
            }
        }
        .navigationTitle("Devices")
        .confirmationDialog(
            "Repair this device's pinned SSH host key?",
            isPresented: $confirmHostKeyRepair,
            titleVisibility: .visible
        ) {
            Button("Repair Exact USB Device", role: .destructive) {
                model.repairPinnedHostKey()
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("Use only after confirming the selected UDID is physically connected by USB. Automatic recovery never replaces this trust pin.")
        }
    }
}

struct DeviceContextActions: View {
    @ObservedObject var model: BridgeAppModel
    let device: SkyDevice
    let openDetails: () -> Void
    let addressIssues: () -> Void
    let requestHostKeyRepair: () -> Void

    private var hasProfile: Bool { device.instanceName != nil }

    var body: some View {
        Button("Open Device Details", systemImage: "iphone") { openDetails() }
        Button("Address Device Issues…", systemImage: "wrench.and.screwdriver") {
            addressIssues()
        }
        Button("Run Verbose Diagnostics", systemImage: "stethoscope") {
            addressIssues()
        }
        Divider()
        if !hasProfile {
            Button("Set Up New Device…", systemImage: "plus.circle") {
                openDetails()
                model.enrollSelectedDevice()
            }
        }
        Button("Set Up iOS Components…", systemImage: "shippingbox.and.arrow.backward") {
            model.select(device.udid)
            model.openSetupAssistant(step: 7)
        }
        .disabled((!hasProfile && !device.usbConnected) || model.isBusy)
        Button("Reconnect", systemImage: "arrow.triangle.2.circlepath") {
            model.select(device.udid)
            model.reconnect()
        }
        .disabled(!hasProfile || model.isBusy)
        Button("Run Safe Recovery", systemImage: "cross.case") {
            model.select(device.udid)
            model.fixBridge()
        }
        .disabled(!hasProfile || model.isBusy)
        Divider()
        Button("Pair Device", systemImage: "link") {
            model.select(device.udid)
            model.pairDevice()
        }
        .disabled(!hasProfile || model.isBusy)
        Button("Verify Pairing", systemImage: "checkmark.shield") {
            model.select(device.udid)
            model.verifyPairing()
        }
        .disabled(!hasProfile || model.isBusy)
        Button("Enable Wi-Fi Pairing", systemImage: "wifi") {
            model.select(device.udid)
            model.enableWireless()
        }
        .disabled(!hasProfile || model.isBusy)
        Button("Verify Wi-Fi Connection", systemImage: "wifi.circle") {
            model.select(device.udid)
            model.verifyWireless()
        }
        .disabled(!hasProfile || model.isBusy)
        Divider()
        Button("Repair Pinned Host Key…", systemImage: "key", role: .destructive) {
            requestHostKeyRepair()
        }
        .disabled(!hasProfile || !device.usbConnected || model.isBusy)
    }
}

struct DefaultCredentialsWarning: View {
    @ObservedObject var model: BridgeAppModel
    let action: () -> Void

    private var accountResult: HealthResult? {
        model.srdHealthReport?.results.first(where: {
            $0.name == "DEFAULT_CREDENTIALS" && $0.status == .fail
        })
    }

    private var vncResult: HealthResult? {
        model.srdHealthReport?.results.first(where: {
            $0.name == "VNC_DEFAULT_CREDENTIALS" && $0.status == .fail
        })
    }

    private var affectedTargets: String {
        var values: [String] = []
        if let result = accountResult {
            if result.observed["mobile_default"] == .bool(true) { values.append("mobile") }
            if result.observed["root_default"] == .bool(true) { values.append("root") }
            if values.isEmpty { values.append("mobile/root") }
        }
        if let result = vncResult {
            let initialCount = values.count
            if result.observed["port_5900_open"] == .bool(true) { values.append("VNC :5900") }
            if result.observed["port_5800_open"] == .bool(true) { values.append("HTTP VNC :5800") }
            if values.count == initialCount { values.append("VNC :5900 / HTTP VNC :5800") }
        }
        return values.isEmpty ? "mobile/root or VNC" : values.joined(separator: ", ")
    }

    private var affectedLabel: String {
        if accountResult != nil && vncResult != nil { return "Affected account(s)/service(s)" }
        return vncResult != nil ? "Affected service(s)" : "Affected account(s)"
    }

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "exclamationmark.shield.fill")
                .font(.title).foregroundStyle(.red)
            VStack(alignment: .leading, spacing: 5) {
                Text("Default Credentials Detected").font(.headline).foregroundStyle(.red)
                Text(DefaultCredentialsAdapter.warningMessage)
                    .font(.callout.bold()).textSelection(.enabled)
                Text("\(affectedLabel): \(affectedTargets)")
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Address Security Warning", action: action)
                .buttonStyle(.borderedProminent).tint(.red)
        }
        .padding(16)
        .background(.red.opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(.red.opacity(0.45)))
    }
}

struct PairingWorkflowView: View {
    let steps: [PairingWorkflowStep]
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("New Device Workflow").font(.headline)
            ForEach(steps) { step in
                HStack {
                    Image(systemName: icon(step.state))
                        .foregroundStyle(color(step.state))
                    Text(step.title)
                    Spacer()
                    if step.state == .active { Text("NEXT").font(.caption.bold()).foregroundStyle(.blue) }
                }.font(.callout)
            }
        }
        .padding()
        .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 12))
    }

    private func icon(_ state: PairingWorkflowStep.State) -> String {
        switch state {
        case .complete: "checkmark.circle.fill"
        case .active: "arrow.right.circle.fill"
        case .pending: "circle"
        case .failed: "xmark.circle.fill"
        }
    }
    private func color(_ state: PairingWorkflowStep.State) -> Color {
        switch state {
        case .complete: .green
        case .active: .blue
        case .pending: .secondary
        case .failed: .red
        }
    }
}

struct HealthDetails: View {
    let snapshot: BridgeHealthSnapshot?
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Connection Health").font(.headline)
            ForEach(snapshot?.checks ?? []) { check in
                HStack(alignment: .top) {
                    Text(check.state.rawValue).font(.caption.bold()).frame(width: 70, alignment: .leading)
                    VStack(alignment: .leading) {
                        Text(HealthResult.displayName(for: check.transition)).font(.callout.bold())
                        Text(DiagnosticRedactor.redact(check.detail)).font(.caption).foregroundStyle(.secondary)
                    }
                }.padding(.vertical, 3)
            }
        }.padding().background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 12))
    }
}

struct BridgeControlView: View {
    @ObservedObject var model: BridgeAppModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                Text("Bridge Control").font(.largeTitle.bold())
                GroupBox("Connection") {
                    HStack {
                        Button("Connect") { model.reconnect() }
                        Button("Reconnect") { model.reconnect() }
                        Button("Fix Bridge") { model.fixBridge() }.buttonStyle(.borderedProminent)
                    }.padding(8)
                }
                GroupBox("Services") {
                    VStack(alignment: .leading) {
                        ForEach(ServiceManager.Kind.allCases, id: \.rawValue) { service in
                            HStack {
                                Text(service.rawValue).frame(width: 160, alignment: .leading)
                                Button("Start") { model.serviceAction("start", service: service) }
                                Button("Restart") { model.serviceAction("restart", service: service) }
                                Button("Stop") { model.serviceAction("stop", service: service) }
                            }
                        }
                    }.padding(8)
                }
                GroupBox("Approved Researcher Operations") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Button("Pair Device") { model.pairDevice() }
                            Button("Verify Pairing") { model.verifyPairing() }
                            Button("Enable Wi-Fi") { model.enableWireless() }
                            Button("Test Wi-Fi") { model.verifyWireless() }
                            Button("Run Full Diagnostic") { model.runDiagnostics() }
                        }
                        HStack {
                            Button("Restart USB Forwarding") { model.serviceAction("restart", service: .usbmux) }
                            Button("Restart SSH Forwarding") { model.serviceAction("restart", service: .usbmux) }
                            Button("Restart Device Discovery") { model.restartDiscovery() }
                            Button("Rebuild Connection") { model.fixBridge() }
                        }
                        HStack {
                            Button("Check CoreDevice") { model.checkCoreDevice() }
                            Button("Check RemoteXPC") { model.checkRemoteXPC() }
                            Button("Check Developer Services") { model.checkDeveloperServices() }
                            Button("Test Device Ports") { model.testDevicePorts() }
                            Button("Export Diagnostics") { model.exportDiagnostics() }
                        }
                        if model.isBusy {
                            Button("Cancel Active Operation") { model.cancelCurrentOperations() }
                                .tint(.red)
                        }
                    }.padding(8)
                }
                GroupBox("Researcher Console") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Button("Copy Output") { model.copyOperationOutput() }
                            Button("Save Output") { model.saveOperationOutput() }
                            Spacer()
                            Text("\(model.operations.count) operation(s)").foregroundStyle(.secondary)
                        }
                        ForEach(Array(model.operations.suffix(20).enumerated()), id: \.offset) { _, operation in
                            DisclosureGroup("\(operation.identifier) — exit \(operation.exitCode) — \(operation.duration, specifier: "%.2f")s") {
                                VStack(alignment: .leading, spacing: 5) {
                                    KeyValue("Started", operation.startedAt.ISO8601Format())
                                    Text("stdout").font(.caption.bold())
                                    Text(operation.stdout.isEmpty ? "(empty)" : DiagnosticRedactor.redact(operation.stdout))
                                        .font(.caption.monospaced()).textSelection(.enabled)
                                    Text("stderr").font(.caption.bold())
                                    Text(operation.stderr.isEmpty ? "(empty)" : DiagnosticRedactor.redact(operation.stderr))
                                        .font(.caption.monospaced()).textSelection(.enabled)
                                }.padding(.vertical, 6)
                            }
                        }
                    }.padding(8)
                }
                Text("Operations are executed as approved argument arrays. Arbitrary shell entry is not exposed.")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(24)
        }.navigationTitle("Bridge")
    }
}

struct DiagnosticsView: View {
    @ObservedObject var model: BridgeAppModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Diagnostics").font(.largeTitle.bold())
                HStack {
                    Button("Run Diagnostics") { model.runDiagnostics() }.buttonStyle(.borderedProminent)
                    Button("Export Diagnostic Report") { model.exportDiagnostics() }
                    Toggle("Verbose Output", isOn: $model.verboseLogging)
                        .toggleStyle(.switch)
                        .fixedSize()
                }
                RequiredActionDetail(model: model)
                if let health = model.health {
                    KeyValue(
                        "FIRST_FAILING_TRANSITION",
                        health.firstFailingTransition.map(HealthResult.displayName(for:)) ?? ""
                    )
                    KeyValue("ROOT_CAUSE", health.rootCause ?? "")
                    KeyValue("RECOMMENDED_ACTION", health.recommendedAction ?? "")
                    HealthDetails(snapshot: health)
                } else {
                    ContentUnavailableView("No Diagnostic Result", systemImage: "stethoscope")
                }
            }.padding(24)
        }.navigationTitle("Diagnostics")
    }
}

struct RequiredActionDetail: View {
    @ObservedObject var model: BridgeAppModel

    var body: some View {
        GroupBox {
            if let result = model.requiredActionResult {
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Label("Action Required", systemImage: "exclamationmark.triangle.fill")
                            .font(.title2.bold()).foregroundStyle(.orange)
                        Spacer()
                        Text(result.status.rawValue)
                            .font(.caption.bold()).padding(.horizontal, 9).padding(.vertical, 4)
                            .background(.orange.opacity(0.16), in: Capsule())
                    }
                    KeyValue("Component", result.displayName)
                    KeyValue("Severity", result.severity.rawValue)
                    KeyValue("Checked", result.checkedAt.ISO8601Format())
                    if let kind = result.failureKind {
                        KeyValue("Failure Type", kind.rawValue)
                    }
                    Divider()
                    Text("What failed").font(.headline)
                    Text(DiagnosticRedactor.redact(
                        result.rootCause
                            ?? model.srdHealthReport?.analysis.primaryRootCause
                            ?? model.health?.rootCause
                            ?? "The component did not reach its expected state."
                    ))
                    .textSelection(.enabled)
                    Text("Expected").font(.headline)
                    Text(DiagnosticRedactor.redact(result.expected))
                        .foregroundStyle(.secondary).textSelection(.enabled)
                    if !result.remediation.isEmpty {
                        Text("Recommended action").font(.headline)
                        ForEach(Array(result.remediation.enumerated()), id: \.offset) { _, action in
                            Label(DiagnosticRedactor.redact(action), systemImage: "arrow.right")
                                .textSelection(.enabled)
                        }
                    }
                    HStack {
                        if model.canSafelyRecoverRequiredAction {
                            Button("Run Safe Recovery") { model.fixBridge() }
                                .buttonStyle(.borderedProminent)
                                .disabled(model.isBusy || model.selectedDevice == nil)
                        }
                        Button("Run Diagnostics Again") { model.runDiagnostics() }
                            .disabled(model.isBusy)
                    }
                    if model.verboseLogging {
                        VerboseHealthOutput(result: result, model: model)
                    }
                }.padding(8)
            } else if model.isBusy {
                HStack { ProgressView(); Text("Running detailed diagnostics…") }
                    .padding(8)
            } else {
                Label("No failing transition is currently identified.", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green).padding(8)
            }
        } label: {
            Label("Required Action", systemImage: "scope")
        }
    }
}

private struct VerboseHealthOutput: View {
    let result: HealthResult
    @ObservedObject var model: BridgeAppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider()
            Label("Verbose Diagnostic Output", systemImage: "text.alignleft")
                .font(.headline)
            if result.observed.isEmpty {
                Text("No structured observations were returned.")
                    .foregroundStyle(.secondary)
            } else {
                GroupBox("Observed") {
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(result.observed.keys.sorted(), id: \.self) { key in
                            KeyValue(key, renderJSON(result.observed[key] ?? .null))
                        }
                    }.padding(6)
                }
            }
            if !result.rawEvidence.isEmpty {
                GroupBox("Raw Evidence") {
                    Text(result.rawEvidence.map(DiagnosticRedactor.redact).joined(separator: "\n---\n"))
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(6)
                }
            }
            if !model.logEntries.isEmpty {
                GroupBox("Recent Structured Logs") {
                    Text(model.logEntries.suffix(20).map {
                        "\($0.timestamp.ISO8601Format()) [\($0.level.rawValue)] \(DiagnosticRedactor.redact($0.message))"
                    }.joined(separator: "\n"))
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }
            }
        }
    }

    private func renderJSON(_ value: JSONValue) -> String {
        switch value {
        case .string(let item): return DiagnosticRedactor.redact(item)
        case .number(let item): return String(item)
        case .bool(let item): return item ? "true" : "false"
        case .null: return "null"
        case .array(let items): return "[" + items.map(renderJSON).joined(separator: ", ") + "]"
        case .object(let values):
            return "{" + values.keys.sorted().map {
                "\($0): \(renderJSON(values[$0] ?? .null))"
            }.joined(separator: ", ") + "}"
        }
    }
}

struct LogsView: View {
    @ObservedObject var model: BridgeAppModel
    @State private var confirmingClear = false
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Structured Logs").font(.largeTitle.bold())
                Spacer()
                Button("Copy Output") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(model.logEntries.map {
                        "\($0.timestamp.ISO8601Format()) \($0.category.rawValue.uppercased()) \($0.level.rawValue) \(DiagnosticRedactor.redact($0.message))"
                    }.joined(separator: "\n"), forType: .string)
                }
                Button("Clear Logs", systemImage: "trash", role: .destructive) {
                    confirmingClear = true
                }
                .disabled(model.isBusy)
            }.padding([.horizontal, .top], 24)
            Table(model.logEntries) {
                TableColumn("Time") { Text($0.timestamp, style: .time).font(.caption.monospaced()) }
                TableColumn("Category") { Text($0.category.rawValue.uppercased()).font(.caption.bold()) }
                TableColumn("Level") { Text($0.level.rawValue).font(.caption.bold()) }
                TableColumn("Message") { Text(DiagnosticRedactor.redact($0.message)).textSelection(.enabled) }
            }
        }
        .navigationTitle("Logs")
        .confirmationDialog(
            "Clear 0-Sky Bridge Logs?",
            isPresented: $confirmingClear,
            titleVisibility: .visible
        ) {
            Button("Clear Logs", role: .destructive) { model.clearLogs() }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("This clears the app log view and 0-Sky-owned rotating bridge logs. Research-session evidence and exported bundles are preserved.")
        }
    }
}

struct SettingsView: View {
    @ObservedObject var model: BridgeAppModel
    var body: some View {
        Form {
            Section("General") {
                Text("0-Sky Bridge monitors authorized SRDs continuously and remains active in the menu bar when its window closes.")
                Toggle("Start 0-Sky Bridge at login", isOn: Binding(
                    get: { model.startAtLogin },
                    set: { model.setStartAtLogin($0) }
                ))
                Toggle("Automatically reconnect devices", isOn: $model.automaticReconnect)
                Button("Open Setup Assistant") { model.openSetupAssistant() }
                if model.hasMissingDependencies {
                    Button("Install Missing Dependencies") { model.installMissingDependencies() }
                }
            }
            Section("Devices") {
                KeyValue("Known devices", String(model.devices.count))
                Text("Each device retains an independent UDID, host-key pin, forwarding port, services, logs and diagnostics.")
            }
            Section("Bridge") {
                KeyValue("Privileged Helper", model.host.helperState)
                Button("Register Privileged Helper") { model.registerPrivilegedHelper() }
                Button("Restart Selected Bridge") { model.serviceAction("restart", service: .deviceBridge) }
                    .disabled(model.selectedDevice == nil)
            }
            Section("Wireless") {
                Text("Initial trust requires USB. Wireless and Bluetooth reconnects retain the same enrolled Mac and device identities.")
                Button("Enable Wi-Fi for Selected Device") { model.enableWireless() }
                    .disabled(model.selectedDevice == nil)
                Button("Verify Wi-Fi Connection") { model.verifyWireless() }
                    .disabled(model.selectedDevice == nil)
            }
            Section("SSH") {
                Text("SSH uses the per-device known-hosts pin, HostKeyAlias, key-only authentication and BatchMode. Password fallback is disabled.")
            }
            Section("Diagnostics") {
                Toggle("Enable verbose logging", isOn: $model.verboseLogging)
                Button("Run Diagnostics") { model.runDiagnostics() }
                Button("Export Diagnostic Report") { model.exportDiagnostics() }
            }
            Section("Security") {
                Text("Passwords, bridge tokens, private keys, and Keychain contents are excluded from configuration and diagnostic exports.")
            }
            Section("Advanced") {
                Text("Per-device operations are serialized. Different devices may run independent operations concurrently.")
            }
        }.formStyle(.grouped).padding().navigationTitle("Settings")
    }
}

struct SetupAssistantView: View {
    @ObservedObject var model: BridgeAppModel
    @Environment(\.dismiss) private var dismiss
    @State private var step: Int
    @State private var confirmIOSComponentSetup = false
    private let steps = [
        "Mac Compatibility", "Required Components", "Bridge Services",
        "Connect Device", "Trust Mac", "Pair Device", "Enable Wireless Pairing",
        "Set Up iOS Components", "Verify 0-Sky Link", "Verify 0-Sky Control", "Complete",
    ]

    init(model: BridgeAppModel) {
        self.model = model
        _step = State(initialValue: max(0, min(10, model.setupAssistantStartStep)))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Welcome to 0-Sky Bridge").font(.largeTitle.bold())
            ProgressView(value: Double(step + 1), total: Double(steps.count))
            Text("Step \(step + 1) of \(steps.count)")
                .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            Label(steps[step], systemImage: "\(step + 1).circle.fill").font(.title2)
            Text(instruction).foregroundStyle(.secondary)
            if step == 1 && model.hasMissingDependencies {
                Button("Install Missing Dependencies") { model.installMissingDependencies() }
                    .buttonStyle(.borderedProminent)
                Text("The installer opens in Terminal so Homebrew and Apple can display their normal prompts.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if step == 7 {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(model.requiredIOSComponentPlan.components, id: \.self) { component in
                        Label(component, systemImage: "shippingbox")
                            .font(.callout)
                    }
                    Button(model.selectedHasProfile
                           ? "Install Complete 0-Sky iOS Project…"
                           : "Enroll New Device and Install Complete Project…") {
                        confirmIOSComponentSetup = true
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.selectedDevice == nil
                              || (!model.selectedHasProfile
                                  && model.selectedDevice?.usbConnected != true)
                              || model.iosSetupActive
                              || model.isBusy)
                    if confirmIOSComponentSetup && !model.iosSetupActive {
                        VStack(alignment: .leading, spacing: 8) {
                            Label("Confirm complete project installation",
                                  systemImage: "exclamationmark.shield.fill")
                                .font(.callout.bold()).foregroundStyle(.orange)
                            Text("This installs or converges SRDssh/Procursus, 0-Sky Link, 0-Sky Control, ElleKit, Runtime Manager, PreferenceLoader, Frida 17.18.0, research runtime Cryptexes, CatVNC, Filza, and exact-build app registration support. A new SRD may reboot once.")
                                .font(.caption).foregroundStyle(.secondary)
                            HStack {
                                Button("Begin Confirmed Setup") {
                                    confirmIOSComponentSetup = false
                                    model.setupCompleteIOSProject()
                                }
                                .buttonStyle(.borderedProminent)
                                Button("Cancel", role: .cancel) {
                                    confirmIOSComponentSetup = false
                                }
                            }
                        }
                        .padding(10)
                        .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                    }
                    if model.iosSetupActive {
                        HStack(spacing: 10) {
                            ProgressView().controlSize(.small)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Setup is running").font(.callout.bold())
                                Text(model.iosSetupProgress.last ?? "Starting verified setup controller…")
                                    .font(.caption).foregroundStyle(.secondary)
                                    .lineLimit(2).textSelection(.enabled)
                            }
                            Spacer()
                            Button("Cancel Setup", role: .destructive) {
                                model.cancelCurrentOperations()
                            }
                            Button("Force Stop & Close", role: .destructive) {
                                model.forceStopCurrentOperation()
                                dismiss()
                            }
                        }
                    }
                    if !model.iosSetupProgress.isEmpty {
                        DisclosureGroup("Verbose Setup Output (\(model.iosSetupProgress.count) lines)") {
                            ScrollView {
                                Text(model.iosSetupProgress.joined(separator: "\n"))
                                    .font(.caption.monospaced())
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .frame(maxHeight: 150)
                        }
                    }
                    if let error = model.iosSetupError {
                        Label(DiagnosticRedactor.redact(error), systemImage: "xmark.octagon.fill")
                            .font(.caption).foregroundStyle(.red).textSelection(.enabled)
                    } else if model.iosSetupCompleted {
                        Label("Complete project installation passed. A health refresh is running separately.",
                              systemImage: "checkmark.circle.fill")
                            .font(.caption).foregroundStyle(.green)
                    }
                    Text("Explicit confirmation required — first setup may install research Cryptexes and reboot the selected SRD. Installs 0-Sky Link, 0-Sky Control, SRDssh/Procursus, the complete runtime, Frida 17.18.0, CatVNC, Filza, and exact-build app registration support. Existing newer packages are preserved.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(12)
                .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 10))
            }
            Spacer()
            HStack {
                Button("Back") { step = max(0, step - 1) }.disabled(step == 0)
                Spacer()
                Button(step == steps.count - 1 ? "Done" : "Continue") {
                    if step == steps.count - 1 { dismiss() } else { step += 1 }
                }.buttonStyle(.borderedProminent)
            }
        }
        .padding(30).frame(width: 760, height: 650)
    }
    private var instruction: String {
        switch step {
        case 0: "0-Sky Bridge requires macOS 15 or later and Apple developer services for SRD workflows."
        case 1: "Select Install Missing Dependencies to add only missing Homebrew tools and the pinned offline Python environment. Installed components are preserved."
        case 2: "The app inspects instance-scoped USB, worker, bridge, and Bluetooth services."
        case 3: "Connect and unlock an authorized iPhone or iPad. Discovery runs continuously."
        case 4: "Approve this Mac using Apple's normal Trust This Computer and Developer Paired Macs workflows."
        case 5: "Use Pair Device. The operation binds Apple trust, the exact UDID, and pinned SSH identity."
        case 6: "Enable wireless pairing while USB remains connected."
        case 7: "Install the complete device-side 0-Sky Project—including Link and Control—with one reviewed, instance-scoped operation. Detailed output is retained in the researcher console and logs."
        case 8: "0-Sky Link is verified over the authenticated, pinned device connection."
        case 9: "0-Sky Control installation, process state, and reachability are checked separately."
        default: "Setup is complete only when every mandatory Dashboard health transition reports PASS."
        }
    }
}
