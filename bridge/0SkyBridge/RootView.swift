import BridgeCore
import SwiftUI

enum BridgeSection: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case devices = "Devices"
    case bridge = "Bridge"
    case diagnostics = "Diagnostics"
    case logs = "Logs"
    case settings = "Settings"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .dashboard: "square.grid.2x2"
        case .devices: "iphone.and.arrow.forward"
        case .bridge: "point.3.connected.trianglepath.dotted"
        case .diagnostics: "stethoscope"
        case .logs: "doc.text.magnifyingglass"
        case .settings: "gearshape"
        }
    }
}

struct RootView: View {
    @ObservedObject var model: BridgeAppModel
    @State private var section: BridgeSection? = .dashboard
    @State private var pendingHostKeyRepairDeviceID: String?
    @State private var pendingDeviceRemoval: SkyDevice?

    var body: some View {
        NavigationSplitView {
            List(selection: $section) {
                Section("0-Sky Bridge") {
                    ForEach(BridgeSection.allCases) { item in
                        Label(item.rawValue, systemImage: item.icon).tag(item)
                    }
                }
                Section("Devices") {
                    ForEach(model.devices) { device in
                        Button {
                            model.select(device.udid)
                            section = .devices
                        } label: {
                            HStack {
                                Image(systemName: device.productType?.hasPrefix("iPad") == true ? "ipad" : "iphone")
                                VStack(alignment: .leading) {
                                    Text(device.name ?? device.productType ?? "Apple Device")
                                    Text(device.bridgeState.rawValue)
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .buttonStyle(.plain)
                        .contextMenu {
                            DeviceContextActions(
                                model: model,
                                device: device,
                                openDetails: {
                                    model.select(device.udid)
                                    section = .devices
                                },
                                addressIssues: {
                                    model.select(device.udid)
                                    model.addressRequiredAction()
                                    section = .diagnostics
                                },
                                requestHostKeyRepair: {
                                    model.select(device.udid)
                                    pendingHostKeyRepairDeviceID = device.udid
                                },
                                requestRemoval: {
                                    model.select(device.udid)
                                    pendingDeviceRemoval = device
                                }
                            )
                        }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 220, ideal: 250)
        } detail: {
            Group {
                switch section ?? .dashboard {
                case .dashboard: DashboardView(model: model) {
                    model.addressRequiredAction()
                    section = .diagnostics
                }
                case .devices: DevicesView(model: model) {
                    model.addressRequiredAction()
                    section = .diagnostics
                }
                case .bridge: BridgeControlView(model: model)
                case .diagnostics: DiagnosticsView(model: model)
                case .logs: LogsView(model: model)
                case .settings: SettingsView(model: model)
                }
            }
            .safeAreaInset(edge: .top, spacing: 0) {
                if model.activeOperationName != nil {
                    ActiveOperationBanner(model: model)
                }
            }
            .toolbar {
                ToolbarItemGroup {
                    if model.isBusy {
                        ProgressView().controlSize(.small)
                        Button(model.cancellationInProgress ? "Stopping…" : "Stop") {
                            model.cancelCurrentOperations()
                        }
                        .disabled(model.cancellationInProgress)
                        .keyboardShortcut(.cancelAction)
                        .help("Stop the active operation (Escape)")
                    }
                    Button { model.manualRefresh() } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .disabled(model.isBusy)
                }
            }
        }
        .sheet(isPresented: $model.showSetupAssistant) { SetupAssistantView(model: model) }
        .confirmationDialog(
            "Repair this device's pinned SSH host key?",
            isPresented: Binding(
                get: { pendingHostKeyRepairDeviceID != nil },
                set: { if !$0 { pendingHostKeyRepairDeviceID = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Repair Exact USB Device", role: .destructive) {
                if let deviceID = pendingHostKeyRepairDeviceID { model.select(deviceID) }
                pendingHostKeyRepairDeviceID = nil
                model.repairPinnedHostKey()
            }
            Button("Cancel", role: .cancel) { pendingHostKeyRepairDeviceID = nil }
        } message: {
            Text("Use only after confirming the selected UDID is physically connected by USB. Automatic recovery never replaces this trust pin.")
        }
        .confirmationDialog(
            "Remove this device from 0-Sky Bridge?",
            isPresented: Binding(
                get: { pendingDeviceRemoval != nil },
                set: { if !$0 { pendingDeviceRemoval = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Remove from This Mac", role: .destructive) {
                guard let device = pendingDeviceRemoval else { return }
                pendingDeviceRemoval = nil
                model.removeDeviceFromBridge(device)
            }
            Button("Cancel", role: .cancel) { pendingDeviceRemoval = nil }
        } message: {
            Text("Only the exact device's Mac-side 0-Sky enrollment, owned services, and cached trust/capability receipts are removed. Research evidence and the Apple device are preserved.")
        }
        .alert("0-Sky Bridge", isPresented: Binding(
            get: { model.lastError != nil },
            set: { if !$0 { model.lastError = nil } }
        )) {
            Button("OK") { model.lastError = nil }
        } message: {
            Text(DiagnosticRedactor.redact(model.lastError ?? "Unknown error"))
        }
    }
}

private struct ActiveOperationBanner: View {
    @ObservedObject var model: BridgeAppModel

    var body: some View {
        HStack(spacing: 12) {
            ProgressView().controlSize(.small)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.activeOperationName ?? "Operation in progress")
                    .font(.callout.bold())
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let elapsed = context.date.timeIntervalSince(
                        model.activeOperationStartedAt ?? context.date
                    )
                    Text("Elapsed \(Self.duration(elapsed)) — \(DiagnosticRedactor.redact(model.statusMessage))")
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer()
            Button(model.cancellationInProgress ? "Stopping…" : "Stop Gracefully") {
                model.cancelCurrentOperations()
            }
            .disabled(model.cancellationInProgress)
            .keyboardShortcut(.cancelAction)
            Button("Force Stop & Return", role: .destructive) {
                model.forceStopCurrentOperation()
            }
            .help("Cancels the Swift task, terminates only 0-Sky-owned processes, and immediately releases the interface.")
        }
        .padding(.horizontal, 16).padding(.vertical, 9)
        .background(.orange.opacity(0.12))
        .overlay(alignment: .bottom) { Divider() }
    }

    private static func duration(_ interval: TimeInterval) -> String {
        let seconds = max(0, Int(interval))
        return String(format: "%02d:%02d:%02d", seconds / 3600, (seconds / 60) % 60, seconds % 60)
    }
}
