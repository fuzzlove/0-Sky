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
            .toolbar {
                ToolbarItemGroup {
                    if model.isBusy { ProgressView().controlSize(.small) }
                    Button { Task { await model.refresh(runHealth: true) } } label: {
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
