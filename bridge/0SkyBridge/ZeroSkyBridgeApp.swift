import SwiftUI
import AppKit
import BridgeCore

@main
struct ZeroSkyBridgeApp: App {
    @StateObject private var model = BridgeAppModel()
    private let document: LicenseAgreementDocument?
    private let acceptanceStore = LicenseAcceptanceStore()
    @State private var agreementAccepted: Bool
    @State private var bridgeStarted = false

    init() {
        let loaded = LicenseAgreementDocument.load()
        document = loaded
        _agreementAccepted = State(initialValue: loaded.map {
            LicenseAcceptanceStore().isAccepted($0.metadata)
        } ?? false)
    }

    var body: some Scene {
        WindowGroup("0-Sky Bridge") {
            Group {
                if agreementAccepted {
                    RootView(model: model)
                        .frame(minWidth: 1080, minHeight: 700)
                        .onAppear { startBridgeOnce() }
                } else {
                    LicenseAgreementView(document: document, onAccept: acceptAgreement)
                }
            }
        }
        .defaultSize(width: 1240, height: 800)

        MenuBarExtra("0-Sky Bridge", systemImage: model.overallReady ? "link.circle.fill" : "link.badge.plus") {
            if agreementAccepted {
                Text(model.overallReady ? "● Connected" : "● Action Required")
                Divider()
                Button("Reconnect") { model.reconnect() }
                Button("Restart Bridge") { model.serviceAction("restart", service: .deviceBridge) }
                if model.activeOperationName != nil {
                    Divider()
                    Text(model.activeOperationName ?? "Operation in progress")
                    Button("Stop Active Operation") { model.cancelCurrentOperations() }
                    Button("Force Stop Active Operation", role: .destructive) {
                        model.forceStopCurrentOperation()
                    }
                }
            } else {
                Text("License acceptance required")
                Button("Review Agreement") {
                    NSApplication.shared.activate(ignoringOtherApps: true)
                }
            }
            Divider()
            Button("Quit") { NSApplication.shared.terminate(nil) }
        }
    }

    private func acceptAgreement() -> Bool {
        guard let document, acceptanceStore.accept(document.metadata) else { return false }
        agreementAccepted = true
        return true
    }

    private func startBridgeOnce() {
        guard agreementAccepted, document != nil, !bridgeStarted else { return }
        bridgeStarted = true
        model.start()
    }
}
