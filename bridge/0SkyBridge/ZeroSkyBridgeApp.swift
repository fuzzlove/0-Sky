import SwiftUI
import AppKit

@main
struct ZeroSkyBridgeApp: App {
    @StateObject private var model = BridgeAppModel()

    var body: some Scene {
        WindowGroup("0-Sky Bridge") {
            RootView(model: model)
                .frame(minWidth: 1080, minHeight: 700)
                .onAppear { model.start() }
        }
        .defaultSize(width: 1240, height: 800)

        MenuBarExtra("0-Sky Bridge", systemImage: model.overallReady ? "link.circle.fill" : "link.badge.plus") {
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
            Divider()
            Button("Quit") { NSApplication.shared.terminate(nil) }
        }
    }
}
