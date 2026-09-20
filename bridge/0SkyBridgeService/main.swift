import BridgeCore
import Foundation

private final class ReplyBox<A, B>: @unchecked Sendable {
    let reply: (A, B) -> Void
    init(_ reply: @escaping (A, B) -> Void) { self.reply = reply }
}

private actor BridgeDaemonRuntime {
    private struct Measurement: Sendable {
        let devices: [SkyDevice]
        let health: [String: BridgeHealthSnapshot]
        let srdHealth: [String: SRDHealthReport]
    }

    static let version = "1.1.1"
    private let startedAt = Date()
    private let environment = BridgeEnvironment()
    private var devices: [SkyDevice] = []
    private var health: [String: BridgeHealthSnapshot] = [:]
    private var srdHealth: [String: SRDHealthReport] = [:]
    private var lastSessionDirectory: URL?
    private var lastError: String?
    private var monitorTask: Task<Void, Never>?

    init() {
        Task { [environment] in
            try? await environment.structuredLog.attach(to: environment.events)
        }
    }

    func startMonitoring() {
        guard monitorTask == nil else { return }
        let environment = self.environment
        monitorTask = Task.detached(priority: .utility) { [weak self, environment] in
            // Let launchd/XPC finish bringing the endpoint online before the
            // first tool-heavy fleet pass. Detached execution also prevents
            // process I/O from starving the listener's run loop.
            try? await Task.sleep(for: .seconds(2))
            while !Task.isCancelled {
                let measurement = await Self.measure(environment: environment)
                await self?.apply(measurement)
                try? await Task.sleep(for: .seconds(30))
            }
        }
    }

    func snapshot(refresh shouldRefresh: Bool) async -> BridgeDaemonSnapshot {
        // Client polling must remain fast. Expensive adapter health checks are
        // owned by the service monitor and populate the cached report; a GUI
        // refresh only updates discovery/transport state.
        if shouldRefresh { await refreshDiscovery() }
        return BridgeDaemonSnapshot(
            serviceVersion: Self.version, serviceStartedAt: startedAt,
            devices: devices, health: health,
            srdHealth: srdHealth,
            activeSession: await environment.sessions.current(), lastError: lastError
        )
    }

    private func refreshDiscovery() async {
        let found = await environment.discovery.discover()
        devices = found
        for device in found {
            _ = await environment.transports.update(
                deviceID: device.udid, usb: device.usbConnected, wifi: device.wifiConnected,
                reason: device.connection == .offline ? "discovery reported no active transport" : nil
            )
        }
    }

    func refresh() async {
        apply(await Self.measure(environment: environment))
    }

    private nonisolated static func measure(environment: BridgeEnvironment) async -> Measurement {
        let found = await environment.discovery.discover()
        var measured: [String: BridgeHealthSnapshot] = [:]
        var advanced: [String: SRDHealthReport] = [:]
        for device in found {
            _ = await environment.transports.update(
                deviceID: device.udid, usb: device.usbConnected, wifi: device.wifiConnected,
                reason: device.connection == .offline ? "discovery reported no active transport" : nil
            )
            guard let profile = await environment.registry.profile(for: device.udid) else { continue }
            measured[device.udid] = await environment.health.check(device: device, profile: profile)
            advanced[device.udid] = await environment.srdHealth.check(deviceID: device.udid, adapters: [
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
            if let session = await environment.sessions.current(),
               session.manifest.deviceIdentifier == device.udid {
                _ = await environment.crashCollector.collect(profile: profile, session: session)
            }
        }
        return Measurement(devices: found, health: measured, srdHealth: advanced)
    }

    private func apply(_ measurement: Measurement) {
        devices = measurement.devices
        health = measurement.health
        srdHealth = measurement.srdHealth
        lastError = nil
    }

    func recover(deviceID: String) async throws -> BridgeHealthSnapshot {
        _ = try BridgeValidation.validateUDID(deviceID)
        await refreshDiscovery()
        guard let device = devices.first(where: { $0.udid == deviceID }),
              let profile = await environment.registry.profile(for: deviceID) else {
            throw BridgeCoreError.operationFailed("Selected device/profile is unavailable.")
        }
        let result = await environment.recovery.fix(device: device, profile: profile)
        health[deviceID] = result
        return result
    }

    func startSession(name: String, deviceID: String) async throws -> ResearchSession {
        _ = try BridgeValidation.validateUDID(deviceID)
        await refreshDiscovery()
        guard let device = devices.first(where: { $0.udid == deviceID }) else {
            throw BridgeCoreError.operationFailed("Selected device is unavailable.")
        }
        return try await environment.sessions.start(
            name: name, device: device, host: HostInspector.summary(),
            toolVersions: ["bridge-service": Self.version],
            researchConfiguration: ["owner": "persistent-bridge-service"]
        )
    }

    func stopSession() async throws -> URL {
        let directory = try await environment.sessions.stop()
        lastSessionDirectory = directory
        return directory
    }

    func export(profile: EvidenceExportProfile) async throws -> URL {
        guard let lastSessionDirectory else {
            throw BridgeCoreError.operationFailed("No completed service-owned session is available.")
        }
        return try await environment.sessions.export(sessionDirectory: lastSessionDirectory, profile: profile)
    }


    func clearLogs() async throws {
        await environment.logs.clear()
        _ = try await environment.structuredLog.clear()
    }
}

private final class BridgeDaemonObject: NSObject, BridgeDaemonProtocol, @unchecked Sendable {
    let runtime = BridgeDaemonRuntime()
    override init() {
        super.init()
        Task { await runtime.startMonitoring() }
    }
    func serviceVersion(reply: @escaping (String) -> Void) { reply(BridgeDaemonRuntime.version) }

    func snapshot(refresh: Bool, reply: @escaping (Data?, String?) -> Void) {
        respond(reply) { try JSONEncoder.sky.encode(await self.runtime.snapshot(refresh: refresh)) }
    }
    func recover(deviceID: String, reply: @escaping (Data?, String?) -> Void) {
        respond(reply) { try JSONEncoder.sky.encode(try await self.runtime.recover(deviceID: deviceID)) }
    }
    func startResearchSession(name: String, deviceID: String, reply: @escaping (Data?, String?) -> Void) {
        respond(reply) { try JSONEncoder.sky.encode(try await self.runtime.startSession(name: name, deviceID: deviceID)) }
    }
    func stopResearchSession(reply: @escaping (Data?, String?) -> Void) {
        struct Result: Codable { let path: String }
        respond(reply) { try JSONEncoder.sky.encode(Result(path: try await self.runtime.stopSession().path)) }
    }
    func exportLastResearchSession(profile: String, reply: @escaping (String?, String?) -> Void) {
        let box = ReplyBox(reply)
        Task {
            do {
                guard let value = EvidenceExportProfile(rawValue: profile) else {
                    throw BridgeCoreError.operationFailed("Unknown export profile.")
                }
                box.reply(try await runtime.export(profile: value).path, nil)
            } catch { box.reply(nil, DiagnosticRedactor.redact(error.localizedDescription)) }
        }
    }
    func clearLogs(reply: @escaping (Bool, String?) -> Void) {
        let box = ReplyBox(reply)
        Task {
            do {
                try await runtime.clearLogs()
                box.reply(true, nil)
            } catch {
                box.reply(false, DiagnosticRedactor.redact(error.localizedDescription))
            }
        }
    }
    private func respond(_ reply: @escaping (Data?, String?) -> Void,
                         operation: @escaping @Sendable () async throws -> Data) {
        let box = ReplyBox(reply)
        Task {
            do { box.reply(try await operation(), nil) }
            catch { box.reply(nil, DiagnosticRedactor.redact(error.localizedDescription)) }
        }
    }
}

private final class BridgeDaemonDelegate: NSObject, NSXPCListenerDelegate {
    private let exported = BridgeDaemonObject()
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard CodeIdentityValidator.authorize(
            connection: connection,
            allowedIdentifiers: ["com.liquidsky.0sky.bridge", "com.liquidsky.0sky.bridge.cli"]
        ) else { return false }
        connection.exportedInterface = NSXPCInterface(with: BridgeDaemonProtocol.self)
        connection.exportedObject = exported
        connection.resume()
        return true
    }
}

private let delegate = BridgeDaemonDelegate()
private let listener = NSXPCListener(machServiceName: BridgeDaemonClient.machServiceName)
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
