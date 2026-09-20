import Foundation
import Network

public actor HealthMonitor {
    private let pairing: PairingManager
    private let wireless: WirelessPairingManager
    private let ssh: SSHManager
    private let services: ServiceManager

    public init(
        pairing: PairingManager,
        wireless: WirelessPairingManager,
        ssh: SSHManager,
        services: ServiceManager
    ) {
        self.pairing = pairing
        self.wireless = wireless
        self.ssh = ssh
        self.services = services
    }

    public func check(device: SkyDevice, profile: DeviceProfile) async -> BridgeHealthSnapshot {
        var checks: [HealthCheck] = []
        let now = Date()
        let transportVisible = device.usbConnected || device.wifiConnected
        let livePairing: BridgeOperationResult?
        if device.usbConnected {
            livePairing = try? await pairing.run(
                profile: profile, mode: .verify, requireWorker: false
            )
        } else if device.wifiConnected,
                  let fingerprint = profile.macIdentityFingerprint {
            livePairing = try? await wireless.run(
                profile: profile,
                operation: .connect,
                hostFingerprint: fingerprint,
                usbTrustVerified: profile.pairingVerified
            )
        } else {
            livePairing = nil
        }
        checks.append(HealthCheck(
            transition: "DEVICE_DISCOVERY",
            state: transportVisible ? .pass : .fail,
            detail: transportVisible
                ? "Device is discoverable." : "Known device is not discoverable over USB or Wi-Fi.",
            checkedAt: now, mandatory: true
        ))
        checks.append(HealthCheck(
            transition: "USB",
            state: device.usbConnected ? .pass : .notApplicable,
            detail: device.usbConnected ? "Exact device is visible over USB." : "USB is not currently connected.",
            checkedAt: now, mandatory: false
        ))
        checks.append(HealthCheck(
            transition: "WIRELESS_PAIRING",
            state: profile.wirelessEnabled || (device.wifiConnected && livePairing?.succeeded == true)
                ? .pass : .fail,
            detail: profile.wirelessEnabled || (device.wifiConnected && livePairing?.succeeded == true)
                ? "Wireless pairing was independently verified."
                : "Wireless pairing has not been verified.",
            checkedAt: now, mandatory: true
        ))
        checks.append(HealthCheck(
            transition: "PAIR_RECORD",
            state: livePairing?.succeeded == true && profile.pairingVerified ? .pass : .fail,
            detail: livePairing?.succeeded == true && profile.pairingVerified
                ? "Pairing receipt and exact-device relationship were verified live."
                : DiagnosticRedactor.redact(livePairing?.stderr.isEmpty == false
                    ? livePairing!.stderr : "Pairing receipt is absent, stale, or invalid."),
            checkedAt: now, mandatory: true
        ))
        checks.append(HealthCheck(
            transition: "TRUST",
            state: livePairing?.succeeded == true && profile.pairingVerified ? .pass : .fail,
            detail: livePairing?.succeeded == true && profile.pairingVerified
                ? "Apple trust and the pinned exact-device SSH relationship were verified live."
                : "Device has not verified trust for this Mac, may be locked, or is offline.",
            checkedAt: now, mandatory: true
        ))

        async let serviceValues = services.allStatuses(profile: profile)
        async let sshResult = ssh.probe(profile)
        async let linkResult = ssh.run(.linkStatus, profile: profile)
        async let controlResult = ssh.run(.controlStatus, profile: profile)
        async let portOpen = TCPProbe.open(port: profile.localPort, timeout: 2)

        let allServices = await serviceValues
        let root = await sshResult
        let link = await linkResult
        let control = await controlResult
        let localPortOpen = await portOpen

        let failedService = allServices.first { !$0.installed || $0.state != "running" }
        checks.append(HealthCheck(
            transition: "BRIDGE_SERVICES",
            state: failedService == nil ? .pass : .fail,
            detail: failedService.map { "\($0.label) is \($0.state)." }
                ?? "All instance-scoped host services are running.",
            checkedAt: Date(), mandatory: true
        ))
        checks.append(HealthCheck(
            transition: "PORT_FORWARD",
            state: localPortOpen ? .pass : .fail,
            detail: localPortOpen
                ? "Local exact-device SSH forwarding port accepted a connection."
                : "The local SSH forwarding port is not accepting connections.",
            checkedAt: Date(), mandatory: true
        ))
        checks.append(HealthCheck(
            transition: "SSH",
            state: root.succeeded && root.stdout.contains("0_SKY_ROOT_READY") ? .pass : .fail,
            detail: root.succeeded
                ? "Pinned SSH returned measured uid 0."
                : DiagnosticRedactor.redact(root.stderr.isEmpty ? "Pinned SSH probe failed." : root.stderr),
            checkedAt: Date(), mandatory: true
        ))

        let linkJSON = (try? JSONSerialization.jsonObject(with: Data(link.stdout.utf8))) as? [String: Any]
        let linkReady = link.succeeded
            && linkJSON?["paired"] as? Bool == true
            && linkJSON?["worker_fresh"] as? Bool == true
            && linkJSON?["privileged_bridge_ready"] as? Bool == true
        checks.append(HealthCheck(
            transition: "0SKY_LINK",
            state: linkReady ? .pass : .fail,
            detail: linkReady
                ? "Authenticated 0-Sky Link heartbeat and bridge protocol are fresh."
                : "0-Sky Link did not return a fresh authenticated bridge status.",
            checkedAt: Date(), mandatory: true
        ))
        let controlJSON = (try? JSONSerialization.jsonObject(with: Data(control.stdout.utf8))) as? [String: Any]
        let controlInstalled = control.succeeded
            && (ControlRuntimeFields.bool(controlJSON, field: "registered")
                || ControlRuntimeFields.bool(controlJSON, field: "mounted"))
        let controlRunning = control.succeeded
            && ControlRuntimeFields.bool(controlJSON, field: "running")
        let controlReachable = control.succeeded
            && ControlRuntimeFields.bool(controlJSON, field: "ok")
        let controlReady = controlInstalled && controlRunning && controlReachable
        checks.append(HealthCheck(
            transition: "0SKY_CONTROL",
            state: controlReady ? .pass : .fail,
            detail: controlReady
                ? "0-Sky Control is installed, running, and its bridge is reachable."
                : "0-Sky Control installation, process, or communication check failed.",
            checkedAt: Date(), mandatory: true
        ))
        // These layers require dedicated tool adapters. Until an adapter returns
        // structured evidence, report NOT_RUN/UNKNOWN rather than inferring PASS
        // from a later working service.
        let unmeasured: [(String, Bool, String)] = [
            ("REMOTEXPC", true, "RemoteXPC has not been independently probed."),
            ("DEVELOPER_SERVICES", true, "Developer services have not been independently probed."),
            ("DDI", true, "Research DDI availability has not been independently probed."),
            ("DEBUGSERVER", false, "Debug service availability has not been independently probed."),
            ("LLDB", false, "LLDB service availability has not been independently probed."),
            ("CRYTEX", false, "Cryptex state has not been independently probed."),
            ("BOOTSTRAP", false, "Bootstrap state has not been independently probed."),
            ("FRIDA_HOST", false, "Frida host availability has not been independently probed."),
            ("FRIDA_DEVICE", false, "Frida device/server availability has not been independently probed."),
            ("FRIDA_VERSION", false, "Frida compatibility has not been independently probed."),
            ("FRIDA_ATTACH", false, "Frida attach has not been independently probed."),
            ("DEVICE_STORAGE", false, "Device free storage has not been independently measured."),
        ]
        checks.append(contentsOf: unmeasured.map {
            HealthCheck(transition: $0.0, state: .notRun, detail: $0.2, checkedAt: Date(), mandatory: $0.1)
        })

        let hostDisk = try? FileManager.default.attributesOfFileSystem(
            forPath: FileManager.default.homeDirectoryForCurrentUser.path
        )
        let freeBytes = (hostDisk?[.systemFreeSize] as? NSNumber)?.int64Value
        let diskOK = freeBytes.map { $0 >= 2 * 1_024 * 1_024 * 1_024 }
        checks.append(HealthCheck(
            transition: "HOST_DISK_SPACE",
            state: diskOK.map { $0 ? .pass : .fail } ?? .notRun,
            detail: freeBytes.map { "Host has \($0 / 1_024 / 1_024) MiB available." }
                ?? "Host disk space could not be determined.",
            checkedAt: Date(), mandatory: false
        ))
        return BridgeHealthSnapshot(deviceID: device.udid, checks: checks)
    }

    public func comprehensiveReport(device: SkyDevice, profile: DeviceProfile,
                                    supplemental: [HealthResult] = []) async -> SRDHealthReport {
        let snapshot = await check(device: device, profile: profile)
        let replacementNames = Set(supplemental.map(\.name))
        let results = snapshot.results.filter { !replacementNames.contains($0.name) } + supplemental
        return SRDHealthReport(deviceID: device.udid, results: results)
    }

    public func integrationStatus(profile: DeviceProfile) async -> DeviceIntegrationStatus {
        async let linkResult = ssh.run(.linkStatus, profile: profile)
        async let controlResult = ssh.run(.controlStatus, profile: profile)
        let link = await linkResult
        let control = await controlResult
        let linkJSON = (try? JSONSerialization.jsonObject(with: Data(link.stdout.utf8))) as? [String: Any]
        let runtime = (try? JSONSerialization.jsonObject(with: Data(control.stdout.utf8))) as? [String: Any]
        let linkReady = link.succeeded
            && linkJSON?["paired"] as? Bool == true
            && linkJSON?["worker_fresh"] as? Bool == true
            && linkJSON?["privileged_bridge_ready"] as? Bool == true
        let installed = control.succeeded
            && (ControlRuntimeFields.bool(runtime, field: "registered")
                || ControlRuntimeFields.bool(runtime, field: "mounted"))
        let running = control.succeeded && ControlRuntimeFields.bool(runtime, field: "running")
        let reachable = control.succeeded && ControlRuntimeFields.bool(runtime, field: "ok")
        let rawVersion = ControlRuntimeFields.string(runtime, field: "version")
        return DeviceIntegrationStatus(
            linkReachable: linkReady,
            controlInstalled: installed,
            controlRunning: running,
            controlReachable: reachable,
            controlVersion: rawVersion == "unknown" ? nil : rawVersion
        )
    }
}

/// Machine-readable runtime output is redacted before it reaches the UI. The
/// stable on-device protocol still uses its legacy compatibility prefix, while
/// redacted output uses the public Commissary name. Accept both without ever
/// changing or guessing the measured values.
private enum ControlRuntimeFields {
    static func bool(_ object: [String: Any]?, field: String) -> Bool {
        value(object, field: field) as? Bool == true
    }

    static func string(_ object: [String: Any]?, field: String) -> String? {
        value(object, field: field) as? String
    }

    private static func value(_ object: [String: Any]?, field: String) -> Any? {
        object?["Commissary_\(field)"] ?? object?["crypstore_\(field)"]
    }
}

public enum TCPProbe {
    public static func open(port: Int, timeout: TimeInterval) async -> Bool {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else { return false }
        return await withCheckedContinuation { continuation in
            let connection = NWConnection(host: "127.0.0.1", port: nwPort, using: .tcp)
            let queue = DispatchQueue(label: "com.liquidsky.0sky.bridge.tcp-probe")
            let box = TCPProbeCompletion(connection: connection, continuation: continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: box.finish(true)
                case .failed, .cancelled: box.finish(false)
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) { box.finish(false) }
        }
    }
}

private final class TCPProbeCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private let connection: NWConnection
    private var continuation: CheckedContinuation<Bool, Never>?

    init(connection: NWConnection, continuation: CheckedContinuation<Bool, Never>) {
        self.connection = connection
        self.continuation = continuation
    }

    func finish(_ value: Bool) {
        lock.lock()
        let current = continuation
        continuation = nil
        lock.unlock()
        guard let current else { return }
        connection.cancel()
        current.resume(returning: value)
    }
}
