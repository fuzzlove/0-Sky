import Foundation

public struct OperationResult: Codable, Sendable {
    public let succeeded: Bool
    public let failureKind: AdapterFailureKind?
    public let message: String
    public let observed: [String: JSONValue]
    public let durationMS: Int

    public init(succeeded: Bool, failureKind: AdapterFailureKind? = nil,
                message: String, observed: [String: JSONValue] = [:], durationMS: Int = 0) {
        self.succeeded = succeeded
        self.failureKind = failureKind
        self.message = DiagnosticRedactor.redact(message)
        self.observed = observed
        self.durationMS = max(0, durationMS)
    }
}

public protocol HealthCheckingAdapter: Sendable {
    var component: String { get }
    func checkHealth() async -> HealthResult
}

public protocol RecoverableAdapter: HealthCheckingAdapter {
    func connect() async -> OperationResult
    func disconnect() async -> OperationResult
    func recover() async -> OperationResult
}

public struct USBAdapter: HealthCheckingAdapter {
    public let component = "USB"
    private let device: SkyDevice
    public init(device: SkyDevice) { self.device = device }
    public func checkHealth() async -> HealthResult {
        HealthResult(name: component, status: device.usbConnected ? .pass : .fail, severity: .high,
                     observed: ["connected": .bool(device.usbConnected)], expected: "exact device visible over USB",
                     rootCause: device.usbConnected ? nil : "USB transport is unavailable",
                     remediation: device.usbConnected ? [] : ["reconnect the SRD USB cable", "refresh device discovery"])
    }
}

public struct RemoteXPCAdapter: HealthCheckingAdapter {
    public let component = "REMOTEXPC"
    private let manager: ResearcherOperationsManager
    private let profile: DeviceProfile
    public init(manager: ResearcherOperationsManager, profile: DeviceProfile) {
        self.manager = manager; self.profile = profile
    }
    public func checkHealth() async -> HealthResult {
        do {
            let result = try await manager.checkRemoteXPC(profile: profile)
            return HealthResult(name: component, status: result.succeeded ? .pass : .fail, severity: .high,
                                observed: ["exit_code": .number(Double(result.exitCode))],
                                expected: "selected SRD appears in authenticated RemoteXPC discovery",
                                rootCause: result.succeeded ? nil : result.stderr,
                                remediation: result.succeeded ? [] : ["retry RemoteXPC discovery"])
        } catch {
            return HealthResult(name: component, status: .unknown, severity: .high,
                                expected: "RemoteXPC status is measurable", rootCause: error.localizedDescription,
                                failureKind: .unexpected)
        }
    }
}

/// Typed probe injection keeps tool invocation in adapters while allowing the
/// actual SRD toolchain to vary by Xcode/device release.
public struct AdapterProbe: Sendable {
    public let run: @Sendable () async -> HealthResult
    public init(_ run: @escaping @Sendable () async -> HealthResult) { self.run = run }
    public static func unavailable(component: String, expected: String) -> AdapterProbe {
        AdapterProbe {
            HealthResult(name: component, status: .unknown, severity: .high, expected: expected,
                         rootCause: "No compatible adapter probe is configured.", failureKind: .unsupported)
        }
    }
}

public struct DDIAdapter: HealthCheckingAdapter {
    public let component = "DDI"; private let probe: AdapterProbe
    public init(probe: AdapterProbe = .unavailable(component: "DDI", expected: "compatible research DDI is mounted")) { self.probe = probe }
    public init(manager: ResearcherOperationsManager, profile: DeviceProfile) {
        self.probe = AdapterProbe {
            do {
                let result = try await manager.checkDDI(profile: profile)
                return HealthResult(
                    name: "DDI", status: result.succeeded ? .pass : .fail, severity: .critical,
                    observed: ["exit_code": .number(Double(result.exitCode))],
                    expected: "compatible research DDI services are available",
                    rootCause: result.succeeded ? nil : (result.stderr.isEmpty ? "Research DDI unavailable or incompatible" : result.stderr),
                    remediation: result.succeeded ? [] : ["verify the matching Xcode research DDI without automatically replacing device state"],
                    rawEvidence: result.succeeded ? [result.stdout] : [result.stderr],
                    durationMS: Int(result.duration * 1000),
                    failureKind: result.succeeded ? nil : .toolFailure
                )
            } catch {
                return HealthResult(name: "DDI", status: .unknown, severity: .critical,
                                    expected: "DDI status is measurable", rootCause: error.localizedDescription,
                                    failureKind: .unexpected)
            }
        }
    }
    public func checkHealth() async -> HealthResult { await probe.run() }
}

private func healthJSON(_ result: BridgeOperationResult) -> [String: Any]? {
    try? JSONSerialization.jsonObject(with: Data(result.stdout.utf8)) as? [String: Any]
}

public struct CryptexAdapter: HealthCheckingAdapter {
    public let component = "CRYTEX"; private let probe: AdapterProbe
    public init(probe: AdapterProbe = .unavailable(component: "CRYTEX", expected: "research Cryptex state is healthy")) { self.probe = probe }
    public init(ssh: SSHManager, profile: DeviceProfile) {
        probe = AdapterProbe {
            let result = await ssh.run(.cryptexHealth, profile: profile)
            let json = healthJSON(result)
            let mounted = result.succeeded && json?["mounted"] as? Bool == true
            return HealthResult(name: "CRYTEX", status: mounted ? .pass : .fail, severity: .high,
                                observed: ["mounted": .bool(mounted)], expected: "a research Cryptex is mounted",
                                rootCause: mounted ? nil : "No mounted research Cryptex was measured",
                                remediation: mounted ? [] : ["inspect Cryptex state; replacement remains Tier 3"],
                                rawEvidence: [result.stdout, result.stderr], durationMS: Int(result.duration * 1000),
                                failureKind: mounted ? nil : .toolFailure)
        }
    }
    public func checkHealth() async -> HealthResult { await probe.run() }
}

public struct BootstrapAdapter: HealthCheckingAdapter {
    public let component = "BOOTSTRAP"; private let probe: AdapterProbe
    public init(probe: AdapterProbe = .unavailable(component: "BOOTSTRAP", expected: "research bootstrap is healthy")) { self.probe = probe }
    public init(ssh: SSHManager, profile: DeviceProfile) {
        probe = AdapterProbe {
            let result = await ssh.run(.bootstrapHealth, profile: profile)
            let json = healthJSON(result)
            let ready = result.succeeded && json?["python"] as? Bool == true
            return HealthResult(name: "BOOTSTRAP", status: ready ? .pass : .fail, severity: .high,
                                observed: ["python": .bool(ready),
                                           "installed_packages": .number(Double(json?["installed_packages"] as? Int ?? 0))],
                                expected: "rootless bootstrap and package database are healthy",
                                rootCause: ready ? nil : "Bootstrap root, Python, or package database is unavailable",
                                remediation: ready ? [] : ["inspect bootstrap configuration; replacement remains Tier 3"],
                                rawEvidence: [result.stdout, result.stderr], durationMS: Int(result.duration * 1000),
                                failureKind: ready ? nil : .toolFailure)
        }
    }
    public func checkHealth() async -> HealthResult { await probe.run() }
}

private func fridaHostExecutable() -> String? {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let managed = "\(home)/Library/Application Support/0-Sky/tools/frida-current/bin/frida"
    if FileManager.default.isExecutableFile(atPath: managed) { return managed }
    return HostToolResolver.executable("frida")
}

public struct FridaAdapter: HealthCheckingAdapter {
    public let component = "FRIDA_VERSION"
    private let hostVersion: @Sendable () async -> String?
    private let deviceVersion: @Sendable () async -> String?
    public init(hostVersion: @escaping @Sendable () async -> String?,
                deviceVersion: @escaping @Sendable () async -> String?) {
        self.hostVersion = hostVersion; self.deviceVersion = deviceVersion
    }
    public init(runner: ScriptRunner, ssh: SSHManager, profile: DeviceProfile) {
        self.init(hostVersion: {
            guard let path = fridaHostExecutable() else { return nil }
            let result = try? await runner.run(ScriptSpecification(
                identifier: "health.frida-host", executableURL: URL(fileURLWithPath: path),
                arguments: ["--version"], timeout: .seconds(10)
            ))
            return result?.succeeded == true ? result?.stdout.trimmingCharacters(in: .whitespacesAndNewlines) : nil
        }, deviceVersion: {
            let result = await ssh.run(.fridaHealth, profile: profile)
            return healthJSON(result)?["version"] as? String
        })
    }
    public func checkHealth() async -> HealthResult {
        async let hostValue = hostVersion(); async let deviceValue = deviceVersion()
        let (host, device) = await (hostValue, deviceValue)
        guard let host, let device else {
            return HealthResult(name: component, status: .unknown, severity: .high,
                                observed: ["host": host.map(JSONValue.string) ?? .null,
                                           "device": device.map(JSONValue.string) ?? .null],
                                expected: "measurable matching compatible versions",
                                rootCause: "Frida host or device version could not be measured",
                                failureKind: .toolMissing)
        }
        let compatible = host == device
        return HealthResult(name: component, status: compatible ? .pass : .fail, severity: .high,
                            observed: ["host": .string(host), "device": .string(device)],
                            expected: "matching compatible versions",
                            rootCause: compatible ? nil : "host/device version mismatch",
                            remediation: compatible ? [] : ["align host and device Frida versions"])
    }
}

public struct FridaHostAdapter: HealthCheckingAdapter {
    public let component = "FRIDA_HOST"
    private let runner: ScriptRunner
    public init(runner: ScriptRunner) { self.runner = runner }
    public func checkHealth() async -> HealthResult {
        guard let path = fridaHostExecutable() else {
            return HealthResult(name: component, status: .fail, severity: .high,
                                observed: ["available": .bool(false)],
                                expected: "Frida host tools are installed and version-readable",
                                rootCause: "Frida host executable is unavailable",
                                remediation: ["install the approved host Frida version"],
                                failureKind: .toolMissing)
        }
        do {
            let result = try await runner.run(ScriptSpecification(
                identifier: "health.frida-host", executableURL: URL(fileURLWithPath: path),
                arguments: ["--version"], timeout: .seconds(10)
            ))
            let version = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            return HealthResult(name: component, status: result.succeeded && !version.isEmpty ? .pass : .fail,
                                severity: .high,
                                observed: ["available": .bool(result.succeeded),
                                           "version": version.isEmpty ? .null : .string(version)],
                                expected: "Frida host tools are installed and version-readable",
                                rootCause: result.succeeded ? nil : "Frida host version probe failed",
                                rawEvidence: [result.stdout, result.stderr],
                                durationMS: Int(result.duration * 1000),
                                failureKind: result.succeeded ? nil : .toolFailure)
        } catch {
            return HealthResult(name: component, status: .unknown, severity: .high,
                                expected: "Frida host status is measurable",
                                rootCause: error.localizedDescription, failureKind: .unexpected)
        }
    }
}

public struct FridaDeviceAdapter: HealthCheckingAdapter {
    public let component = "FRIDA_DEVICE"
    private let ssh: SSHManager
    private let profile: DeviceProfile
    public init(ssh: SSHManager, profile: DeviceProfile) { self.ssh = ssh; self.profile = profile }
    public func checkHealth() async -> HealthResult {
        let result = await ssh.run(.fridaHealth, profile: profile)
        let json = healthJSON(result)
        let available = json?["available"] as? Bool == true
        let running = json?["running"] as? Bool == true
        let version = json?["version"] as? String
        let status: HealthStatus = !available ? .fail : (running ? .pass : .degraded)
        return HealthResult(name: component, status: status, severity: .high,
                            observed: ["available": .bool(available), "running": .bool(running),
                                       "version": version.map(JSONValue.string) ?? .null],
                            expected: "Frida device server is installed, running, and version-readable",
                            rootCause: status == .pass ? nil : (available
                                ? "Frida device server is installed but not running"
                                : "Frida device server is unavailable"),
                            remediation: status == .pass ? [] : ["start or install the approved Frida device server"],
                            rawEvidence: [result.stdout, result.stderr], durationMS: Int(result.duration * 1000),
                            failureKind: status == .pass ? nil : (available ? .toolFailure : .toolMissing))
    }
}

public struct DeviceStorageAdapter: HealthCheckingAdapter {
    public let component = "DEVICE_STORAGE"
    private let ssh: SSHManager
    private let profile: DeviceProfile
    private let minimumKiB: Int
    public init(ssh: SSHManager, profile: DeviceProfile, minimumBytes: Int = 512 * 1_024 * 1_024) {
        self.ssh = ssh; self.profile = profile; self.minimumKiB = max(1, minimumBytes / 1_024)
    }
    public func checkHealth() async -> HealthResult {
        let result = await ssh.run(.deviceStorage, profile: profile)
        let json = healthJSON(result)
        let availableKiB = json?["available_kib"] as? Int
            ?? (json?["available_kib"] as? NSNumber)?.intValue
        guard result.succeeded, let availableKiB else {
            return HealthResult(name: component, status: .unknown, severity: .medium,
                                expected: "device free storage can be measured",
                                rootCause: result.stderr.isEmpty ? "Device storage probe returned malformed data" : result.stderr,
                                rawEvidence: [result.stdout, result.stderr], durationMS: Int(result.duration * 1000),
                                failureKind: result.succeeded ? .malformedResponse : .toolFailure)
        }
        let healthy = availableKiB >= minimumKiB
        return HealthResult(name: component, status: healthy ? .pass : .degraded, severity: .medium,
                            observed: ["available_kib": .number(Double(availableKiB)),
                                       "minimum_kib": .number(Double(minimumKiB))],
                            expected: "at least \(minimumKiB) KiB of device storage is available",
                            rootCause: healthy ? nil : "Device storage is below the research evidence threshold",
                            remediation: healthy ? [] : ["free device storage without deleting current-session evidence"],
                            rawEvidence: [result.stdout], durationMS: Int(result.duration * 1000))
    }
}

public struct DefaultCredentialsAdapter: HealthCheckingAdapter {
    public static let warningMessage = "This device is using default credentials. Please see the control center on the device to update"
    public let component = "DEFAULT_CREDENTIALS"
    private let probe: AdapterProbe

    public init(probe: AdapterProbe = .unavailable(
        component: "DEFAULT_CREDENTIALS",
        expected: "mobile and root accounts do not use legacy default credentials"
    )) {
        self.probe = probe
    }

    public init(ssh: SSHManager, profile: DeviceProfile) {
        probe = AdapterProbe {
            let result = await ssh.run(.defaultCredentialsHealth, profile: profile)
            return Self.evaluate(result)
        }
    }

    public func checkHealth() async -> HealthResult { await probe.run() }

    public static func evaluate(_ result: BridgeOperationResult) -> HealthResult {
        guard let json = healthJSON(result), let measured = json["measured"] as? Bool else {
            return HealthResult(
                name: "DEFAULT_CREDENTIALS", status: .unknown, severity: .critical,
                expected: "mobile and root credential state is measurable",
                rootCause: result.stderr.isEmpty
                    ? "Credential probe returned malformed output"
                    : result.stderr,
                rawEvidence: [result.stdout, result.stderr],
                durationMS: Int(result.duration * 1000), failureKind: .malformedResponse
            )
        }
        let rootDefault = json["root_default"] as? Bool == true
        let mobileDefault = json["mobile_default"] as? Bool == true
        let accountsMeasured = (json["accounts_measured"] as? NSNumber)?.intValue ?? 0
        guard measured else {
            return HealthResult(
                name: "DEFAULT_CREDENTIALS", status: .unknown, severity: .critical,
                observed: ["measured": .bool(false)],
                expected: "mobile and root credential state is measurable",
                rootCause: "The mobile and root credential records could not be measured",
                remediation: ["verify authenticated root SSH access and inspect credential state on the device"],
                rawEvidence: [result.stdout, result.stderr],
                durationMS: Int(result.duration * 1000), failureKind: .permissionDenied
            )
        }
        let unsafe = rootDefault || mobileDefault
        return HealthResult(
            name: "DEFAULT_CREDENTIALS", status: unsafe ? .fail : .pass, severity: .critical,
            observed: [
                "measured": .bool(true),
                "root_default": .bool(rootDefault),
                "mobile_default": .bool(mobileDefault),
                "accounts_measured": .number(Double(accountsMeasured)),
            ],
            expected: "mobile and root accounts do not use legacy default credentials",
            rootCause: unsafe ? warningMessage : nil,
            remediation: unsafe ? [warningMessage] : [],
            rawEvidence: [result.stdout], durationMS: Int(result.duration * 1000)
        )
    }
}

public struct VNCDefaultCredentialsAdapter: HealthCheckingAdapter {
    public static let warningMessage = DefaultCredentialsAdapter.warningMessage
    public let component = "VNC_DEFAULT_CREDENTIALS"
    private let probe: AdapterProbe

    public init(probe: AdapterProbe = .unavailable(
        component: "VNC_DEFAULT_CREDENTIALS",
        expected: "VNC ports 5800 and 5900 reject unauthenticated and null-password access"
    )) {
        self.probe = probe
    }

    public init(ssh: SSHManager, profile: DeviceProfile) {
        probe = AdapterProbe {
            Self.evaluate(await ssh.run(.vncDefaultCredentialsHealth, profile: profile))
        }
    }

    public func checkHealth() async -> HealthResult { await probe.run() }

    public static func evaluate(_ result: BridgeOperationResult) -> HealthResult {
        let expected = "VNC ports 5800 and 5900 reject unauthenticated and null-password access"
        guard result.succeeded, let json = healthJSON(result),
              let measured = json["measured"] as? Bool else {
            return HealthResult(
                name: "VNC_DEFAULT_CREDENTIALS", status: .unknown, severity: .critical,
                expected: expected,
                rootCause: result.stderr.isEmpty
                    ? "VNC credential probe returned malformed output"
                    : result.stderr,
                rawEvidence: [result.stdout, result.stderr],
                durationMS: Int(result.duration * 1000),
                failureKind: result.succeeded ? .malformedResponse : .connectionLost
            )
        }
        let unsafe = json["unsafe"] as? Bool == true
        let port5900 = json["port_5900_open"] as? Bool == true
        let port5800 = json["port_5800_open"] as? Bool == true
        let noneAuth = json["rfb_none_auth"] as? Bool == true
        let emptyPassword = json["rfb_empty_password"] as? Bool == true
        let httpUnauthenticated = json["http_unauthenticated"] as? Bool == true
        guard measured else {
            return HealthResult(
                name: "VNC_DEFAULT_CREDENTIALS", status: .unknown, severity: .critical,
                observed: [
                    "measured": .bool(false), "port_5900_open": .bool(port5900),
                    "port_5800_open": .bool(port5800),
                ],
                expected: expected,
                rootCause: "VNC credential state could not be measured",
                remediation: ["verify authenticated root SSH access and inspect the VNC service configuration"],
                rawEvidence: [result.stdout, result.stderr],
                durationMS: Int(result.duration * 1000), failureKind: .toolFailure
            )
        }
        var observed: [String: JSONValue] = [
            "measured": .bool(true), "unsafe": .bool(unsafe),
            "port_5900_open": .bool(port5900), "port_5800_open": .bool(port5800),
            "rfb_none_auth": .bool(noneAuth),
            "rfb_empty_password": .bool(emptyPassword),
            "http_unauthenticated": .bool(httpUnauthenticated),
        ]
        if let protocolName = json["rfb_protocol"] as? String {
            observed["rfb_protocol"] = .string(protocolName)
        }
        if let status = (json["http_status"] as? NSNumber)?.doubleValue {
            observed["http_status"] = .number(status)
        }
        return HealthResult(
            name: "VNC_DEFAULT_CREDENTIALS", status: unsafe ? .fail : .pass,
            severity: .critical, observed: observed, expected: expected,
            rootCause: unsafe ? warningMessage : nil,
            remediation: unsafe ? [warningMessage] : [],
            rawEvidence: [result.stdout], durationMS: Int(result.duration * 1000)
        )
    }
}

public struct DebugserverAdapter: HealthCheckingAdapter {
    public let component = "DEBUGSERVER"
    private let probe: AdapterProbe
    public init(probe: AdapterProbe = .unavailable(
        component: "DEBUGSERVER",
        expected: "CoreDevice LLDB can enumerate attachable device processes"
    )) {
        self.probe = probe
    }
    public init(manager: ResearcherOperationsManager, profile: DeviceProfile) {
        probe = AdapterProbe {
            do {
                let result = try await manager.checkDebugserver(profile: profile)
                let available = result.succeeded
                let failure = result.stderr.isEmpty ? result.stdout : result.stderr
                return HealthResult(
                    name: "DEBUGSERVER", status: available ? .pass : .fail, severity: .high,
                    observed: [
                        "available": .bool(available),
                        "exit_code": .number(Double(result.exitCode)),
                        "probe": .string("coredevice-lldb-process-list"),
                    ],
                    expected: "CoreDevice LLDB can enumerate attachable device processes",
                    rootCause: available ? nil : (failure.isEmpty
                        ? "LLDB could not reach the device debugging service"
                        : failure),
                    remediation: available ? [] : [
                        "verify the matching DDI is usable, unlock the device, and retry the LLDB service probe"
                    ],
                    rawEvidence: available
                        ? ["LLDB selected the exact device and enumerated attachable processes."]
                        : [result.stderr, result.stdout],
                    durationMS: Int(result.duration * 1000),
                    failureKind: available ? nil : (result.timedOut ? .timeout : .toolFailure)
                )
            } catch let error as BridgeCoreError {
                let kind: AdapterFailureKind = switch error {
                case .dependencyMissing: .toolMissing
                case .timeout: .timeout
                case .unauthorized: .permissionDenied
                case .malformedOutput: .malformedResponse
                default: .toolFailure
                }
                return HealthResult(
                    name: "DEBUGSERVER", status: .unknown, severity: .high,
                    expected: "CoreDevice LLDB debugging service is measurable",
                    rootCause: error.localizedDescription, failureKind: kind
                )
            } catch {
                return HealthResult(
                    name: "DEBUGSERVER", status: .unknown, severity: .high,
                    expected: "CoreDevice LLDB debugging service is measurable",
                    rootCause: error.localizedDescription, failureKind: .unexpected
                )
            }
        }
    }
    public func checkHealth() async -> HealthResult {
        await probe.run()
    }
}

public struct LLDBAdapter: HealthCheckingAdapter {
    public let component = "LLDB"
    private let runner: ScriptRunner
    public init(runner: ScriptRunner) { self.runner = runner }
    public func checkHealth() async -> HealthResult {
        do {
            let result = try await runner.run(ScriptSpecification(
                identifier: "health.lldb-host", executableURL: URL(fileURLWithPath: "/usr/bin/xcrun"),
                arguments: ["lldb", "--version"], timeout: .seconds(15)
            ))
            return HealthResult(name: component, status: result.succeeded ? .pass : .fail, severity: .medium,
                                observed: ["available": .bool(result.succeeded)], expected: "host LLDB is available",
                                rootCause: result.succeeded ? nil : result.stderr,
                                rawEvidence: [result.stdout, result.stderr], durationMS: Int(result.duration * 1000),
                                failureKind: result.succeeded ? nil : .toolMissing)
        } catch {
            return HealthResult(name: component, status: .unknown, severity: .medium,
                                expected: "host LLDB is measurable", rootCause: error.localizedDescription,
                                failureKind: .unexpected)
        }
    }
}

public struct SSHAdapter: RecoverableAdapter {
    public let component = "SSH"
    private let manager: SSHManager
    private let profile: DeviceProfile
    public init(manager: SSHManager, profile: DeviceProfile) { self.manager = manager; self.profile = profile }
    public func checkHealth() async -> HealthResult {
        let start = ContinuousClock.now
        let result = await manager.probe(profile)
        return HealthResult(
            name: component, status: result.succeeded ? .pass : .fail, severity: .high,
            observed: ["exit_code": .number(Double(result.exitCode))], expected: "authenticated root SSH probe succeeds",
            rootCause: result.succeeded ? nil : (result.stderr.isEmpty ? "SSH probe failed" : result.stderr),
            remediation: result.succeeded ? [] : ["reconnect the exact-device SSH forward"],
            durationMS: Int(start.duration(to: .now).components.attoseconds / 1_000_000_000_000_000),
            failureKind: result.succeeded ? nil : .connectionLost
        )
    }
    public func connect() async -> OperationResult { await probeOperation("SSH connection") }
    public func disconnect() async -> OperationResult {
        OperationResult(succeeded: true, message: "SSH adapter has no persistent unmanaged process to terminate.")
    }
    public func recover() async -> OperationResult { await probeOperation("SSH recovery") }
    private func probeOperation(_ name: String) async -> OperationResult {
        let result = await manager.probe(profile)
        return OperationResult(succeeded: result.succeeded,
                               failureKind: result.succeeded ? nil : .connectionLost,
                               message: result.succeeded ? "\(name) succeeded." : "\(name) failed.")
    }
}

public struct DeveloperServicesAdapter: HealthCheckingAdapter {
    public let component = "DEVELOPER_SERVICES"
    private let manager: ResearcherOperationsManager
    public init(manager: ResearcherOperationsManager) { self.manager = manager }
    public func checkHealth() async -> HealthResult {
        let start = Date()
        do {
            let result = try await manager.checkDeveloperServices()
            return HealthResult(name: component, status: result.succeeded ? .pass : .fail, severity: .high,
                                observed: ["exit_code": .number(Double(result.exitCode))],
                                expected: "developer services are listed by CoreDevice",
                                rootCause: result.succeeded ? nil : result.stderr,
                                durationMS: Int(Date().timeIntervalSince(start) * 1000),
                                failureKind: result.succeeded ? nil : .toolFailure)
        } catch let error as BridgeCoreError {
            return HealthResult(name: component, status: .unknown, severity: .high,
                                expected: "developer services status is measurable",
                                rootCause: error.localizedDescription,
                                durationMS: Int(Date().timeIntervalSince(start) * 1000),
                                failureKind: Self.kind(error))
        } catch {
            return HealthResult(name: component, status: .unknown, severity: .high,
                                expected: "developer services status is measurable",
                                rootCause: error.localizedDescription, failureKind: .unexpected)
        }
    }
    private static func kind(_ error: BridgeCoreError) -> AdapterFailureKind {
        switch error {
        case .dependencyMissing: .toolMissing
        case .timeout: .timeout
        case .malformedOutput: .malformedResponse
        case .unauthorized: .permissionDenied
        default: .toolFailure
        }
    }
}

public enum RecoveryTier: Int, Codable, Comparable, Sendable {
    case automaticSafe = 1, confirmationRequired = 2, highRisk = 3
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

public struct RetryPolicy: Codable, Hashable, Sendable {
    public let maximumRetryCount: Int
    public let backoffMilliseconds: [UInt64]
    public let cooldownMilliseconds: UInt64
    public init(maximumRetryCount: Int = 4,
                backoffMilliseconds: [UInt64] = [0, 1_000, 3_000, 10_000],
                cooldownMilliseconds: UInt64 = 30_000) {
        self.maximumRetryCount = max(0, maximumRetryCount)
        self.backoffMilliseconds = Array(backoffMilliseconds.prefix(maximumRetryCount))
        self.cooldownMilliseconds = cooldownMilliseconds
    }
}

public struct RecoveryAction: Codable, Hashable, Sendable {
    public let id: String
    public let component: String
    public let tier: RecoveryTier
    public let description: String
    public init(id: String, component: String, tier: RecoveryTier, description: String) {
        self.id = id; self.component = component; self.tier = tier; self.description = description
    }
}

public struct RecoveryOutcome: Codable, Sendable {
    public let action: RecoveryAction
    public let attempts: Int
    public let succeeded: Bool
    public let lastReason: String
    public let lastResult: OperationResult?
    public let exhausted: Bool
}

public actor RecoveryPolicyEngine {
    public typealias Executor = @Sendable () async -> OperationResult
    private let events: EventBus
    private var cooldownUntil: [String: Date] = [:]
    public init(events: EventBus) { self.events = events }

    public func execute(action: RecoveryAction, deviceID: String, reason: String,
                        policy: RetryPolicy = RetryPolicy(), confirmed: Bool = false,
                        executor: @escaping Executor) async -> RecoveryOutcome {
        guard action.tier == .automaticSafe || (action.tier == .confirmationRequired && confirmed) else {
            return RecoveryOutcome(action: action, attempts: 0, succeeded: false,
                                   lastReason: action.tier == .highRisk ? "high-risk action is never automatic" : "user confirmation required",
                                   lastResult: nil, exhausted: false)
        }
        if let deadline = cooldownUntil[action.id], deadline > Date() {
            return RecoveryOutcome(action: action, attempts: 0, succeeded: false,
                                   lastReason: "recovery action is cooling down", lastResult: nil, exhausted: false)
        }
        let correlation = UUID()
        await events.publish(BridgeEvent(event: .recoveryStarted, deviceID: deviceID,
                                         component: action.component, message: reason,
                                         correlationID: correlation))
        var last: OperationResult?
        for attempt in 0..<policy.maximumRetryCount {
            if Task.isCancelled { break }
            let delay = attempt < policy.backoffMilliseconds.count ? policy.backoffMilliseconds[attempt] : 0
            if delay > 0 { try? await Task.sleep(for: .milliseconds(delay)) }
            let result = await executor(); last = result
            if result.succeeded {
                cooldownUntil.removeValue(forKey: action.id)
                await events.publish(BridgeEvent(event: .recoverySucceeded, deviceID: deviceID,
                                                 component: action.component, message: result.message,
                                                 observed: ["attempts": .number(Double(attempt + 1))],
                                                 correlationID: correlation))
                return RecoveryOutcome(action: action, attempts: attempt + 1, succeeded: true,
                                       lastReason: reason, lastResult: result, exhausted: false)
            }
        }
        cooldownUntil[action.id] = Date().addingTimeInterval(Double(policy.cooldownMilliseconds) / 1000)
        await events.publish(BridgeEvent(event: .recoveryFailed, deviceID: deviceID,
                                         severity: .warning, component: action.component,
                                         message: last?.message ?? "Recovery retry limit reached.",
                                         correlationID: correlation))
        return RecoveryOutcome(action: action, attempts: policy.maximumRetryCount,
                               succeeded: false, lastReason: reason, lastResult: last, exhausted: true)
    }
}

public enum ActiveTransport: String, Codable, Sendable { case wifi = "WI_FI", usb = "USB", none = "NONE" }

public struct ConnectionMetrics: Codable, Sendable {
    public var primary: ActiveTransport
    public var fallback: ActiveTransport
    public var usb: ComponentCondition
    public var wifi: ComponentCondition
    public var remoteXPC: ComponentCondition
    public var ssh: ComponentCondition
    public var latencyMS: Double?
    public var lastSuccessfulHeartbeat: Date?
    public var reconnectCount: Int
    public var sessionStartedAt: Date?
    public var lastDisconnectReason: String?
    public var lastReconnectAt: Date?
}

public actor TransportCoordinator {
    private let events: EventBus
    private var metrics: [String: ConnectionMetrics] = [:]
    public init(events: EventBus) { self.events = events }

    public func update(deviceID: String, usb: Bool, wifi: Bool, reason: String? = nil) async -> ConnectionMetrics {
        var value = metrics[deviceID] ?? ConnectionMetrics(
            primary: .none, fallback: .none, usb: .unknown, wifi: .unknown,
            remoteXPC: .unknown, ssh: .unknown, latencyMS: nil,
            lastSuccessfulHeartbeat: nil, reconnectCount: 0, sessionStartedAt: Date(),
            lastDisconnectReason: nil, lastReconnectAt: nil
        )
        let oldPrimary = value.primary
        value.usb = usb ? .ready : .unavailable
        value.wifi = wifi ? .ready : .unavailable
        value.primary = wifi ? .wifi : (usb ? .usb : .none)
        value.fallback = wifi && usb ? .usb : .none
        if oldPrimary != value.primary {
            if oldPrimary != .none { value.reconnectCount += 1; value.lastReconnectAt = Date() }
            if value.primary == .none { value.lastDisconnectReason = DiagnosticRedactor.redact(reason ?? "all transports unavailable") }
        }
        metrics[deviceID] = value
        if oldPrimary == .wifi && !wifi {
            await events.publish(BridgeEvent(event: .wifiLost, deviceID: deviceID, severity: .warning,
                                             component: "wifi", message: usb ? "Wi-Fi lost; session continued over USB." : "Wi-Fi transport lost."))
        } else if oldPrimary == .usb && !usb && wifi {
            await events.publish(BridgeEvent(event: .usbLost, deviceID: deviceID, severity: .warning,
                                             component: "usb", message: "USB lost; session continued over Wi-Fi."))
        }
        return value
    }

    public func heartbeat(deviceID: String, latencyMS: Double, remoteXPC: Bool, ssh: Bool) {
        guard var value = metrics[deviceID] else { return }
        value.latencyMS = max(0, latencyMS); value.lastSuccessfulHeartbeat = Date()
        value.remoteXPC = remoteXPC ? .ready : .failed; value.ssh = ssh ? .ready : .failed
        metrics[deviceID] = value
    }

    public func status(deviceID: String) -> ConnectionMetrics? { metrics[deviceID] }

    public func remove(deviceID: String) { metrics.removeValue(forKey: deviceID) }
}

public struct OwnedProcess: Codable, Hashable, Sendable {
    public let pid: Int32
    public let processType: String
    public let deviceID: String?
    public let startedAt: Date
    public let commandIdentifier: String
    public let ownership: String
}

public actor OwnedProcessRegistry {
    private var values: [Int32: OwnedProcess] = [:]
    public init() {}
    public func register(_ process: OwnedProcess) { values[process.pid] = process }
    public func remove(pid: Int32) { values.removeValue(forKey: pid) }
    public func all() -> [OwnedProcess] { values.values.sorted { $0.startedAt < $1.startedAt } }
    public func terminate(pid: Int32) -> Bool {
        guard values[pid]?.ownership == "0-Sky" else { return false }
        guard kill(pid, SIGTERM) == 0 else { return false }
        values.removeValue(forKey: pid); return true
    }
}

/// Service-side facade used by GUI/CLI clients. IPC transports can expose this
/// narrow API without moving device logic into UI callbacks.
public actor BridgeService {
    public let events: EventBus
    public let states: DeviceStateStore
    public let transports: TransportCoordinator
    public let recovery: RecoveryPolicyEngine
    public let sessions: ResearchSessionRecorder

    public init(supportRoot: URL, events: EventBus = EventBus()) {
        self.events = events
        self.states = DeviceStateStore(events: events)
        self.transports = TransportCoordinator(events: events)
        self.recovery = RecoveryPolicyEngine(events: events)
        self.sessions = ResearchSessionRecorder(
            root: supportRoot.appendingPathComponent("research_sessions", isDirectory: true), events: events
        )
    }
}
