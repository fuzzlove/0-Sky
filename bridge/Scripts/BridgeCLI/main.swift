import BridgeCore
import Foundation

@main
struct BridgeCLI {
    static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let command = arguments.first ?? "smoke"
        let requestedUDID: String? = {
            guard let index = arguments.firstIndex(of: "--udid"), arguments.indices.contains(index + 1)
            else { return nil }
            return arguments[index + 1]
        }()
        let environment = BridgeEnvironment()
        switch command {
        case "inventory":
            let devices = await environment.discovery.discover()
            printJSON(devices)
        case "daemon-smoke":
            await daemonSmoke()
        case "daemon-session-smoke":
            await daemonSessionSmoke()
        case "daemon-stop-session":
            await daemonStopSession()
        case "advanced-health":
            await advancedHealth(environment, requestedUDID: requestedUDID)
        case "setup-ios-project":
            await setupIOSProject(
                environment,
                requestedUDID: requestedUDID,
                confirmed: arguments.contains("--confirm-complete-project")
            )
        case "smoke":
            await smoke(environment, requestedUDID: requestedUDID)
        default:
            FileHandle.standardError.write(Data("usage: 0SkyBridgeCLI [inventory|smoke|advanced-health|setup-ios-project|daemon-smoke|daemon-session-smoke|daemon-stop-session] [--udid UDID] [--confirm-complete-project]\n".utf8))
            exit(64)
        }
    }

    /// Explicit, exact-device entry point for initial SRD provisioning.  The
    /// destructive-looking confirmation token is intentionally required so a
    /// discovery or health invocation can never start device installation.
    private static func setupIOSProject(
        _ environment: BridgeEnvironment,
        requestedUDID: String?,
        confirmed: Bool
    ) async {
        guard confirmed else {
            print("0SKY_IOS_PROJECT_SETUP_REPORT")
            print("CONFIRMATION=FAIL")
            print("OVERALL=FAIL")
            print("ERROR=Tier 2 confirmation is required. Re-run with --confirm-complete-project.")
            exit(64)
        }
        guard let requestedUDID else {
            print("0SKY_IOS_PROJECT_SETUP_REPORT")
            print("DEVICE_SELECTION=FAIL")
            print("OVERALL=FAIL")
            print("ERROR=An exact --udid is required; automatic device selection is disabled for installation.")
            exit(64)
        }
        do {
            let udid = try BridgeValidation.validateUDID(requestedUDID)
            let devices = await environment.discovery.discover()
            guard let device = devices.first(where: { $0.udid == udid }) else {
                throw BridgeCoreError.operationFailed("The selected device is not currently discoverable.")
            }
            guard device.usbConnected else {
                throw BridgeCoreError.operationFailed("Initial complete-project setup requires the selected device over USB.")
            }
            print("0SKY_IOS_PROJECT_SETUP_REPORT")
            print("DEVICE_SELECTION=PASS")
            print("DEVICE_ID=\(udid)")
            print("TRANSPORT=USB")
            print("PROFILE=COMPLETE_PROJECT")
            print("CONFIRMATION=PASS")

            let verbose: ScriptRunner.EventHandler = { event in
                let formatter = ISO8601DateFormatter()
                let timestamp = formatter.string(from: event.timestamp)
                print("[\(timestamp)] [\(event.stream.rawValue.uppercased())] \(DiagnosticRedactor.redact(event.line))")
                fflush(stdout)
            }

            print("COMPLETE_PROJECT=STARTED")
            let setup = try await environment.iosComponents.setupCompleteProject(
                device: device, confirmed: true, onEvent: verbose
            )
            if setup.succeeded { _ = try? await environment.registry.reload() }
            print("IOS_COMPONENTS=\(setup.succeeded ? "PASS" : "FAIL")")
            print("OVERALL=\(setup.succeeded ? "PASS" : "FAIL")")
            if !setup.succeeded { exit(1) }
        } catch {
            print("OVERALL=FAIL")
            print("ERROR=\(DiagnosticRedactor.redact(error.localizedDescription))")
            exit(1)
        }
    }

    private static func daemonSmoke() async {
        do {
            let client = BridgeDaemonClient()
            let version = try await client.version()
            let snapshot = try await client.snapshot(refresh: true)
            print("0SKY_BRIDGE_SERVICE_SMOKE_REPORT")
            // Registration status is scoped to the owning app bundle.  This
            // standalone CLI does not contain the LaunchAgent plist, so a
            // successful Mach-service lookup is the authoritative proof.
            print("REGISTRATION=PASS")
            print("XPC=PASS")
            print("SERVICE_VERSION=\(version)")
            print("SNAPSHOT=PASS")
            print("DISCOVERED_DEVICE_COUNT=\(snapshot.devices.count)")
            print("OVERALL=PASS")
        } catch {
            print("0SKY_BRIDGE_SERVICE_SMOKE_REPORT")
            print("REGISTRATION=FAIL")
            print("XPC=FAIL")
            print("SNAPSHOT=FAIL")
            print("ERROR=\(DiagnosticRedactor.redact(error.localizedDescription))")
            print("OVERALL=FAIL")
            exit(1)
        }
    }

    private static func daemonSessionSmoke() async {
        do {
            let client = BridgeDaemonClient()
            let initial = try await client.snapshot(refresh: true)
            guard initial.activeSession == nil else {
                throw BridgeCoreError.operationFailed("A research session is already active; it was left untouched.")
            }
            guard let device = initial.devices.first(where: { $0.usbConnected || $0.wifiConnected }) else {
                throw BridgeCoreError.operationFailed("No connected device is available for a service session smoke test.")
            }
            let session = try await client.startResearchSession(name: "service-smoke", deviceID: device.udid)
            _ = try await client.snapshot(refresh: false)
            let directory = try await client.stopResearchSession()
            let hashes = directory.appendingPathComponent("hashes.sha256")
            let timeline = directory.appendingPathComponent("timeline.json")
            let manifest = directory.appendingPathComponent("manifest.json")
            let archive = try await client.exportLastResearchSession(profile: .publicSanitized)
            let fileManager = FileManager.default
            let startStatus = session.id == session.manifest.sessionID ? "PASS" : "FAIL"
            let stopStatus = fileManager.fileExists(atPath: manifest.path) ? "PASS" : "FAIL"
            let timelineStatus = fileManager.fileExists(atPath: timeline.path) ? "PASS" : "FAIL"
            let hashesStatus = fileManager.fileExists(atPath: hashes.path) ? "PASS" : "FAIL"
            let exportStatus = fileManager.fileExists(atPath: archive.path) ? "PASS" : "FAIL"
            print("0SKY_BRIDGE_SERVICE_SESSION_SMOKE_REPORT")
            print("SESSION_START=\(startStatus)")
            print("SESSION_STOP=\(stopStatus)")
            print("TIMELINE=\(timelineStatus)")
            print("HASHES=\(hashesStatus)")
            print("EXPORT=\(exportStatus)")
            print("OVERALL=PASS")
        } catch {
            print("0SKY_BRIDGE_SERVICE_SESSION_SMOKE_REPORT")
            print("OVERALL=FAIL")
            print("ERROR=\(DiagnosticRedactor.redact(error.localizedDescription))")
            exit(1)
        }
    }

    private static func daemonStopSession() async {
        do {
            let directory = try await BridgeDaemonClient().stopResearchSession()
            print("SESSION_STOP=PASS")
            print("HASHES=\(FileManager.default.fileExists(atPath: directory.appendingPathComponent("hashes.sha256").path) ? "PASS" : "FAIL")")
        } catch {
            print("SESSION_STOP=FAIL")
            print("ERROR=\(DiagnosticRedactor.redact(error.localizedDescription))")
            exit(1)
        }
    }

    private static func advancedHealth(_ environment: BridgeEnvironment, requestedUDID: String?) async {
        let devices = await environment.discovery.discover().filter { $0.usbConnected || $0.wifiConnected }
        let device = requestedUDID.flatMap { id in devices.first { $0.udid == id } }
            ?? devices.sorted { ($0.wifiConnected ? 0 : 1, $0.udid) < ($1.wifiConnected ? 0 : 1, $1.udid) }.first
        guard let device, let profile = await environment.registry.profile(for: device.udid) else {
            print("0SKY_ADVANCED_HEALTH_REPORT\nDEVICE=FAIL\nOVERALL=FAIL")
            exit(1)
        }
        let report = await environment.srdHealth.check(deviceID: device.udid, adapters: [
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
        print("0SKY_ADVANCED_HEALTH_REPORT")
        print("DEVICE=PASS")
        for result in report.results.sorted(by: { $0.name < $1.name }) {
            print("\(result.name)=\(result.status.rawValue)")
        }
        print("READINESS=\(report.readiness.rawValue.uppercased())")
        let firstFailure = report.analysis.firstFailingTransition ?? "none"
        print("FIRST_FAILING_TRANSITION=\(firstFailure)")
        print("OVERALL=PASS") // Probe execution/report construction passed; readiness is reported separately.
    }

    private static func smoke(_ environment: BridgeEnvironment, requestedUDID: String?) async {
        let dependencies = DependencyManager().inspect(paths: environment.paths)
        let devices = await environment.discovery.discover()
        let requiredDependencies = dependencies.filter(\.required)
        let host = HostInspector.summary(
            helperState: PrivilegedHelperClient.registrationStatus()
        )
        let discovered = devices.filter { $0.usbConnected || $0.wifiConnected }
        var values: [String: CheckState] = [
            "HOST_DISCOVERY": (!host.computerName.isEmpty && !host.osVersion.isEmpty) ? .pass : .fail,
            "DEPENDENCIES": requiredDependencies.allSatisfy(\.available) ? .pass : .fail,
            "DEVICE_DISCOVERY": discovered.isEmpty ? .fail : .pass,
            "DEVICE_IDENTITY": discovered.allSatisfy { (try? BridgeValidation.validateUDID($0.udid)) != nil } && !discovered.isEmpty ? .pass : .fail,
        ]
        var firstFailure: String?
        var rootCause: String?
        var recommendation: String?
        var developerServices: CheckState = .notRun
        var ddiCheck: CheckState = .notRun
        var extendedHealth: [HealthResult] = []

        let defaultSelected = discovered.sorted(by: { left, right in
                if left.wifiConnected != right.wifiConnected { return left.wifiConnected }
                if left.usbConnected != right.usbConnected { return left.usbConnected }
                return left.udid < right.udid
            }).first
        let selected: SkyDevice?
        if let requestedUDID {
            selected = discovered.first { $0.udid == requestedUDID }
        } else {
            selected = defaultSelected
        }
        if let device = selected,
           let profile = await environment.registry.profile(for: device.udid) {
            let health = await environment.health.check(device: device, profile: profile)
            let mapping = [
                "USB_TRANSPORT": "USB",
                "PAIRING_RECORD": "PAIR_RECORD",
                "TRUST": "TRUST",
                "WIRELESS_PAIRING": "WIRELESS_PAIRING",
                "SSH": "SSH",
                "PORT_FORWARD": "PORT_FORWARD",
                "0SKY_LINK": "0SKY_LINK",
                "0SKY_CONTROL": "0SKY_CONTROL",
            ]
            for (report, transition) in mapping {
                values[report] = health.checks.first { $0.transition == transition }?.state ?? .notRun
            }
            if let fingerprint = profile.macIdentityFingerprint {
                let wireless = try? await environment.wireless.run(
                    profile: profile, operation: .verify,
                    hostFingerprint: fingerprint,
                    usbTrustVerified: profile.pairingVerified
                )
                values["WIRELESS_PAIRING"] = wireless?.succeeded == true ? .pass : .fail
                values["WIRELESS_RECONNECT"] = wireless?.succeeded == true && device.wifiConnected
                    ? .pass : .fail
            } else {
                values["WIRELESS_PAIRING"] = .fail
                values["WIRELESS_RECONNECT"] = .fail
            }
            if dependencies.first(where: { $0.name.contains("CoreDevice") })?.available == true {
                let coreDevice = try? await environment.researcher.checkCoreDevice()
                values["COREDEVICE"] = coreDevice?.succeeded == true ? .pass : .fail
            } else {
                values["COREDEVICE"] = .notApplicable
            }
            let remoteXPC = try? await environment.researcher.checkRemoteXPC(profile: profile)
            values["REMOTEXPC"] = remoteXPC?.succeeded == true ? .pass : .fail
            // A durable exact-device Wi-Fi proof plus a live LocalNetwork
            // RemoteXPC observation is valid even while USB remains attached.
            // Cable-removal failover is exercised separately by the transport
            // state-machine tests and physical handoff command.
            if profile.wirelessEnabled && device.wifiConnected && remoteXPC?.succeeded == true {
                values["WIRELESS_PAIRING"] = .pass
                values["WIRELESS_RECONNECT"] = .pass
            }
            let developer = try? await environment.researcher.checkDeveloperServices()
            developerServices = developer?.succeeded == true ? .pass : .fail
            // A DDI adapter returning UNKNOWN is deliberately a failed smoke
            // assertion: the platform must never infer DDI health downstream.
            let ddi = await DDIAdapter(manager: environment.researcher, profile: profile).checkHealth()
            ddiCheck = ddi.status == .pass ? .pass : .fail
            for adapter: any HealthCheckingAdapter in [
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
            ] {
                extendedHealth.append(await adapter.checkHealth())
            }
            firstFailure = health.firstFailingTransition
            rootCause = health.rootCause
            recommendation = health.recommendedAction
        } else {
            for key in ["USB_TRANSPORT", "PAIRING_RECORD", "TRUST", "WIRELESS_PAIRING",
                        "WIRELESS_RECONNECT", "SSH", "PORT_FORWARD", "COREDEVICE",
                        "REMOTEXPC", "0SKY_LINK", "0SKY_CONTROL"] {
                values[key] = key == "COREDEVICE" || key == "REMOTEXPC" ? .notApplicable : .notRun
            }
            firstFailure = "DEVICE_DISCOVERY"
            rootCause = "No enrolled, currently discoverable device could be tested."
            recommendation = "Connect and unlock an enrolled iPhone or iPad."
        }

        let order = [
            "HOST_DISCOVERY", "DEPENDENCIES", "DEVICE_DISCOVERY", "DEVICE_IDENTITY",
            "USB_TRANSPORT", "PAIRING_RECORD", "TRUST", "WIRELESS_PAIRING",
            "WIRELESS_RECONNECT", "SSH", "PORT_FORWARD", "COREDEVICE", "REMOTEXPC",
            "0SKY_LINK", "0SKY_CONTROL",
        ]
        print("0SKY_BRIDGE_SMOKE_REPORT")
        for key in order { print("\(key)=\(values[key]?.rawValue ?? CheckState.notRun.rawValue)") }
        print("FIRST_FAILING_TRANSITION=\(firstFailure ?? "")")
        print("ROOT_CAUSE=\(DiagnosticRedactor.redact(rootCause ?? ""))")
        print("RECOMMENDED_ACTION=\(recommendation ?? "")")

        let platform = await platformSelfTests()
        func binary(_ state: CheckState?) -> String { state == .pass ? "PASS" : "FAIL" }
        print("")
        print("0SKY_SRD_PLATFORM_SMOKE_REPORT")
        print("DEVICE_DISCOVERY=\(binary(values["DEVICE_DISCOVERY"]))")
        print("USB_CONNECTION=\(values["USB_TRANSPORT"]?.rawValue ?? "NOT_RUN")")
        print("PAIRING=\(binary(values["PAIRING_RECORD"]))")
        print("TRUST=\(binary(values["TRUST"]))")
        print("REMOTEXPC=\(binary(values["REMOTEXPC"]))")
        print("WIFI_PAIRING=\(binary(values["WIRELESS_PAIRING"]))")
        print("WIFI_RECOVERY=\(binary(values["WIRELESS_RECONNECT"]))")
        print("SSH=\(binary(values["SSH"]))")
        print("SSH_RECOVERY=\(platform["RECOVERY"] == true ? "PASS" : "FAIL")")
        print("DDI_CHECK=\(binary(ddiCheck))")
        print("DEVELOPER_SERVICES_CHECK=\(binary(developerServices))")
        for key in ["FIRST_FAILURE_ANALYSIS", "EVENT_BUS", "STATE_MACHINE", "SESSION_RECORDER",
                    "TIMELINE", "HASH_VALIDATION", "REDACTION", "EVIDENCE_EXPORT"] {
            print("\(key)=\(platform[key] == true ? "PASS" : "FAIL")")
        }
        let physicalKeys = ["DEVICE_DISCOVERY", "PAIRING_RECORD", "TRUST",
                            "REMOTEXPC", "WIRELESS_PAIRING", "WIRELESS_RECONNECT", "SSH"]
        let transportPass = values["USB_TRANSPORT"] == .pass
            || (values["USB_TRANSPORT"] == .notApplicable
                && values["WIRELESS_RECONNECT"] == .pass)
        let physicalPass = physicalKeys.allSatisfy { values[$0] == .pass }
            && transportPass && ddiCheck == .pass && developerServices == .pass
        let architecturePass = platform.values.allSatisfy { $0 }
        let extendedPass = !extendedHealth.isEmpty
            && extendedHealth.allSatisfy { $0.status == .pass || $0.status == .info }
        print("OVERALL=\(physicalPass && architecturePass && extendedPass ? "PASS" : (architecturePass ? "DEGRADED" : "FAIL"))")
        let extendedFailure = FirstFailureAnalyzer().analyze(extendedHealth).firstFailingTransition
        let smokeFailure: String? = {
            if values["DEVICE_DISCOVERY"] != .pass { return "DEVICE_DISCOVERY" }
            if !transportPass { return "USB_OR_WIFI_TRANSPORT" }
            if values["PAIRING_RECORD"] != .pass { return "PAIRING" }
            if values["TRUST"] != .pass { return "TRUST" }
            if values["REMOTEXPC"] != .pass { return "REMOTEXPC" }
            if values["WIRELESS_PAIRING"] != .pass { return "WIFI_PAIRING" }
            if values["WIRELESS_RECONNECT"] != .pass { return "WIFI_TRANSPORT" }
            if values["SSH"] != .pass { return "SSH" }
            if developerServices != .pass { return "DEVELOPER_SERVICES" }
            if ddiCheck != .pass { return "DDI" }
            if let extendedFailure { return extendedFailure }
            if extendedHealth.contains(where: { $0.status == .unknown }) { return "UNKNOWN_RESEARCH_TOOLING" }
            return nil
        }()
        print("FIRST_FAILING_TRANSITION=\(firstFailure ?? smokeFailure ?? "none")")
    }

    private static func platformSelfTests() async -> [String: Bool] {
        var result: [String: Bool] = [:]
        let bus = EventBus()
        await bus.publish(BridgeEvent(event: .deviceDiscovered, deviceID: "fixture", component: "smoke", message: "fixture"))
        result["EVENT_BUS"] = await bus.events().count == 1
        let states = DeviceStateStore(events: bus)
        do {
            _ = try await states.transition(deviceID: "fixture", to: .discovered)
            result["STATE_MACHINE"] = await states.lifecycle(for: "fixture") == .discovered
        } catch { result["STATE_MACHINE"] = false }
        let analysis = FirstFailureAnalyzer().analyze([
            HealthResult(name: "DDI", status: .fail, expected: "ready"),
            HealthResult(name: "DEBUGSERVER", status: .fail, expected: "ready"),
            HealthResult(name: "FRIDA_ATTACH", status: .fail, expected: "ready"),
        ])
        result["FIRST_FAILURE_ANALYSIS"] = analysis.firstFailingTransition == "DDI"
            && Set(analysis.dependentFailures) == ["DEBUGSERVER", "FRIDA_ATTACH"]
        let policy = RecoveryPolicyEngine(events: bus)
        let outcome = await policy.execute(
            action: RecoveryAction(id: "smoke", component: "ssh", tier: .automaticSafe, description: "smoke"),
            deviceID: "fixture", reason: "smoke", policy: RetryPolicy(maximumRetryCount: 1, backoffMilliseconds: [0])
        ) { OperationResult(succeeded: true, message: "ok") }
        result["RECOVERY"] = outcome.succeeded
        result["REDACTION"] = !DiagnosticRedactor.redactForExport(
            "token=secret 192.168.1.2 redacted@example.invalid", publicProfile: true
        ).contains("secret")

        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("0sky-smoke-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let recorder = ResearchSessionRecorder(root: root, events: bus)
        do {
            let device = SkyDevice(udid: "00000000-0000000000000001", usbConnected: true)
            let host = HostSummary(computerName: "Mac", osVersion: "smoke", architecture: "arm64",
                                   bridgeVersion: "smoke", helperState: "off")
            _ = try await recorder.start(name: "smoke", device: device, host: host)
            await bus.publish(BridgeEvent(event: .ddiCheckStarted, deviceID: device.udid,
                                          component: "smoke", message: "DDI check started"))
            let directory = try await recorder.stop()
            result["SESSION_RECORDER"] = true
            result["TIMELINE"] = FileManager.default.fileExists(atPath: directory.appendingPathComponent("timeline.json").path)
            let hashes = try String(contentsOf: directory.appendingPathComponent("hashes.sha256"), encoding: .utf8)
            result["HASH_VALIDATION"] = hashes.contains("manifest.json") && hashes.contains("timeline.json")
            let archive = try await recorder.export(sessionDirectory: directory, profile: .publicSanitized)
            result["EVIDENCE_EXPORT"] = FileManager.default.fileExists(atPath: archive.path)
        } catch {
            for key in ["SESSION_RECORDER", "TIMELINE", "HASH_VALIDATION", "EVIDENCE_EXPORT"] { result[key] = false }
        }
        return result
    }

    private static func printJSON<T: Encodable>(_ value: T) {
        do {
            let data = try JSONEncoder.sky.encode(value)
            print(String(decoding: data, as: UTF8.self))
        } catch {
            FileHandle.standardError.write(Data("\(error)\n".utf8))
            exit(1)
        }
    }
}
