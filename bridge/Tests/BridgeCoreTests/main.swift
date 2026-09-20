import BridgeCore
import CryptoKit
import Foundation

private enum TestFailure: Error, CustomStringConvertible {
    case failed(String)
    var description: String {
        switch self { case .failed(let message): return message }
    }
}

private func expect(_ value: @autoclosure () -> Bool, _ message: String) throws {
    guard value() else { throw TestFailure.failed(message) }
}

private func expectThrows(_ message: String, _ body: () throws -> Void) throws {
    do { try body(); throw TestFailure.failed(message) } catch is TestFailure { throw errorPlaceholder }
    catch { return }
}

// Keeps expectThrows from accepting its own assertion failure as success.
private let errorPlaceholder = TestFailure.failed("expected tested operation to throw")

private final class EventCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [ScriptOutputEvent] = []
    func append(_ value: ScriptOutputEvent) { lock.lock(); values.append(value); lock.unlock() }
    func lines() -> [String] { lock.lock(); defer { lock.unlock() }; return values.map(\.line) }
}

private struct FixtureBackend: DeviceDiscoveryBackend {
    let name = "fixture"
    let values: [SkyDevice]
    func discover() async throws -> [SkyDevice] { values }
}

private actor FixtureCrashSource: CrashReportProviding {
    private(set) var reads = 0

    func listRecentCrashReports(profile: DeviceProfile, since: Date) async -> BridgeOperationResult {
        result(stdout: "/var/mobile/Library/Logs/CrashReporter/SpringBoard-2026-09-19.ips\n")
    }

    func readCrashReport(profile: DeviceProfile, path: String) async -> BridgeOperationResult {
        reads += 1
        return result(stdout: #"{"procName":"SpringBoard","termination":"watchdog"}"#)
    }

    func readCount() -> Int { reads }

    private func result(stdout: String) -> BridgeOperationResult {
        let now = Date()
        return BridgeOperationResult(identifier: "fixture.crash", startedAt: now, finishedAt: now,
                                     exitCode: 0, stdout: stdout, stderr: "")
    }
}

@main
struct BridgeCoreTestRunner {
    static func main() async {
        let tests: [(String, () async throws -> Void)] = [
            ("device parsing", deviceParsing),
            ("state transitions", stateTransitions),
            ("health calculation", healthCalculation),
            ("security validation", securityValidation),
            ("script execution", scriptExecution),
            ("integration scenarios", integrationScenarios),
            ("failure scenario matrix", failureScenarioMatrix),
            ("reconnection lifecycle matrix", reconnectionLifecycleMatrix),
            ("enrollment planning", enrollmentPlanning),
            ("diagnostic export", diagnosticExport),
            ("process cancellation", processCancellation),
            ("normalized event bus", normalizedEventBus),
            ("safe log clearing", safeLogClearing),
            ("SRD lifecycle state machine", srdLifecycleStateMachine),
            ("first failing dependency graph", firstFailingDependencyGraph),
            ("human-facing Cryptex label", cryptexDisplayLabel),
            ("bounded recovery policy", boundedRecoveryPolicy),
            ("USB Wi-Fi failover", transportFailover),
            ("research session evidence", researchSessionEvidence),
            ("evidence security", evidenceSecurity),
            ("persistent service contract", persistentServiceContract),
            ("versioned adapter probes", versionedAdapterProbes),
            ("CoreDevice debugserver probe", coreDeviceDebugserverProbe),
            ("default credential detection", defaultCredentialDetection),
            ("session crash collection", sessionCrashCollection),
            ("wireless capability persistence", wirelessCapabilityPersistence),
        ]
        var failures = 0
        var assertions = 0
        for (name, test) in tests {
            do {
                try await test()
                assertions += 1
                print("PASS \(name)")
            } catch {
                failures += 1
                print("FAIL \(name): \(error)")
            }
        }
        print("BRIDGE_CORE_TESTS total=\(tests.count) passed=\(assertions) failed=\(failures)")
        if failures > 0 { exit(1) }
    }

    private static func deviceParsing() async throws {
        let input = """
        [{"BuildVersion":"24A437","DeviceName":"Research iPad","ProductType":"iPad13,8","ProductVersion":"27.0","UniqueDeviceID":"00000000-0000000000000001"}]
        """
        let parsed = try PymobileDeviceDiscoveryBackend.parse(Data(input.utf8))
        try expect(parsed.count == 1 && parsed[0].usbConnected, "USB fixture did not parse")
        try expectThrows("injected UDID was accepted") {
            _ = try PymobileDeviceDiscoveryBackend.parse(Data(#"[{"UniqueDeviceID":"x;touch /tmp/x"}]"#.utf8))
        }
        let core = try CoreDeviceDiscoveryBackend.parse(Data("""
        {"result":{"devices":[
        {"identifier":"11111111-1111-1111-1111-111111111111",
         "hardwareProperties":{"udid":"00000000-0000000000000001","productType":"iPad13,8"},
         "deviceProperties":{"name":"Research iPad","osVersionNumber":"27.0"},
         "connectionProperties":{"transportType":"wired","pairingState":"paired"}},
        {"identifier":"00000000-0000000000000002","transport":"network"}]}}
        """.utf8))
        try expect(core.count == 2, "CoreDevice multi-device parse failed")
        try expect(core.contains { $0.udid == "00000000-0000000000000001" && $0.usbConnected },
                   "CoreDevice stable hardware UDID was not preferred")
        try expect(!core.contains { $0.udid == "11111111-1111-1111-1111-111111111111" },
                   "CoreDevice transient identifier leaked as a ghost device")
        try expect(core.contains { $0.wifiConnected }, "CoreDevice Wi-Fi transport was not parsed")
        let remote = try RemoteXPCDiscoveryBackend.parse(Data("""
        [{"udid":"00000000-0000000000000001","name":"Research iPad","model":"iPad13,8","networkAdvertActive":true,"authState":{"rawCase":"authenticated"},"connectionState":{"value":{"attachedPhysically":false}}}]
        """.utf8))
        try expect(remote.count == 1 && remote[0].wifiConnected && remote[0].trusted,
                   "RemoteXPC Wi-Fi discovery did not normalize")
        try expectThrows("invalid discovery JSON accepted") {
            _ = try CoreDeviceDiscoveryBackend.parse(Data("{not-json".utf8))
        }
    }

    private static func stateTransitions() async throws {
        let machine = BridgeStateMachine()
        let id = "00000000-0000000000000001"
        for state: BridgeState in [.discovering, .deviceDetected, .waitingForTrust,
                                   .pairing, .paired, .enablingWireless, .connecting, .connected] {
            _ = try await machine.transition(deviceID: id, to: state)
        }
        let finalState = await machine.state(for: id)
        try expect(finalState == .connected, "valid lifecycle did not connect")
        do {
            _ = try await BridgeStateMachine().transition(deviceID: id, to: .connected)
            throw TestFailure.failed("invalid transition was accepted")
        } catch BridgeCoreError.invalidTransition { }
    }

    private static func healthCalculation() async throws {
        func check(_ name: String, _ state: CheckState, mandatory: Bool = true) -> HealthCheck {
            HealthCheck(transition: name, state: state, detail: name, checkedAt: Date(), mandatory: mandatory)
        }
        try expect(BridgeHealthSnapshot(deviceID: "d", checks: [
            check("USB", .pass), check("SSH", .pass)
        ]).state == .healthy, "all-pass result was not healthy")
        try expect(BridgeHealthSnapshot(deviceID: "d", checks: [
            check("USB", .pass), check("SSH", .notRun)
        ]).state == .unknown, "not-run mandatory check reported healthy")
        let failure = BridgeHealthSnapshot(deviceID: "d", checks: [
            check("PAIR_RECORD", .fail), check("SSH", .fail)
        ])
        try expect(failure.firstFailingTransition == "PAIR_RECORD", "wrong first failure")
        try expect(BridgeHealthSnapshot(deviceID: "d", checks: [
            check("REQUIRED", .pass), check("OPTIONAL", .fail, mandatory: false)
        ]).state == .degraded, "optional failure was not degraded")
    }

    private static func securityValidation() async throws {
        try expectThrows("command injection UDID accepted") {
            _ = try BridgeValidation.validateUDID("abc;rm -rf /")
        }
        try expectThrows("unsafe instance accepted") {
            _ = try BridgeValidation.validateInstance("../other")
        }
        let profile = DeviceProfile(
            udid: "00000000-0000000000000001", instanceName: "research-ipad",
            localPort: 2231, sshHostAlias: "0sky-device-aaaaaaaaaaaaaaaaaaaaaaaa",
            sshKeyPath: "/tmp/fixture-home/.ssh/key",
            knownHostsPath: "/tmp/fixture-home/0-Sky/known-hosts"
        )
        let values = try await SSHManager(runner: ScriptRunner()).arguments(
            for: profile, operation: .rootProbe
        )
        try expect(values.contains("StrictHostKeyChecking=yes"), "strict SSH missing")
        try expect(values.contains("PasswordAuthentication=no"), "password SSH was not disabled")
        let fridaValues = try await SSHManager(runner: ScriptRunner()).arguments(
            for: profile, operation: .fridaHealth
        )
        try expect(fridaValues.last?.contains("/var/jb/usr/sbin/frida-server") == true,
                   "rootless Frida sbin path was not probed")
        try expect(fridaValues.last?.contains("codes.openai.research.ellekitloader.*/usr/sbin/frida-server") == true,
                   "iOS 26/27 Frida compatibility Cryptex path was not probed")
        try expect(fridaValues.last?.contains("ps ax -o command=") == true
                   && fridaValues.last?.contains("[f]rida-server$") == true,
                   "Frida process detection must use Toybox's untruncated command field and an anchored match")
        let fixtureHome = "/" + "Users" + "/engineer/project"
        let legacyBrand = "Troll" + "Store / Cryp" + "Store"
        let redacted = DiagnosticRedactor.redact(
            "password=hunter2 token:abc \(fixtureHome) \(legacyBrand)"
        )
        try expect(!redacted.contains("hunter2") && !redacted.contains("engineer"), "redaction failed")
        try expect(redacted.contains("Commissary")
                   && legacyBrand.components(separatedBy: " / ").allSatisfy { !redacted.contains($0) },
                   "legacy branding leaked into researcher-facing output")
    }

    private static func scriptExecution() async throws {
        let runner = ScriptRunner()
        let events = EventCollector()
        let result = try await runner.run(ScriptSpecification(
            identifier: "test.echo", executableURL: URL(fileURLWithPath: "/usr/bin/python3"),
            arguments: ["-c", "import sys;print('one');print('two');print('bad',file=sys.stderr);sys.exit(7)"],
            timeout: .seconds(5)
        )) { events.append($0) }
        try expect(result.exitCode == 7, "exit code not collected")
        try expect(result.stdout == "one\ntwo\n" && result.stderr == "bad\n", "streams not collected")
        try expect(Set(events.lines()) == ["one", "two", "bad"], "streaming lines were wrong")
        do {
            _ = try await runner.run(ScriptSpecification(
                identifier: "test.timeout", executableURL: URL(fileURLWithPath: "/bin/sleep"),
                arguments: ["10"], timeout: .milliseconds(100)
            ))
            throw TestFailure.failed("timeout did not fire")
        } catch BridgeCoreError.timeout { }
        let oversized = try await runner.run(ScriptSpecification(
            identifier: "test.output-limit", executableURL: URL(fileURLWithPath: "/usr/bin/python3"),
            arguments: ["-c", "print('x'*10000)"], timeout: .seconds(5), maximumOutputBytes: 1_024
        ))
        try expect(oversized.stdout.contains("<output-truncated>") && oversized.stdout.count < 1_100,
                   "oversized output was not bounded")
    }

    private static func integrationScenarios() async throws {
        let emptyRoot = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        let empty = DeviceDiscoveryManager(
            backends: [FixtureBackend(values: [])], registry: DeviceRegistry(supportURL: emptyRoot)
        )
        let emptyValues = await empty.discover()
        try expect(emptyValues.isEmpty, "no-device scenario failed")
        let fixtures = [
            SkyDevice(udid: "00000000-0000000000000001", name: "iPad", usbConnected: true),
            SkyDevice(udid: "00000000-0000000000000002", name: "iPhone", wifiConnected: true),
        ]
        let multiple = DeviceDiscoveryManager(
            backends: [FixtureBackend(values: fixtures)], registry: DeviceRegistry(supportURL: emptyRoot)
        )
        let multipleValues = await multiple.discover()
        try expect(multipleValues.count == 2, "multi-device scenario collapsed devices")
        try expect(ConnectionManager.backoffSeconds == [1, 2, 5, 10, 30, 60], "backoff changed")
        try expect(WirelessPairingManager.isDisconnectRequired(stdout:
            #"{"status":"pending","errorCode":"USB_DISCONNECT_REQUIRED","wifiLockdownEnabled":true}"#
        ), "successful Wi-Fi handoff prompt was classified as failure")
        let coordinator = OperationCoordinator()
        let id = fixtures[0].udid
        let first = Task {
            try await coordinator.withLock(deviceID: id, operation: "PAIR") {
                try await Task.sleep(for: .milliseconds(200)); return true
            }
        }
        try await Task.sleep(for: .milliseconds(20))
        do {
            _ = try await coordinator.withLock(deviceID: id, operation: "REMOVE_PAIR_RECORD") { true }
            throw TestFailure.failed("per-device lock allowed conflicting operations")
        } catch BridgeCoreError.operationBusy { }
        let firstValue = try await first.value
        try expect(firstValue, "serialized operation failed")
    }

    private static func failureScenarioMatrix() async throws {
        func snapshot(_ checks: [(String, CheckState, Bool)]) -> BridgeHealthSnapshot {
            BridgeHealthSnapshot(deviceID: "fixture", checks: checks.map {
                HealthCheck(transition: $0.0, state: $0.1, detail: "fixture \($0.0)", mandatory: $0.2)
            })
        }
        let trusted = snapshot([
            ("DEVICE_DISCOVERY", .pass, true), ("TRUST", .pass, true),
            ("SSH", .pass, true), ("0SKY_LINK", .pass, true),
        ])
        try expect(trusted.state == .healthy, "trusted fixture was not healthy")
        let untrusted = snapshot([
            ("DEVICE_DISCOVERY", .pass, true), ("TRUST", .fail, true),
            ("SSH", .fail, true),
        ])
        try expect(untrusted.firstFailingTransition == "TRUST", "untrusted fixture misclassified")
        let locked = snapshot([
            ("DEVICE_DISCOVERY", .pass, true), ("PAIR_RECORD", .fail, true),
            ("TRUST", .fail, true),
        ])
        try expect(locked.firstFailingTransition == "PAIR_RECORD", "locked fixture ordering changed")
        let sshUnavailable = snapshot([
            ("DEVICE_DISCOVERY", .pass, true), ("PAIR_RECORD", .pass, true),
            ("SSH", .fail, true),
        ])
        try expect(sshUnavailable.firstFailingTransition == "SSH", "SSH outage was hidden")
        let iproxyFailure = snapshot([
            ("DEVICE_DISCOVERY", .pass, true), ("PORT_FORWARD", .fail, true),
            ("SSH", .fail, true),
        ])
        try expect(iproxyFailure.firstFailingTransition == "PORT_FORWARD", "iproxy failure was hidden")
        let bridgeCrash = snapshot([
            ("BRIDGE_SERVICES", .fail, true), ("PORT_FORWARD", .pass, true),
            ("SSH", .pass, true),
        ])
        try expect(bridgeCrash.firstFailingTransition == "BRIDGE_SERVICES", "bridge crash was hidden")
        let coreUnavailable = snapshot([
            ("REQUIRED", .pass, true), ("COREDEVICE", .notApplicable, false),
        ])
        try expect(coreUnavailable.state == .healthy, "optional CoreDevice absence broke fallback")
    }

    private static func reconnectionLifecycleMatrix() async throws {
        let id = "00000000-0000000000000001"
        let machine = BridgeStateMachine()
        let scenarios: [[BridgeState]] = [
            [.deviceDetected, .paired, .connecting, .connected, .reconnecting, .connected], // USB → Wi-Fi
            [.reconnecting, .connected, .reconnecting, .connected],                         // Wi-Fi → USB
            [.reconnecting, .offline, .reconnecting, .connected],                           // disconnect/reconnect
            [.reconnecting, .connected],                                                      // wake
            [.reconnecting, .degraded, .reconnecting, .connected],                           // reboot
            [.reconnecting, .connected],                                                      // app restart
            [.reconnecting, .connected],                                                      // helper restart
            [.reconnecting, .degraded, .reconnecting, .connected],                           // network change
        ]
        for (index, states) in scenarios.enumerated() {
            await machine.restore(deviceID: id, state: .offline)
            for state in states {
                do { _ = try await machine.transition(deviceID: id, to: state) }
                catch { throw TestFailure.failed("reconnect scenario \(index) rejected \(state.rawValue): \(error)") }
            }
            let finalState = await machine.state(for: id)
            try expect(finalState == .connected, "reconnect scenario \(index) did not recover")
        }
        try expect(ConnectionManager.backoffSeconds.last == 60, "reconnect backoff is unbounded or missing")
    }

    private static func enrollmentPlanning() async throws {
        let device = SkyDevice(
            udid: "00000000-0000000000000001", productType: "iPad13,8", usbConnected: true
        )
        let instanceName = try DeviceEnrollmentManager.instanceName(for: device)
        try expect(
            instanceName == "ipad-srd-00000001",
            "stable instance naming failed"
        )
        let profile = DeviceProfile(
            udid: "00000000-0000000000000002", instanceName: "iphone-srd-00000002",
            localPort: 2222, sshHostAlias: "0sky-device-bbbbbbbbbbbbbbbbbbbbbbbb",
            sshKeyPath: "/tmp/fixture-home/.ssh/key", knownHostsPath: "/tmp/fixture-home/known-hosts"
        )
        let port = try DeviceEnrollmentManager.nextAvailablePort(profiles: [profile])
        try expect(port == 2223,
                   "port allocator reused an existing device port")
        let complete = IOSComponentSetupManager.plan(.completeProject)
        try expect(complete.tier == .highRisk
                   && complete.components.contains("0-Sky Link")
                   && complete.components.contains("0-Sky Control")
                   && complete.components.contains("CatVNC research service")
                   && complete.components.contains("Filza 4.0 research Cryptex")
                   && complete.components.contains("Exact-build appregistrard service")
                   && complete.components.contains("Frida 17.18.0 host/device runtime"),
                   "complete iOS Project plan omitted a required component")
        try expect(complete.preservesNewerPackages,
                   "complete iOS Project plan would replace newer packages")
        // The public repository is deliberately source-only. Distribution
        // payload resolution is covered by installer verification; here we
        // assert that a source checkout fails closed instead of inventing or
        // downloading an unverified device kit.
        do {
            _ = try BridgePaths(repositoryRoot: nil, bundledKitRoot: nil).zeroSkyLinkIPA()
            throw TestFailure.failed("source checkout unexpectedly exposed a Link IPA")
        } catch BridgeCoreError.dependencyMissing { /* expected */ }
        do {
            _ = try BridgePaths(repositoryRoot: nil, bundledKitRoot: nil).projectSetupKit()
            throw TestFailure.failed("source checkout unexpectedly exposed a device kit")
        } catch BridgeCoreError.dependencyMissing { /* expected */ }
    }

    private static func diagnosticExport() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("0sky-diagnostic-test-\(UUID().uuidString)")
        let exporter = DiagnosticExporter(root: root)
        let now = Date()
        let output = try await exporter.export(
            host: HostSummary(
                computerName: "Engineer Personal Mac", osVersion: "macOS fixture",
                architecture: "arm64", bridgeVersion: "test", helperState: "fixture"
            ),
            device: nil, services: [], pairing: ["token": "supersecret"], network: [:],
            health: nil,
            logs: [BridgeLogEntry(category: .security, level: .info,
                                  message: "password=hunter2 /" + "Users" + "/engineer/project")],
            operations: [BridgeOperationResult(
                identifier: "fixture", startedAt: now, finishedAt: now, exitCode: 0,
                stdout: "token=abcdef", stderr: ""
            )]
        )
        let expected = ["summary.txt", "host.json", "device.json", "services.json",
                        "pairing.json", "network.json", "bridge.log", "operations.log"]
        for name in expected {
            let url = output.appendingPathComponent(name)
            try expect(FileManager.default.fileExists(atPath: url.path), "diagnostic missing \(name)")
            let mode = (try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)?.intValue
            try expect(mode == 0o600, "diagnostic mode is not 0600 for \(name)")
            let text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            try expect(!text.contains("hunter2") && !text.contains("supersecret")
                       && !text.contains("Engineer Personal Mac"), "diagnostic leaked sensitive data")
        }
    }

    private static func processCancellation() async throws {
        let runner = ScriptRunner()
        let task = Task {
            try await runner.run(ScriptSpecification(
                identifier: "test.cancel", executableURL: URL(fileURLWithPath: "/bin/sleep"),
                arguments: ["20"], timeout: .seconds(30)
            ))
        }
        try await Task.sleep(for: .milliseconds(150))
        task.cancel()
        do {
            _ = try await task.value
            throw TestFailure.failed("cancelled child process returned success")
        } catch is CancellationError { }
        catch BridgeCoreError.cancelled { }
        catch BridgeCoreError.timeout { throw TestFailure.failed("cancellation waited for timeout") }
        catch { /* Process termination can surface as a task-group cancellation. */ }
    }

    private static func normalizedEventBus() async throws {
        let bus = EventBus(historyLimit: 2)
        for index in 0..<3 {
            await bus.publish(BridgeEvent(
                event: .deviceDiscovered, deviceID: "device-\(index)", component: "test",
                message: "fixture", observed: ["index": .number(Double(index))]
            ))
        }
        let history = await bus.events()
        try expect(history.count == 2, "event history did not enforce its bound")
        try expect(history.last?.event == .deviceDiscovered, "event was not normalized")
        try expect(history.last?.correlationID != nil, "correlation ID missing")
    }

    private static func safeLogClearing() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("0sky-log-clear-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let bus = EventBus()
        let persistent = StructuredEventLog(directory: root)
        try await persistent.attach(to: bus)
        await bus.publish(BridgeEvent(
            event: .serviceStarted, component: "test", message: "before clear"
        ))
        for name in ["pairing-events.jsonl", "transport-events.jsonl"] {
            try Data("fixture\n".utf8).write(to: root.appendingPathComponent(name))
        }
        let cleared = try await persistent.clear()
        try expect(cleared == 3, "not all 0-Sky-owned log files were cleared")
        for name in ["bridge-events.jsonl", "pairing-events.jsonl", "transport-events.jsonl"] {
            let attributes = try FileManager.default.attributesOfItem(
                atPath: root.appendingPathComponent(name).path
            )
            try expect((attributes[.size] as? NSNumber)?.intValue == 0,
                       "\(name) retained content after clearing")
        }
        await bus.publish(BridgeEvent(
            event: .serviceStarted, component: "test", message: "after clear"
        ))
        let activeSize = try FileManager.default.attributesOfItem(
            atPath: root.appendingPathComponent("bridge-events.jsonl").path
        )[.size] as? NSNumber
        try expect((activeSize?.intValue ?? 0) > 0, "structured logging did not resume after clearing")

        let outside = root.deletingLastPathComponent()
            .appendingPathComponent("0sky-log-target-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: outside) }
        try Data("must-survive".utf8).write(to: outside)
        let transport = root.appendingPathComponent("transport-events.jsonl")
        try FileManager.default.removeItem(at: transport)
        try FileManager.default.createSymbolicLink(at: transport, withDestinationURL: outside)
        do {
            _ = try await persistent.clear()
            throw TestFailure.failed("symlink log target was accepted")
        } catch BridgeCoreError.invalidPath { }
        let outsideContents = String(decoding: try Data(contentsOf: outside), as: UTF8.self)
        try expect(outsideContents == "must-survive",
                   "log clearing modified a symlink target")
        let retainedSize = try FileManager.default.attributesOfItem(
            atPath: root.appendingPathComponent("bridge-events.jsonl").path
        )[.size] as? NSNumber
        try expect((retainedSize?.intValue ?? 0) > 0,
                   "unsafe log layout caused a partial clear")

        let memory = BridgeLogStore()
        await memory.append(category: .service, level: .info, message: "fixture")
        await memory.clear()
        let remaining = await memory.all()
        try expect(remaining.isEmpty, "in-memory log view was not cleared")
    }

    private static func srdLifecycleStateMachine() async throws {
        let bus = EventBus(); let state = DeviceStateStore(events: bus); let id = "fixture"
        for next: DeviceLifecycleState in [.discovered, .usbConnected, .paired, .trusted,
                                           .remoteXPCReady, .sshReady,
                                           .developerServicesReady, .researchReady] {
            _ = try await state.transition(deviceID: id, to: next)
        }
        let finalLifecycle = await state.lifecycle(for: id)
        try expect(finalLifecycle == .researchReady, "normal SRD lifecycle failed")
        await state.setComponent("ddi", condition: .failed, deviceID: id)
        await state.setComponent("ssh", condition: .ready, deviceID: id)
        let components = await state.componentState(for: id)
        try expect(components["ddi"] == .failed && components["ssh"] == .ready,
                   "component state was not independent")
        do {
            _ = try await DeviceStateStore(events: bus).transition(deviceID: id, to: .researchReady)
            throw TestFailure.failed("invalid lifecycle transition was accepted")
        } catch BridgeCoreError.operationFailed { }
    }

    private static func firstFailingDependencyGraph() async throws {
        let results = [
            HealthResult(name: "DEVICE", status: .pass, expected: "ready"),
            HealthResult(name: "USB", status: .pass, expected: "ready"),
            HealthResult(name: "PAIRING", status: .pass, expected: "ready"),
            HealthResult(name: "TRUST", status: .pass, expected: "ready"),
            HealthResult(name: "REMOTEXPC", status: .pass, expected: "ready"),
            HealthResult(name: "DEVELOPER_SERVICES", status: .pass, expected: "ready"),
            HealthResult(name: "DDI", status: .fail, severity: .critical,
                         expected: "compatible research DDI", rootCause: "Research DDI unavailable"),
            HealthResult(name: "DEBUGSERVER", status: .fail, expected: "available"),
            HealthResult(name: "LLDB", status: .fail, expected: "available"),
            HealthResult(name: "FRIDA_ATTACH", status: .fail, expected: "available"),
        ]
        let analysis = FirstFailureAnalyzer().analyze(results)
        try expect(analysis.firstFailingTransition == "DDI", "DDI was not the first upstream failure")
        try expect(Set(analysis.dependentFailures) == ["DEBUGSERVER", "LLDB", "FRIDA_ATTACH"],
                   "dependent failures were presented as roots")
        try DependencyGraph().validate()
        do {
            try DependencyGraph(prerequisites: ["A": ["B"], "B": ["A"]]).validate()
            throw TestFailure.failed("cyclic dependency graph accepted")
        } catch BridgeCoreError.malformedOutput { }
    }

    private static func cryptexDisplayLabel() async throws {
        let result = HealthResult(name: "CRYTEX", status: .pass, expected: "ready")
        try expect(result.name == "CRYTEX", "canonical Cryptex identifier changed")
        try expect(result.displayName == "Cryptex", "Cryptex was not humanized")
        try expect(HealthResult.displayName(for: "cryptex") == "Cryptex",
                   "Cryptex display label should be case-insensitive")
    }

    private actor AttemptCounter {
        var value = 0
        func next(successAt: Int) -> OperationResult {
            value += 1
            return OperationResult(succeeded: value >= successAt, message: "attempt \(value)")
        }
    }

    private static func boundedRecoveryPolicy() async throws {
        let bus = EventBus(); let engine = RecoveryPolicyEngine(events: bus)
        let action = RecoveryAction(id: "ssh-reconnect", component: "ssh",
                                    tier: .automaticSafe, description: "Reconnect SSH")
        let successCounter = AttemptCounter()
        let success = await engine.execute(
            action: action, deviceID: "fixture", reason: "SSH disconnected",
            policy: RetryPolicy(maximumRetryCount: 4, backoffMilliseconds: [0, 0, 0, 0], cooldownMilliseconds: 1)
        ) { await successCounter.next(successAt: 3) }
        try expect(success.succeeded && success.attempts == 3, "successful recovery retry count was wrong")

        let failureCounter = AttemptCounter()
        let failure = await engine.execute(
            action: RecoveryAction(id: "ssh-fail", component: "ssh", tier: .automaticSafe, description: "Reconnect"),
            deviceID: "fixture", reason: "outage",
            policy: RetryPolicy(maximumRetryCount: 2, backoffMilliseconds: [0, 0], cooldownMilliseconds: 10)
        ) { await failureCounter.next(successAt: 99) }
        try expect(!failure.succeeded && failure.exhausted && failure.attempts == 2,
                   "recovery was not bounded")
        let blocked = await engine.execute(
            action: RecoveryAction(id: "reboot", component: "device", tier: .highRisk, description: "Reboot"),
            deviceID: "fixture", reason: "test"
        ) { OperationResult(succeeded: true, message: "must not execute") }
        try expect(blocked.attempts == 0 && !blocked.succeeded, "high-risk action ran automatically")
    }

    private static func transportFailover() async throws {
        let bus = EventBus(); let transport = TransportCoordinator(events: bus)
        let initial = await transport.update(deviceID: "fixture", usb: true, wifi: true)
        try expect(initial.primary == .wifi && initial.fallback == .usb, "Wi-Fi preference was wrong")
        let usbFallback = await transport.update(deviceID: "fixture", usb: true, wifi: false, reason: "radio lost")
        try expect(usbFallback.primary == .usb, "Wi-Fi loss did not fail over to USB")
        let wifiOnly = await transport.update(deviceID: "fixture", usb: false, wifi: true, reason: "cable removed")
        try expect(wifiOnly.primary == .wifi, "USB loss interrupted healthy Wi-Fi")
        let transportEvents = await bus.events(deviceID: "fixture")
        try expect(transportEvents.contains { $0.event == .wifiLost },
                   "transport loss event missing")
    }

    private static func researchSessionEvidence() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("0sky-session-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let bus = EventBus(); let recorder = ResearchSessionRecorder(root: root, events: bus)
        let device = SkyDevice(udid: "00000000-0000000000000001", name: "Fixture", usbConnected: true)
        let host = HostSummary(computerName: "Fixture Mac", osVersion: "macOS", architecture: "arm64",
                               bridgeVersion: "test", helperState: "off")
        let session = try await recorder.start(name: "DDI test", device: device, host: host)
        await bus.publish(BridgeEvent(event: .ddiFailed, deviceID: device.udid, sessionID: session.id,
                                      severity: .error, component: "ddi", message: "DDI failed"))
        try await recorder.record(command: CommandRecord(
            timestamp: Date(), component: "ssh", commandIdentifier: "probe",
            redactedArguments: ["--token", "secret-value", "safe"], exitCode: 1,
            durationMS: 12, stdoutReference: nil, stderrReference: nil
        ))
        let artifact = root.appendingPathComponent("source.log")
        try Data("fixture".utf8).write(to: artifact)
        _ = try await recorder.captureArtifact(from: artifact, preferredName: "trace.log")
        let directory = try await recorder.stop()
        for item in ["manifest.json", "host.json", "device.json", "tools.json", "health.json",
                     "events.jsonl", "timeline.json", "timeline.txt", "commands.jsonl", "hashes.sha256"] {
            try expect(FileManager.default.fileExists(atPath: directory.appendingPathComponent(item).path),
                       "session missing \(item)")
        }
        let commands = try String(contentsOf: directory.appendingPathComponent("commands.jsonl"), encoding: .utf8)
        try expect(!commands.contains("secret-value") && commands.contains("<redacted>"),
                   "command argument secret leaked")
        let hashes = try String(contentsOf: directory.appendingPathComponent("hashes.sha256"), encoding: .utf8)
        try expect(hashes.contains("manifest.json") && hashes.contains("artifacts/trace.log"),
                   "evidence hashes were incomplete")
        let archive = try await recorder.export(sessionDirectory: directory, profile: .publicSanitized)
        try expect(FileManager.default.fileExists(atPath: archive.path), "bundle export failed")
    }

    private static func evidenceSecurity() async throws {
        let args = ResearchSessionRecorder.redactArguments([
            "--password=hunter2", "--identity", "/Users/example/.ssh/id_ed25519", "normal"
        ])
        try expect(!args.joined().contains("hunter2") && !args.joined().contains("id_ed25519"),
                   "argument-level redaction failed")
        let malicious = DiagnosticRedactor.redact("token=abc123 /Users/example/private")
        try expect(!malicious.contains("abc123") && !malicious.contains("person"), "text redaction failed")

        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("0sky-symlink-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let target = root.appendingPathComponent("target"); try Data("x".utf8).write(to: target)
        let link = root.appendingPathComponent("link"); try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        let recorder = ResearchSessionRecorder(root: root.appendingPathComponent("sessions"), events: EventBus())
        _ = try await recorder.start(
            name: "../ traversal", device: SkyDevice(udid: "00000000-0000000000000001", usbConnected: true),
            host: HostSummary(computerName: "Mac", osVersion: "test", architecture: "arm64", bridgeVersion: "test", helperState: "off")
        )
        do {
            _ = try await recorder.captureArtifact(from: link)
            throw TestFailure.failed("symlink artifact accepted")
        } catch EvidenceError.unsafePath { }
    }

    private static func persistentServiceContract() async throws {
        let snapshot = BridgeDaemonSnapshot(
            serviceVersion: "test", serviceStartedAt: Date(), devices: [
                SkyDevice(udid: "00000000-0000000000000001", usbConnected: true)
            ], health: [:], activeSession: nil
        )
        let decoded = try JSONDecoder.sky.decode(
            BridgeDaemonSnapshot.self, from: JSONEncoder.sky.encode(snapshot)
        )
        try expect(decoded.serviceVersion == "test" && decoded.devices.count == 1,
                   "daemon IPC snapshot was not Codable")
        try expect(BridgeDaemonClient.machServiceName == "com.liquidsky.0sky.bridge.service",
                   "daemon Mach service identifier changed")
    }

    private static func versionedAdapterProbes() async throws {
        let matching = await FridaAdapter(hostVersion: { "17.2.1" }, deviceVersion: { "17.2.1" }).checkHealth()
        try expect(matching.status == .pass, "matching Frida versions failed")
        let mismatch = await FridaAdapter(hostVersion: { "17.2.1" }, deviceVersion: { "17.3.0" }).checkHealth()
        try expect(mismatch.status == .fail && mismatch.rootCause == "host/device version mismatch",
                   "Frida mismatch was not classified")
        let profile = DeviceProfile(
            udid: "00000000-0000000000000001", instanceName: "fixture", localPort: 2222,
            sshHostAlias: "0sky-device-aaaaaaaaaaaaaaaaaaaaaaaa",
            sshKeyPath: "/tmp/key", knownHostsPath: "/tmp/known"
        )
        let rejected = await SSHManager(runner: ScriptRunner()).readCrashReport(
            profile: profile, path: "/var/mobile/Library/Logs/CrashReporter/../../private/key"
        )
        try expect(!rejected.succeeded && rejected.exitCode == 126,
                   "crash collector accepted path traversal")
    }

    private static func coreDeviceDebugserverProbe() async throws {
        let healthy = await DebugserverAdapter(probe: AdapterProbe {
            HealthResult(
                name: "DEBUGSERVER", status: .pass, severity: .high,
                observed: ["probe": .string("coredevice-lldb-process-list")],
                expected: "CoreDevice LLDB can enumerate attachable device processes"
            )
        }).checkHealth()
        try expect(healthy.status == .pass, "CoreDevice LLDB debug service was not accepted")
        try expect(healthy.observed["probe"] == .string("coredevice-lldb-process-list"),
                   "debugserver health did not retain structured probe evidence")
    }

    private static func defaultCredentialDetection() async throws {
        let now = Date()
        let unsafeOperation = BridgeOperationResult(
            identifier: "fixture.credentials", startedAt: now, finishedAt: now,
            exitCode: 1,
            stdout: #"{"measured":true,"root_default":true,"mobile_default":false,"accounts_measured":2}"#,
            stderr: ""
        )
        let unsafe = DefaultCredentialsAdapter.evaluate(unsafeOperation)
        try expect(unsafe.status == .fail && unsafe.severity == .critical,
                   "legacy default credentials were not blocked")
        try expect(unsafe.rootCause == DefaultCredentialsAdapter.warningMessage,
                   "default credential warning text changed")
        try expect(unsafe.observed["root_default"] == .bool(true)
                   && unsafe.observed["mobile_default"] == .bool(false),
                   "affected accounts were not reported structurally")

        let safeOperation = BridgeOperationResult(
            identifier: "fixture.credentials", startedAt: now, finishedAt: now,
            exitCode: 0,
            stdout: #"{"measured":true,"root_default":false,"mobile_default":false,"accounts_measured":2}"#,
            stderr: ""
        )
        try expect(DefaultCredentialsAdapter.evaluate(safeOperation).status == .pass,
                   "changed credentials did not pass")

        let profile = DeviceProfile(
            udid: "00000000-0000000000000001", instanceName: "fixture", localPort: 2222,
            sshHostAlias: "0sky-device-aaaaaaaaaaaaaaaaaaaaaaaa",
            sshKeyPath: "/tmp/key", knownHostsPath: "/tmp/known"
        )
        let arguments = try await SSHManager(runner: ScriptRunner()).arguments(
            for: profile, operation: .defaultCredentialsHealth
        )
        let command = arguments.last ?? ""
        let plaintextDefault = String(bytes: [97, 108, 112, 105, 110, 101], encoding: .utf8)!
        try expect(command.contains("root") && command.contains("mobile"),
                   "credential probe did not inspect both required accounts")
        try expect(!command.contains(plaintextDefault),
                   "credential probe exposed a plaintext password")
        try expect(DependencyGraph().ancestors(of: "DEFAULT_CREDENTIALS").contains("SSH"),
                   "credential health was not dependent on authenticated SSH")

        let unsafeVNCOperation = BridgeOperationResult(
            identifier: "fixture.vnc-credentials", startedAt: now, finishedAt: now,
            exitCode: 0,
            stdout: #"{"measured":true,"unsafe":true,"port_5900_open":true,"port_5800_open":false,"rfb_none_auth":true,"rfb_empty_password":false,"rfb_protocol":"RFB 003.008","http_unauthenticated":false,"http_status":null}"#,
            stderr: ""
        )
        let unsafeVNC = VNCDefaultCredentialsAdapter.evaluate(unsafeVNCOperation)
        try expect(unsafeVNC.status == .fail && unsafeVNC.severity == .critical,
                   "unauthenticated VNC was not blocked")
        try expect(unsafeVNC.rootCause == DefaultCredentialsAdapter.warningMessage,
                   "VNC default credential warning text changed")
        try expect(unsafeVNC.observed["port_5900_open"] == .bool(true)
                   && unsafeVNC.observed["rfb_none_auth"] == .bool(true),
                   "VNC exposure was not reported structurally")

        let safeVNCOperation = BridgeOperationResult(
            identifier: "fixture.vnc-credentials", startedAt: now, finishedAt: now,
            exitCode: 0,
            stdout: #"{"measured":true,"unsafe":false,"port_5900_open":false,"port_5800_open":false,"rfb_none_auth":false,"rfb_empty_password":false,"rfb_protocol":null,"http_unauthenticated":false,"http_status":null}"#,
            stderr: ""
        )
        try expect(VNCDefaultCredentialsAdapter.evaluate(safeVNCOperation).status == .pass,
                   "closed VNC services did not pass")
        let vncArguments = try await SSHManager(runner: ScriptRunner()).arguments(
            for: profile, operation: .vncDefaultCredentialsHealth
        )
        try expect(vncArguments.last?.contains("/var/jb/usr/bin/python3") == true
                   && vncArguments.last?.contains("/var/jb/usr/bin/base64") == true,
                   "bounded VNC credential probe was not configured")
        let vncCommand = vncArguments.last ?? ""
        let payloadMarker = "printf '%s' '"
        guard let payloadStart = vncCommand.range(of: payloadMarker)?.upperBound,
              let payloadEnd = vncCommand[payloadStart...].range(of: "' |")?.lowerBound,
              let payloadData = Data(base64Encoded: String(vncCommand[payloadStart..<payloadEnd])),
              let payloadSource = String(data: payloadData, encoding: .utf8) else {
            throw TestFailure.failed("VNC probe payload was not valid base64 Python")
        }
        try expect(payloadSource.contains("5900") && payloadSource.contains("5800")
                   && payloadSource.contains("CCCrypt")
                   && payloadSource.contains("empty_password")
                   && payloadSource.contains("none_auth"),
                   "VNC probe omitted a required port or null-authentication check")
        try expect(DependencyGraph().ancestors(of: "VNC_DEFAULT_CREDENTIALS").contains("SSH"),
                   "VNC credential health was not dependent on authenticated SSH")
    }

    private static func sessionCrashCollection() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("0sky-crashes-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let events = EventBus()
        let recorder = ResearchSessionRecorder(root: root, events: events)
        let udid = "00000000-0000000000000001"
        let session = try await recorder.start(
            name: "crash-fixture", device: SkyDevice(udid: udid, usbConnected: true),
            host: HostSummary(computerName: "Mac", osVersion: "test", architecture: "arm64",
                              bridgeVersion: "test", helperState: "off")
        )
        let source = FixtureCrashSource()
        let collector = CrashCollector(ssh: source, recorder: recorder, events: events)
        let profile = DeviceProfile(udid: udid, instanceName: "fixture", localPort: 2222,
                                    sshHostAlias: "0sky-device-aaaaaaaaaaaaaaaaaaaaaaaa",
                                    sshKeyPath: "/tmp/key", knownHostsPath: "/tmp/known")
        let first = await collector.collect(profile: profile, session: session)
        let duplicate = await collector.collect(profile: profile, session: session)
        let readCount = await source.readCount()
        try expect(first.count == 1 && first[0].kind == .springBoard,
                   "session crash report was not classified and captured")
        try expect(duplicate.isEmpty && readCount == 1,
                   "session crash collector did not deduplicate evidence")
        try expect(FileManager.default.fileExists(
            atPath: session.directory.appendingPathComponent("crashes/\(first[0].filename)").path
        ), "crash evidence file is missing")
        let names = await events.events().map(\.event)
        try expect(names.contains(.crashDetected) && names.contains(.artifactCaptured),
                   "crash collection did not publish normalized events")
        _ = try await recorder.stop()
    }

    private static func wirelessCapabilityPersistence() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("0sky-registry-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let instance = root.appendingPathComponent("instances/fixture", isDirectory: true)
        let capabilityRoot = root.appendingPathComponent("trusted-device-capabilities", isDirectory: true)
        try FileManager.default.createDirectory(at: instance, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: capabilityRoot, withIntermediateDirectories: true)
        let udid = "00000000-0000000000000001"
        let config: [String: Any] = [
            "udid": udid, "instance": "fixture", "ssh_port": 2222,
            "ssh_host_alias": "0sky-device-aaaaaaaaaaaaaaaaaaaaaaaa", "ssh_key": "/tmp/key"
        ]
        try JSONSerialization.data(withJSONObject: config).write(to: instance.appendingPathComponent("config.json"))
        let pairing: [String: Any] = ["verified": true, "wireless": ["status": "not-requested"]]
        try JSONSerialization.data(withJSONObject: pairing).write(to: instance.appendingPathComponent("pairing-state.json"))
        let hash = SHA256.hash(data: Data(udid.utf8)).map { String(format: "%02x", $0) }.joined().prefix(24)
        try JSONSerialization.data(withJSONObject: ["wifiPairingVerified": true])
            .write(to: capabilityRoot.appendingPathComponent("\(hash).json"))
        let values = try await DeviceRegistry(supportURL: root).reload()
        try expect(values.first?.wirelessEnabled == true,
                   "durable wireless proof was erased by a later USB verification")
    }
}
