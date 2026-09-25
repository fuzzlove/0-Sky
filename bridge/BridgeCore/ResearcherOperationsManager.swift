import Foundation

/// Approved host-side probes exposed by the Researcher Console.  Every probe
/// has fixed executable/argument semantics; device values still pass through
/// the same validators used by production operations.
public actor ResearcherOperationsManager {
    private let runner: ScriptRunner
    private let paths: BridgePaths

    public init(runner: ScriptRunner, paths: BridgePaths) {
        self.runner = runner
        self.paths = paths
    }

    public func checkCoreDevice() async throws -> BridgeOperationResult {
        return try await runner.run(ScriptSpecification(
            identifier: "research.check-coredevice",
            executableURL: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["devicectl", "list", "devices"],
            timeout: .seconds(30)
        ))
    }

    public func checkDeveloperServices() async throws -> BridgeOperationResult {
        return try await runner.run(ScriptSpecification(
            identifier: "research.check-developer-services",
            executableURL: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["--find", "devicectl"],
            timeout: .seconds(15)
        ))
    }

    public func checkDDI(profile: DeviceProfile) async throws -> BridgeOperationResult {
        _ = try BridgeValidation.validateUDID(profile.udid)
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("0sky-ddi-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let json = directory.appendingPathComponent("ddi.json")
        let measured = try await runner.run(ScriptSpecification(
            identifier: "research.check-ddi.\(profile.instanceName)",
            executableURL: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["devicectl", "device", "info", "ddiServices", "--device", profile.udid,
                                 "--no-auto-mount-ddis", "--json-output", json.path],
            workingDirectory: directory, timeout: .seconds(45)
        ))
        guard measured.succeeded else { return measured }
        do {
            let data = try Data(contentsOf: json, options: .mappedIfSafe)
            _ = try JSONSerialization.jsonObject(with: data)
            return BridgeOperationResult(
                identifier: measured.identifier, startedAt: measured.startedAt,
                finishedAt: measured.finishedAt, exitCode: measured.exitCode,
                stdout: String(decoding: data, as: UTF8.self), stderr: measured.stderr,
                timedOut: measured.timedOut, cancelled: measured.cancelled
            )
        } catch {
            throw BridgeCoreError.malformedOutput("devicectl DDI JSON")
        }
    }

    /// Verifies the non-invasive half of the device debugging path through
    /// Xcode's CoreDevice-aware LLDB integration. Modern personalized DDIs do
    /// not guarantee that `debugserver` is exposed as a file in the device's
    /// root SSH namespace, so probing `/Developer/usr/bin/debugserver` creates
    /// a false failure even when the debugger service is usable.
    ///
    /// Selecting the exact device and enumerating attachable processes proves
    /// that LLDB can reach the mounted developer services without attaching to,
    /// suspending, or modifying any device process.
    public func checkDebugserver(profile: DeviceProfile) async throws -> BridgeOperationResult {
        let udid = try BridgeValidation.validateUDID(profile.udid)
        let commands = [
            "-b",
            "-o", "device select \(udid)",
            "-o", "device process list",
            "-o", "quit",
        ]
        return try await runner.run(ScriptSpecification(
            identifier: "research.check-debugserver.\(profile.instanceName)",
            executableURL: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["lldb"] + commands,
            timeout: .seconds(30),
            maximumOutputBytes: 512 * 1_024
        ))
    }

    public func checkRemoteXPC(profile: DeviceProfile) async throws -> BridgeOperationResult {
        let python = try paths.python(for: profile)
        _ = try BridgeValidation.validateUDID(profile.udid)
        let measured = try await runner.run(ScriptSpecification(
            identifier: "research.check-remotexpc.\(profile.instanceName)",
            executableURL: python,
            arguments: ["-m", "pymobiledevice3", "remote", "browse", "--timeout", "5"],
            timeout: .seconds(30)
        ))
        guard measured.succeeded, measured.stdout.contains(profile.udid) else {
            return BridgeOperationResult(
                identifier: measured.identifier,
                startedAt: measured.startedAt,
                finishedAt: measured.finishedAt,
                exitCode: measured.exitCode == 0 ? 1 : measured.exitCode,
                stdout: measured.stdout,
                stderr: measured.stderr + (measured.exitCode == 0
                    ? "Selected UDID was not present in measured RemoteXPC browse results.\n" : ""),
                timedOut: measured.timedOut,
                cancelled: measured.cancelled
            )
        }
        return measured
    }

    public func testForwardedPort(profile: DeviceProfile) async -> BridgeOperationResult {
        let start = Date()
        let reachable = await TCPProbe.open(port: profile.localPort, timeout: 3)
        return BridgeOperationResult(
            identifier: "research.test-port.\(profile.instanceName)",
            startedAt: start,
            finishedAt: Date(),
            exitCode: reachable ? 0 : 1,
            stdout: reachable
                ? "127.0.0.1:\(profile.localPort) accepted a measured TCP connection.\n" : "",
            stderr: reachable
                ? "" : "127.0.0.1:\(profile.localPort) did not accept a TCP connection.\n"
        )
    }
}
