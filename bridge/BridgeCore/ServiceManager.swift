import Foundation

public actor ServiceManager {
    public enum Kind: String, CaseIterable, Sendable {
        case usbmux
        case worker
        case deviceBridge = "device-bridge"
        case bluetooth
    }

    private let runner: ScriptRunner

    public init(runner: ScriptRunner) { self.runner = runner }

    public func label(kind: Kind, profile: DeviceProfile) throws -> String {
        let instance = try BridgeValidation.validateInstance(profile.instanceName)
        return "com.liquidskysecurity.crypstore-\(kind.rawValue).\(instance)"
    }

    public func status(kind: Kind, profile: DeviceProfile) async -> ServiceStatus {
        do {
            let label = try label(kind: kind, profile: profile)
            let result = try await runner.run(ScriptSpecification(
                identifier: "service.status.\(kind.rawValue).\(profile.instanceName)",
                executableURL: URL(fileURLWithPath: "/bin/launchctl"),
                arguments: ["print", "gui/\(getuid())/\(label)"],
                timeout: .seconds(10)
            ))
            return Self.parseStatus(label: label, result: result)
        } catch {
            return ServiceStatus(
                label: (try? label(kind: kind, profile: profile)) ?? kind.rawValue,
                state: "unavailable", processIdentifier: nil,
                lastExitCode: nil, installed: false
            )
        }
    }

    public func allStatuses(profile: DeviceProfile) async -> [ServiceStatus] {
        await withTaskGroup(of: ServiceStatus.self) { group in
            for kind in Kind.allCases {
                group.addTask { await self.status(kind: kind, profile: profile) }
            }
            var values: [ServiceStatus] = []
            for await value in group { values.append(value) }
            return values.sorted { $0.label < $1.label }
        }
    }

    public func start(kind: Kind, profile: DeviceProfile) async throws -> BridgeOperationResult {
        let label = try label(kind: kind, profile: profile)
        let plist = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
        guard FileManager.default.isReadableFile(atPath: plist.path) else {
            throw BridgeCoreError.dependencyMissing(plist.path)
        }
        let bootstrap = try await runner.run(ScriptSpecification(
            identifier: "service.start.\(kind.rawValue).\(profile.instanceName)",
            executableURL: URL(fileURLWithPath: "/bin/launchctl"),
            arguments: ["bootstrap", "gui/\(getuid())", plist.path],
            timeout: .seconds(15)
        ))
        if bootstrap.exitCode != 0 && !bootstrap.stderr.contains("already") {
            return bootstrap
        }
        return try await restart(kind: kind, profile: profile)
    }

    public func stop(kind: Kind, profile: DeviceProfile) async throws -> BridgeOperationResult {
        let label = try label(kind: kind, profile: profile)
        return try await runner.run(ScriptSpecification(
            identifier: "service.stop.\(kind.rawValue).\(profile.instanceName)",
            executableURL: URL(fileURLWithPath: "/bin/launchctl"),
            arguments: ["bootout", "gui/\(getuid())/\(label)"],
            timeout: .seconds(15)
        ))
    }

    public func restart(kind: Kind, profile: DeviceProfile) async throws -> BridgeOperationResult {
        let label = try label(kind: kind, profile: profile)
        return try await runner.run(ScriptSpecification(
            identifier: "service.restart.\(kind.rawValue).\(profile.instanceName)",
            executableURL: URL(fileURLWithPath: "/bin/launchctl"),
            arguments: ["kickstart", "-k", "gui/\(getuid())/\(label)"],
            timeout: .seconds(15)
        ))
    }

    private static func parseStatus(label: String, result: BridgeOperationResult) -> ServiceStatus {
        guard result.exitCode == 0 else {
            return ServiceStatus(
                label: label, state: "not loaded", processIdentifier: nil,
                lastExitCode: nil, installed: false
            )
        }
        let state = capture(#"(?m)^\s*state = ([^\n]+)"#, in: result.stdout) ?? "unknown"
        let pid = capture(#"(?m)^\s*pid = (\d+)"#, in: result.stdout).flatMap(Int.init)
        let exit = capture(#"(?m)^\s*last exit code = (-?\d+)"#, in: result.stdout).flatMap(Int.init)
        return ServiceStatus(
            label: label, state: state.trimmingCharacters(in: .whitespaces),
            processIdentifier: pid, lastExitCode: exit, installed: true
        )
    }

    private static func capture(_ pattern: String, in input: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(
                in: input, range: NSRange(input.startIndex..<input.endIndex, in: input)
              ),
              let range = Range(match.range(at: 1), in: input) else { return nil }
        return String(input[range])
    }
}
