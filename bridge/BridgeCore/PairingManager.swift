import Foundation

public actor PairingManager {
    public enum Mode: Sendable, Equatable { case pair, verify, repairHostKey }

    private let runner: ScriptRunner
    private let paths: BridgePaths
    private let coordinator: OperationCoordinator

    public init(runner: ScriptRunner, paths: BridgePaths, coordinator: OperationCoordinator) {
        self.runner = runner
        self.paths = paths
        self.coordinator = coordinator
    }

    public func run(
        profile: DeviceProfile,
        mode: Mode,
        requireWorker: Bool = false,
        onEvent: @escaping ScriptRunner.EventHandler = { _ in }
    ) async throws -> BridgeOperationResult {
        try await coordinator.withLock(deviceID: profile.udid, operation: "pairing") {
            let python = try paths.python(for: profile)
            let script = try paths.hostScript("pair.py", profile: profile)
            var arguments = [
                script.path,
                "--udid", profile.udid,
                "--ssh-key", profile.sshKeyPath,
                "--host", profile.sshHost,
                "--port", String(profile.localPort),
                "--instance-name", profile.instanceName,
                "--support", paths.supportRoot.path,
                "--pymobile-python", python.path,
            ]
            switch mode {
            case .pair: arguments.append("--confirm-host-enrollment")
            case .verify: arguments.append("--verify-only")
            case .repairHostKey: arguments.append("--repair-device-host-key")
            }
            if requireWorker { arguments.append("--require-worker") }
            return try await runner.run(
                ScriptSpecification(
                    identifier: "pairing.\(profile.instanceName)",
                    executableURL: python,
                    arguments: arguments,
                    workingDirectory: script.deletingLastPathComponent(),
                    timeout: .seconds(330)
                ),
                onEvent: onEvent
            )
        }
    }

    public func exportAdditionalMacRequest(
        deviceID: String,
        destination: URL,
        onEvent: @escaping ScriptRunner.EventHandler = { _ in }
    ) async throws -> BridgeOperationResult {
        try await coordinator.withLock(deviceID: deviceID, operation: "pairing-request-export") {
            let python = try paths.projectPython()
            let script = try paths.hostScript("multi_host_pairing.py")
            let identity = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".ssh/srdsh_ed25519")
            return try await runner.run(
                ScriptSpecification(
                    identifier: "pairing.additional-mac.export",
                    executableURL: python,
                    arguments: [
                        script.path, "--export-request", destination.path,
                        "--udid", deviceID, "--identity", identity.path,
                        "--support", paths.supportRoot.path,
                    ],
                    workingDirectory: script.deletingLastPathComponent(),
                    timeout: .seconds(60)
                ),
                onEvent: onEvent
            )
        }
    }

    public func approveAdditionalMacRequest(
        profile: DeviceProfile,
        request: URL,
        onEvent: @escaping ScriptRunner.EventHandler = { _ in }
    ) async throws -> BridgeOperationResult {
        try await coordinator.withLock(deviceID: profile.udid, operation: "pairing-request-approve") {
            let python = try paths.python(for: profile)
            let script = try paths.hostScript("multi_host_pairing.py", profile: profile)
            return try await runner.run(
                ScriptSpecification(
                    identifier: "pairing.additional-mac.approve.\(profile.instanceName)",
                    executableURL: python,
                    arguments: [
                        script.path, "--approve-request", request.path,
                        "--udid", profile.udid,
                        "--identity", profile.sshKeyPath,
                        "--support", paths.supportRoot.path,
                        "--host", profile.sshHost,
                        "--port", String(profile.localPort),
                        "--known-hosts", profile.knownHostsPath,
                        "--host-alias", profile.sshHostAlias,
                    ],
                    workingDirectory: script.deletingLastPathComponent(),
                    timeout: .seconds(60)
                ),
                onEvent: onEvent
            )
        }
    }
}
