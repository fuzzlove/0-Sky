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
}
