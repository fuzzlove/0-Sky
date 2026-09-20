import Foundation

public actor WirelessPairingManager {
    public enum Operation: String, Sendable {
        case connect
        case enable = "enable-wireless"
        case verify = "verify-wireless"
    }

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
        operation: Operation,
        hostFingerprint: String,
        usbTrustVerified: Bool,
        output: URL? = nil,
        onEvent: @escaping ScriptRunner.EventHandler = { _ in }
    ) async throws -> BridgeOperationResult {
        guard hostFingerprint.hasPrefix("SHA256:"), hostFingerprint.count >= 24 else {
            throw BridgeCoreError.operationFailed(
                "Verified Mac identity fingerprint is missing; verify pairing over USB first."
            )
        }
        return try await coordinator.withLock(deviceID: profile.udid, operation: operation.rawValue) {
            let python = try paths.python(for: profile)
            let script = try paths.hostScript("apple_device_transport.py", profile: profile)
            var arguments = [
                script.path, operation.rawValue,
                "--support", paths.supportRoot.path,
                "--target", profile.udid,
                "--host-fingerprint", hostFingerprint,
            ]
            if usbTrustVerified { arguments.append("--usb-trust-verified") }
            if let output { arguments += ["--output", output.path] }
            let measured = try await runner.run(
                ScriptSpecification(
                    identifier: "wireless.\(operation.rawValue).\(profile.instanceName)",
                    executableURL: python,
                    arguments: arguments,
                    workingDirectory: script.deletingLastPathComponent(),
                    timeout: .seconds(240)
                ),
                onEvent: onEvent
            )
            // The existing transport tool uses exit 2 to signal the required
            // physical handoff after it has successfully enabled Wi-Fi. That
            // is a user-action transition, not an operation failure.
            if operation == .enable, Self.isDisconnectRequired(stdout: measured.stdout) {
                return BridgeOperationResult(
                    identifier: measured.identifier,
                    startedAt: measured.startedAt,
                    finishedAt: measured.finishedAt,
                    exitCode: 0,
                    stdout: measured.stdout,
                    stderr: measured.stderr,
                    timedOut: measured.timedOut,
                    cancelled: measured.cancelled
                )
            }
            return measured
        }
    }

    public static func isDisconnectRequired(stdout: String) -> Bool {
        guard let object = (try? JSONSerialization.jsonObject(
            with: Data(stdout.utf8)
        )) as? [String: Any] else { return false }
        return object["status"] as? String == "pending"
            && object["errorCode"] as? String == "USB_DISCONNECT_REQUIRED"
            && object["wifiLockdownEnabled"] as? Bool == true
    }
}
