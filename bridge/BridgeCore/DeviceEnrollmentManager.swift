import Foundation

/// Creates an instance-scoped host companion for a newly discovered,
/// explicitly selected SRD.  The existing audited installer remains the
/// authority; this layer only validates values and supplies argument arrays.
public actor DeviceEnrollmentManager {
    private let runner: ScriptRunner
    private let paths: BridgePaths
    private let registry: DeviceRegistry
    private let coordinator: OperationCoordinator

    public init(
        runner: ScriptRunner,
        paths: BridgePaths,
        registry: DeviceRegistry,
        coordinator: OperationCoordinator
    ) {
        self.runner = runner
        self.paths = paths
        self.registry = registry
        self.coordinator = coordinator
    }

    public func enroll(
        device: SkyDevice,
        identity: URL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh/srdsh_ed25519"),
        onEvent: @escaping ScriptRunner.EventHandler = { _ in }
    ) async throws -> BridgeOperationResult {
        let udid = try BridgeValidation.validateUDID(device.udid)
        guard device.usbConnected else {
            throw BridgeCoreError.operationFailed(
                "Initial enrollment requires this exact device over USB. Connect and unlock it, then approve Apple's Trust This Computer prompt."
            )
        }
        guard identity.path.hasPrefix(FileManager.default.homeDirectoryForCurrentUser.path + "/"),
              FileManager.default.isReadableFile(atPath: identity.path) else {
            throw BridgeCoreError.dependencyMissing("authorized SRD SSH identity at \(identity.path)")
        }
        return try await coordinator.withLock(deviceID: udid, operation: "enrollment") {
            let profiles = (try? await registry.reload()) ?? []
            let interrupted = profiles.first(where: { $0.udid == udid })
            let installComplete = interrupted.map {
                FileManager.default.fileExists(
                    atPath: paths.instanceDirectory($0)
                        .appendingPathComponent(".install-complete").path
                )
            } ?? false
            if interrupted?.pairingVerified == true && installComplete {
                throw BridgeCoreError.operationFailed("This device already has a verified instance-scoped 0-Sky profile.")
            }
            // install.py writes its validated public config before it enters
            // the SSH/pairing phase. A new device without SRDssh therefore
            // leaves a deliberately resumable profile when that first pass
            // fails. Reuse only this exact UDID's validated instance and port;
            // never allocate a second identity or silently select a device.
            let port = try interrupted.map { try BridgeValidation.validatePort($0.localPort) }
                ?? Self.nextAvailablePort(profiles: profiles)
            let instance = try interrupted.map { try BridgeValidation.validateInstance($0.instanceName) }
                ?? Self.instanceName(for: device)
            let installer = try paths.enrollmentInstaller()
            let result = try await runner.run(
                ScriptSpecification(
                    identifier: "device.enroll.\(instance)",
                    executableURL: URL(fileURLWithPath: "/usr/bin/python3"),
                    arguments: [
                        installer.path,
                        "--udid", udid,
                        "--ssh-key", identity.path,
                        "--host", "127.0.0.1",
                        "--port", String(port),
                        "--instance-name", instance,
                        "--support", paths.supportRoot.path,
                    ],
                    workingDirectory: installer.deletingLastPathComponent(),
                    timeout: .seconds(1_800)
                ),
                onEvent: onEvent
            )
            if result.succeeded { _ = try await registry.reload() }
            return result
        }
    }

    public static func instanceName(for device: SkyDevice) throws -> String {
        let family = device.productType?.lowercased().hasPrefix("ipad") == true
            ? "ipad-srd" : "iphone-srd"
        let suffix = String(device.udid.lowercased().filter(\.isHexDigit).suffix(8))
        return try BridgeValidation.validateInstance("\(family)-\(suffix)")
    }

    public static func nextAvailablePort(profiles: [DeviceProfile]) throws -> Int {
        let used = Set(profiles.map(\.localPort))
        guard let port = (2222...8999).first(where: { !used.contains($0) }) else {
            throw BridgeCoreError.operationFailed("No unprivileged per-device forwarding port is available.")
        }
        return try BridgeValidation.validatePort(port)
    }
}
