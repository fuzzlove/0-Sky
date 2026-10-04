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
            let canonical = try Self.canonicalResumeCandidate(
                supportURL: paths.supportRoot, device: device
            )
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
                ?? canonical?.port
                ?? Self.nextAvailablePort(
                    profiles: profiles,
                    reservedPorts: Self.configuredPorts(supportURL: paths.supportRoot)
                )
            let instance = try interrupted.map { try BridgeValidation.validateInstance($0.instanceName) }
                ?? canonical?.instance
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

    public static func nextAvailablePort(
        profiles: [DeviceProfile], reservedPorts: Set<Int> = []
    ) throws -> Int {
        let used = Set(profiles.map(\.localPort)).union(reservedPorts)
        guard let port = (2222...8999).first(where: { !used.contains($0) }) else {
            throw BridgeCoreError.operationFailed("No unprivileged per-device forwarding port is available.")
        }
        return try BridgeValidation.validatePort(port)
    }

    /// Resume the deterministic directory created by an interrupted setup,
    /// even when other incomplete legacy directories claim the same UUID.
    /// Identity and port are validated before the installer sees them.
    public static func canonicalResumeCandidate(
        supportURL: URL, device: SkyDevice
    ) throws -> (instance: String, port: Int)? {
        let instance = try instanceName(for: device)
        let directory = supportURL.appendingPathComponent("instances/\(instance)", isDirectory: true)
        let config = directory.appendingPathComponent("config.json")
        let fm = FileManager.default
        guard fm.fileExists(atPath: config.path) else { return nil }
        let properties = try directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        let configProperties = try config.resourceValues(
            forKeys: [.isRegularFileKey, .isSymbolicLinkKey]
        )
        guard properties.isDirectory == true, properties.isSymbolicLink != true,
              configProperties.isRegularFile == true, configProperties.isSymbolicLink != true else {
            throw BridgeCoreError.operationFailed(
                "The resumable setup directory is unsafe. Open Diagnostics and export a report; no files were changed."
            )
        }
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: config)) as? [String: Any]
        guard let object,
              object["udid"] as? String == device.udid,
              object["instance"] as? String == instance else {
            throw BridgeCoreError.operationFailed(
                "The deterministic setup directory \(instance) belongs to another endpoint. Open Diagnostics and remove only the obsolete Mac-side enrollment before retrying."
            )
        }
        let rawPort = object["ssh_port"]
        let port = (rawPort as? Int) ?? (rawPort as? String).flatMap(Int.init)
        guard let port else {
            throw BridgeCoreError.operationFailed(
                "The interrupted setup profile has no valid local SSH port. Open Diagnostics and repair that profile before retrying."
            )
        }
        return (instance, try BridgeValidation.validatePort(port))
    }

    public static func configuredPorts(supportURL: URL) -> Set<Int> {
        let instances = supportURL.appendingPathComponent("instances", isDirectory: true)
        let fm = FileManager.default
        guard let directories = try? fm.contentsOfDirectory(
            at: instances, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey]
        ) else { return [] }
        return Set(directories.compactMap { directory in
            guard let properties = try? directory.resourceValues(
                forKeys: [.isDirectoryKey, .isSymbolicLinkKey]
            ), properties.isDirectory == true, properties.isSymbolicLink != true,
            let data = try? Data(contentsOf: directory.appendingPathComponent("config.json")),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { return nil }
            if let value = object["ssh_port"] as? Int { return value }
            if let value = object["ssh_port"] as? String { return Int(value) }
            return nil
        }.filter { (1024...65535).contains($0) })
    }
}
