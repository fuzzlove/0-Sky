import CryptoKit
import Foundation

/// A reversible Mac-only removal. The backup ID can be passed to the bundled
/// host-mac/uninstall.py --restore-backup command before reinstalling.
public struct DeviceRemovalResult: Codable, Sendable {
    public let deviceID: String
    public let instanceName: String
    public let stoppedServices: [String]
    public let serviceStopFailures: [String]
    public let removedItems: [String]
    public let researchEvidencePreserved: Bool
    public let deviceModified: Bool
    public let rollbackID: String?
}

public actor DeviceRemovalManager {
    private let runner: ScriptRunner
    private let paths: BridgePaths
    private let registry: DeviceRegistry
    private let coordinator: OperationCoordinator
    private let events: EventBus
    private let launchAgentsRoot: URL
    private let launchctlURL: URL?
    private let fileManager: FileManager

    public init(
        runner: ScriptRunner, paths: BridgePaths, registry: DeviceRegistry,
        coordinator: OperationCoordinator, events: EventBus,
        launchAgentsRoot: URL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents", isDirectory: true),
        launchctlURL: URL? = URL(fileURLWithPath: "/bin/launchctl"),
        fileManager: FileManager = .default
    ) {
        self.runner = runner; self.paths = paths; self.registry = registry
        self.coordinator = coordinator; self.events = events
        self.launchAgentsRoot = launchAgentsRoot; self.launchctlURL = launchctlURL
        self.fileManager = fileManager
    }

    public func remove(profile: DeviceProfile) async throws -> DeviceRemovalResult {
        let deviceID = try BridgeValidation.validateUDID(profile.udid)
        let instance = try BridgeValidation.validateInstance(profile.instanceName)
        return try await coordinator.withLock(deviceID: deviceID, operation: "remove-device") {
            await self.events.publish(BridgeEvent(
                event: .deviceRemovalStarted, deviceID: deviceID,
                component: "device_manager",
                message: "Moving the exact Mac-side enrollment into a private rollback backup.",
                observed: ["instance": .string(instance)],
                expected: ["device_modified": .bool(false), "evidence_preserved": .bool(true)]
            ))
            do {
                let result = try await self.removeValidated(deviceID: deviceID, instance: instance)
                await self.events.publish(BridgeEvent(
                    event: .deviceRemoved, deviceID: deviceID,
                    component: "device_manager",
                    message: "Mac enrollment was backed up; the device and research evidence were preserved.",
                    observed: ["removed_items": .number(Double(result.removedItems.count)),
                               "device_modified": .bool(false)],
                    evidence: ["research_evidence_preserved": .bool(true)]
                ))
                return result
            } catch {
                await self.events.publish(BridgeEvent(
                    event: .deviceRemovalFailed, deviceID: deviceID, severity: .error,
                    component: "device_manager",
                    message: "Mac-side device removal failed: \(error.localizedDescription)",
                    expected: ["device_modified": .bool(false)]
                ))
                throw error
            }
        }
    }

    private func removeValidated(deviceID: String, instance: String) async throws -> DeviceRemovalResult {
        let root = paths.supportRoot
        let config = root.appendingPathComponent("instances/\(instance)/config.json")
        guard let contents = try? Data(contentsOf: config),
              let value = try? JSONSerialization.jsonObject(with: contents) as? [String: Any],
              value["udid"] as? String == deviceID else {
            throw BridgeCoreError.operationFailed("Exact-device host profile is missing or mismatched")
        }
        let agents = try ownedAgents(deviceID: deviceID, instance: instance)
        let digest = SHA256.hash(data: Data(deviceID.utf8))
            .map { String(format: "%02x", $0) }.joined().prefix(24)
        let candidates: [(String, URL)] = [
            ("instance", root.appendingPathComponent("instances/\(instance)")),
            ("public-profile", root.appendingPathComponent("bridge-profiles/\(instance).json")),
            ("runtime-state", root.appendingPathComponent("state/\(instance)")),
            ("trust-receipt", root.appendingPathComponent("trusted-devices/\(digest).json")),
            ("transport-capability", root.appendingPathComponent("trusted-device-capabilities/\(digest).json")),
        ]
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let backupID = "\(instance).\(formatter.string(from: Date())).\(DispatchTime.now().uptimeNanoseconds)"
        let backup = root.appendingPathComponent("uninstall-backups/\(backupID)")
        try fileManager.createDirectory(at: backup, withIntermediateDirectories: true,
                                        attributes: [.posixPermissions: 0o700])
        var stopped: [URL] = []
        var moved: [(from: URL, to: URL)] = []
        var removed: [String] = []
        do {
            for agent in agents where try await stopIfLoaded(agent) {
                stopped.append(agent)
            }
            for agent in agents {
                let destination = backup.appendingPathComponent("launchagents/\(agent.lastPathComponent)")
                try move(agent, to: destination, beneath: launchAgentsRoot)
                moved.append((destination, agent))
                removed.append("launch-agent:\(agent.deletingPathExtension().lastPathComponent)")
            }
            for (name, target) in candidates where fileManager.fileExists(atPath: target.path) {
                let relative = String(target.path.dropFirst(root.path.count + 1))
                let destination = backup.appendingPathComponent("state/\(relative)")
                try move(target, to: destination, beneath: root)
                moved.append((destination, target))
                removed.append(name)
            }
            let manifest: [String: Any] = [
                "schema": 1, "instance": instance, "udid": deviceID,
                "state": moved.filter { $0.to.path.hasPrefix(root.path + "/") }
                    .map { String($0.to.path.dropFirst(root.path.count + 1)) },
                "services": agents.map(\.lastPathComponent),
            ]
            let data = try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
            let ledger = backup.appendingPathComponent("manifest.json")
            try data.write(to: ledger, options: .atomic)
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: ledger.path)
        } catch {
            for pair in moved.reversed() {
                try? fileManager.createDirectory(at: pair.to.deletingLastPathComponent(),
                                                 withIntermediateDirectories: true)
                try? fileManager.moveItem(at: pair.from, to: pair.to)
            }
            for agent in stopped { try? await start(agent) }
            throw error
        }
        _ = try await registry.reload()
        return DeviceRemovalResult(
            deviceID: deviceID, instanceName: instance,
            stoppedServices: stopped.map { $0.deletingPathExtension().lastPathComponent },
            serviceStopFailures: [], removedItems: removed,
            researchEvidencePreserved: true, deviceModified: false,
            rollbackID: backupID
        )
    }

    private func move(_ source: URL, to destination: URL, beneath root: URL) throws {
        let base = root.standardizedFileURL.path
        guard source.standardizedFileURL.path.hasPrefix(base + "/"),
              (try? source.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) != true
        else { throw BridgeCoreError.invalidPath(source.path) }
        try fileManager.createDirectory(at: destination.deletingLastPathComponent(),
                                        withIntermediateDirectories: true,
                                        attributes: [.posixPermissions: 0o700])
        try fileManager.moveItem(at: source, to: destination)
    }

    private func ownedAgents(deviceID: String, instance: String) throws -> [URL] {
        let prefix = "com.liquidskysecurity.crypstore-"
        let roles = ["usbmux", "worker", "device-bridge", "bluetooth"]
        let files = (try? fileManager.contentsOfDirectory(
            at: launchAgentsRoot, includingPropertiesForKeys: nil
        )) ?? []
        return try files.filter { file in
            guard file.pathExtension == "plist", file.lastPathComponent.hasPrefix(prefix) else { return false }
            let label = file.deletingPathExtension().lastPathComponent
            let current = roles.contains { label == "\(prefix)\($0).\(instance)" }
            let possibleLegacyForward = label.hasPrefix("\(prefix)usbmux.")
            guard current || possibleLegacyForward else { return false }
            guard (try? file.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) != true,
                  let data = try? Data(contentsOf: file),
                  let plist = try? PropertyListSerialization.propertyList(
                    from: data, format: nil
                  ) as? [String: Any],
                  plist["Label"] as? String == label else {
                throw BridgeCoreError.invalidPath("Unsafe LaunchAgent for selected device")
            }
            let env = plist["EnvironmentVariables"] as? [String: String] ?? [:]
            let argv = plist["ProgramArguments"] as? [String] ?? []
            let exactForward = argv.indices.contains { index in
                argv[index] == "-u" && argv.indices.contains(index + 1)
                    && argv[index + 1] == deviceID
            } && argv.first.map { URL(fileURLWithPath: $0).lastPathComponent } == "iproxy"
            if current && env["CRYPSTORE_DEVICE_UDID"] != deviceID && !exactForward {
                throw BridgeCoreError.operationFailed("LaunchAgent belongs to another device")
            }
            return current || (possibleLegacyForward && exactForward)
        }.sorted { $0.path < $1.path }
    }

    private func stopIfLoaded(_ agent: URL) async throws -> Bool {
        guard let launchctlURL else { return false }
        let label = agent.deletingPathExtension().lastPathComponent
        let target = "gui/\(getuid())/\(label)"
        let status = try await runner.run(ScriptSpecification(
            identifier: "device.remove.status.\(label)", executableURL: launchctlURL,
            arguments: ["print", target], timeout: .seconds(10)
        ))
        if !status.succeeded {
            let missing = status.stderr.localizedCaseInsensitiveContains("could not find")
                || status.stderr.localizedCaseInsensitiveContains("not found")
            guard missing else {
                throw BridgeCoreError.operationFailed("Cannot determine LaunchAgent state: \(label)")
            }
            return false
        }
        let stopped = try await runner.run(ScriptSpecification(
            identifier: "device.remove.stop.\(label)", executableURL: launchctlURL,
            arguments: ["bootout", target], timeout: .seconds(15)
        ))
        if !stopped.succeeded {
            let retry = try await runner.run(ScriptSpecification(
                identifier: "device.remove.verify-stop.\(label)", executableURL: launchctlURL,
                arguments: ["print", target], timeout: .seconds(10)
            ))
            guard !retry.succeeded else {
                throw BridgeCoreError.operationFailed("Service remains loaded: \(label)")
            }
        }
        return true
    }

    private func start(_ agent: URL) async throws {
        guard let launchctlURL else { return }
        _ = try await runner.run(ScriptSpecification(
            identifier: "device.remove.rollback-start", executableURL: launchctlURL,
            arguments: ["bootstrap", "gui/\(getuid())", agent.path], timeout: .seconds(15)
        ))
    }
}
