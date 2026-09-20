import CryptoKit
import Foundation

/// Result of forgetting one device on the Mac. Device-side files and retained
/// research-session evidence are deliberately outside this operation's scope.
public struct DeviceRemovalResult: Codable, Sendable {
    public let deviceID: String
    public let instanceName: String
    public let stoppedServices: [String]
    public let serviceStopFailures: [String]
    public let removedItems: [String]
    public let researchEvidencePreserved: Bool
    public let deviceModified: Bool
}

/// Removes only one exact, validated Mac-side device enrollment. It never
/// invokes SSH or a device service and therefore cannot erase or mutate the
/// connected Apple device.
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
                message: "Removing the exact Mac-side 0-Sky device enrollment.",
                observed: ["instance": .string(instance)],
                expected: ["device_modified": .bool(false), "evidence_preserved": .bool(true)]
            ))
            do {
                let result = try await self.removeValidated(
                    deviceID: deviceID, instance: instance
                )
                await self.events.publish(BridgeEvent(
                    event: .deviceRemoved, deviceID: deviceID,
                    severity: result.serviceStopFailures.isEmpty ? .info : .warning,
                    component: "device_manager",
                    message: "Mac-side device enrollment removed; research evidence was preserved.",
                    observed: [
                        "removed_items": .number(Double(result.removedItems.count)),
                        "service_stop_failures": .number(Double(result.serviceStopFailures.count)),
                        "device_modified": .bool(false),
                    ],
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
        let roles = ["usbmux", "worker", "device-bridge", "bluetooth"]
        var stopped: [String] = []
        var stopFailures: [String] = []
        for role in roles {
            let label = "com.liquidskysecurity.crypstore-\(role).\(instance)"
            if let launchctlURL {
                do {
                    let result = try await runner.run(ScriptSpecification(
                        identifier: "device.remove.stop.\(role).\(instance)",
                        executableURL: launchctlURL,
                        arguments: ["bootout", "gui/\(getuid())/\(label)"],
                        timeout: .seconds(15)
                    ))
                    if result.succeeded { stopped.append(label) }
                    else { stopFailures.append(label) }
                } catch {
                    stopFailures.append(label)
                }
            }
        }

        var removed: [String] = []
        for role in roles {
            let label = "com.liquidskysecurity.crypstore-\(role).\(instance)"
            if try removeIfPresent(
                launchAgentsRoot.appendingPathComponent("\(label).plist"),
                beneath: launchAgentsRoot
            ) { removed.append("launch-agent:\(role)") }
        }

        let digest = SHA256.hash(data: Data(deviceID.utf8))
            .map { String(format: "%02x", $0) }.joined().prefix(24)
        let targets: [(String, URL)] = [
            ("instance", paths.supportRoot.appendingPathComponent("instances/\(instance)")),
            ("public-profile", paths.supportRoot.appendingPathComponent("bridge-profiles/\(instance).json")),
            ("runtime-state", paths.supportRoot.appendingPathComponent("state/\(instance)")),
            ("trust-receipt", paths.supportRoot.appendingPathComponent("trusted-devices/\(digest).json")),
            ("transport-capability", paths.supportRoot.appendingPathComponent("trusted-device-capabilities/\(digest).json")),
        ]
        for (name, target) in targets where try removeIfPresent(target, beneath: paths.supportRoot) {
            removed.append(name)
        }
        _ = try await registry.reload()
        return DeviceRemovalResult(
            deviceID: deviceID, instanceName: instance,
            stoppedServices: stopped, serviceStopFailures: stopFailures,
            removedItems: removed, researchEvidencePreserved: true,
            deviceModified: false
        )
    }

    private func removeIfPresent(_ target: URL, beneath root: URL) throws -> Bool {
        let safeRoot = root.standardizedFileURL.path
        let safeTarget = target.standardizedFileURL.path
        guard safeTarget != safeRoot, safeTarget.hasPrefix(safeRoot + "/") else {
            throw BridgeCoreError.invalidPath(target.path)
        }
        guard fileManager.fileExists(atPath: target.path)
                || (try? target.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true
        else { return false }
        try fileManager.removeItem(at: target)
        return true
    }
}
