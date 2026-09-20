import Foundation
import OSLog

public protocol DeviceDiscoveryBackend: Sendable {
    var name: String { get }
    func discover() async throws -> [SkyDevice]
}

public actor DeviceDiscoveryManager {
    private let backends: [any DeviceDiscoveryBackend]
    private let registry: DeviceRegistry
    private let logger = Logger(subsystem: "com.liquidsky.0sky.bridge", category: "device")
    private var lastSnapshot: [SkyDevice] = []

    public init(backends: [any DeviceDiscoveryBackend], registry: DeviceRegistry) {
        self.backends = backends
        self.registry = registry
    }

    public func discover() async -> [SkyDevice] {
        let profiles = (try? await registry.reload()) ?? []
        var merged: [String: SkyDevice] = [:]
        for profile in profiles {
            merged[profile.udid] = SkyDevice(
                udid: profile.udid,
                name: profile.name,
                productType: profile.productType,
                osVersion: profile.osVersion,
                buildVersion: profile.buildVersion,
                paired: profile.pairingVerified,
                trusted: profile.pairingVerified,
                lastSeen: profile.lastSeen,
                instanceName: profile.instanceName,
                localPort: profile.localPort,
                bridgeState: .offline
            )
        }
        await withTaskGroup(of: [SkyDevice].self) { group in
            for backend in backends {
                group.addTask {
                    do { return try await backend.discover() }
                    catch { return [] }
                }
            }
            for await devices in group {
                for device in devices {
                    guard (try? BridgeValidation.validateUDID(device.udid)) != nil else {
                        logger.error("Discovery backend returned an invalid UDID")
                        continue
                    }
                    if var old = merged[device.udid] {
                        old.name = device.name ?? old.name
                        old.productType = device.productType ?? old.productType
                        old.osVersion = device.osVersion ?? old.osVersion
                        old.buildVersion = device.buildVersion ?? old.buildVersion
                        old.usbConnected = old.usbConnected || device.usbConnected
                        old.wifiConnected = old.wifiConnected || device.wifiConnected
                        old.paired = old.paired || device.paired
                        old.trusted = old.trusted || device.trusted
                        old.lastSeen = max(old.lastSeen, device.lastSeen)
                        old.bridgeState = .deviceDetected
                        merged[device.udid] = old
                    } else {
                        merged[device.udid] = device
                    }
                }
            }
        }
        lastSnapshot = merged.values.sorted {
            ($0.name ?? $0.udid).localizedCaseInsensitiveCompare($1.name ?? $1.udid)
                == .orderedAscending
        }
        return lastSnapshot
    }

    public func snapshot() -> [SkyDevice] { lastSnapshot }
}

public struct PymobileDeviceDiscoveryBackend: DeviceDiscoveryBackend {
    public let name = "pymobiledevice3-usbmux"
    public let pythonURL: URL
    public let runner: ScriptRunner

    public init(pythonURL: URL, runner: ScriptRunner) {
        self.pythonURL = pythonURL
        self.runner = runner
    }

    public func discover() async throws -> [SkyDevice] {
        let specification = ScriptSpecification(
            identifier: "device.discovery.usbmux",
            executableURL: pythonURL,
            arguments: ["-m", "pymobiledevice3", "usbmux", "list", "--usb"],
            timeout: .seconds(15)
        )
        let result = try await runner.run(specification)
        guard result.exitCode == 0 else {
            throw BridgeCoreError.operationFailed(result.stderr)
        }
        return try Self.parse(Data(result.stdout.utf8))
    }

    public static func parse(_ data: Data) throws -> [SkyDevice] {
        guard let records = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw BridgeCoreError.malformedOutput("pymobiledevice3 USB device list")
        }
        return try records.map { value in
            guard let udid = (value["UniqueDeviceID"] ?? value["Identifier"]) as? String else {
                throw BridgeCoreError.malformedOutput("USB record has no identifier")
            }
            _ = try BridgeValidation.validateUDID(udid)
            return SkyDevice(
                udid: udid,
                name: value["DeviceName"] as? String,
                productType: value["ProductType"] as? String,
                osVersion: value["ProductVersion"] as? String,
                buildVersion: value["BuildVersion"] as? String,
                usbConnected: true,
                lastSeen: Date(),
                bridgeState: .deviceDetected
            )
        }
    }
}

public struct CoreDeviceDiscoveryBackend: DeviceDiscoveryBackend {
    public let name = "CoreDevice-devicectl"
    public let runner: ScriptRunner
    public let outputDirectory: URL

    public init(runner: ScriptRunner, outputDirectory: URL = URL(fileURLWithPath: NSTemporaryDirectory())) {
        self.runner = runner
        self.outputDirectory = outputDirectory
    }

    public func discover() async throws -> [SkyDevice] {
        let destination = outputDirectory
            .appendingPathComponent("0sky-devicectl-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: destination) }
        let direct = "/Applications/Xcode.app/Contents/Developer/usr/bin/devicectl"
        let useDirect = FileManager.default.isExecutableFile(atPath: direct)
        let specification = ScriptSpecification(
            identifier: "device.discovery.coredevice",
            executableURL: URL(fileURLWithPath: useDirect ? direct : "/usr/bin/xcrun"),
            arguments: (useDirect ? [] : ["devicectl"])
                + ["list", "devices", "--json-output", destination.path],
            timeout: .seconds(20)
        )
        let result = try await runner.run(specification)
        guard result.exitCode == 0, FileManager.default.isReadableFile(atPath: destination.path) else {
            throw BridgeCoreError.operationFailed(result.stderr)
        }
        return try Self.parse(Data(contentsOf: destination))
    }

    public static func parse(_ data: Data) throws -> [SkyDevice] {
        let root = try JSONSerialization.jsonObject(with: data)
        let dictionaries: [[String: Any]]
        if let root = root as? [String: Any],
           let result = root["result"] as? [String: Any],
           let devices = result["devices"] as? [[String: Any]] {
            // devicectl's `identifier` is a transient CoreDevice UUID.  The
            // stable hardware UDID is nested under hardwareProperties.  Only
            // parse the actual device records so nested dictionaries cannot
            // become duplicate/ghost devices.
            dictionaries = devices
        } else if let devices = root as? [[String: Any]] {
            dictionaries = devices
        } else {
            throw BridgeCoreError.malformedOutput("CoreDevice device list")
        }
        var result: [String: SkyDevice] = [:]
        for value in dictionaries {
            let hardware = value["hardwareProperties"] as? [String: Any]
            let properties = value["deviceProperties"] as? [String: Any]
            let connectionProperties = value["connectionProperties"] as? [String: Any]
            let raw = hardware?["udid"] ?? value["udid"] ?? value["hardwareIdentifier"]
                ?? (hardware == nil ? value["identifier"] : nil)
            guard let udid = raw as? String,
                  (try? BridgeValidation.validateUDID(udid)) != nil else { continue }
            let connection = String(describing:
                connectionProperties?["transportType"]
                    ?? value["connectionProperties"]
                    ?? value["transport"]
                    ?? ""
            )
                .lowercased()
            let pairing = String(describing: connectionProperties?["pairingState"] ?? "")
                .lowercased()
            let build = properties?["osBuildUpdate"] as? [String: Any]
            result[udid] = SkyDevice(
                udid: udid,
                name: properties?["name"] as? String
                    ?? value["name"] as? String ?? value["deviceName"] as? String,
                productType: hardware?["productType"] as? String
                    ?? value["productType"] as? String,
                osVersion: properties?["osVersionNumber"] as? String
                    ?? value["osVersion"] as? String ?? value["productVersion"] as? String,
                buildVersion: build?["buildVersion"] as? String
                    ?? properties?["buildVersion"] as? String
                    ?? value["buildVersion"] as? String,
                usbConnected: connection.contains("usb") || connection.contains("wired"),
                wifiConnected: connection.contains("network") || connection.contains("wifi"),
                paired: pairing.contains("paired"),
                trusted: pairing.contains("paired"),
                lastSeen: Date(),
                bridgeState: .deviceDetected
            )
        }
        return Array(result.values)
    }
}

public struct RemoteXPCDiscoveryBackend: DeviceDiscoveryBackend {
    public let name = "pymobiledevice3-remotexpc"
    public let pythonURL: URL
    public let runner: ScriptRunner

    public init(pythonURL: URL, runner: ScriptRunner) {
        self.pythonURL = pythonURL
        self.runner = runner
    }

    public func discover() async throws -> [SkyDevice] {
        let result = try await runner.run(ScriptSpecification(
            identifier: "device.discovery.remotexpc",
            executableURL: pythonURL,
            arguments: ["-m", "pymobiledevice3", "remote", "browse", "--timeout", "3"],
            timeout: .seconds(15)
        ))
        guard result.succeeded else { throw BridgeCoreError.operationFailed(result.stderr) }
        return try Self.parse(Data(result.stdout.utf8))
    }

    public static func parse(_ data: Data) throws -> [SkyDevice] {
        guard let records = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw BridgeCoreError.malformedOutput("RemoteXPC browse result")
        }
        var devices: [SkyDevice] = []
        for record in records {
            guard let rawUDID = record["udid"] as? String else { continue }
            let udid = try BridgeValidation.validateUDID(rawUDID)
            let connectionState = record["connectionState"] as? [String: Any]
            let connectionValue = connectionState?["value"] as? [String: Any]
            let attached = connectionValue?["attachedPhysically"] as? Bool ?? false
            let authenticated = (record["authState"] as? [String: Any])?["rawCase"] as? String
            let networkActive = record["networkAdvertActive"] as? Bool ?? false
            devices.append(SkyDevice(
                udid: udid,
                name: record["name"] as? String,
                productType: record["model"] as? String,
                usbConnected: attached,
                wifiConnected: !attached && networkActive,
                paired: authenticated == "authenticated",
                trusted: authenticated == "authenticated",
                lastSeen: Date(),
                bridgeState: .deviceDetected
            ))
        }
        return devices
    }
}
