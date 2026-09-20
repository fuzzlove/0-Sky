import CryptoKit
import Foundation

public actor DeviceRegistry {
    public let supportURL: URL
    private let fileManager: FileManager
    private var profiles: [String: DeviceProfile] = [:]

    public init(
        supportURL: URL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/0-Sky"),
        fileManager: FileManager = .default
    ) {
        self.supportURL = supportURL
        self.fileManager = fileManager
    }

    public func reload() throws -> [DeviceProfile] {
        let instances = supportURL.appendingPathComponent("instances", isDirectory: true)
        guard fileManager.fileExists(atPath: instances.path) else {
            profiles = [:]
            return []
        }
        let directories = try fileManager.contentsOfDirectory(
            at: instances,
            includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles]
        )
        var loaded: [String: DeviceProfile] = [:]
        for directory in directories {
            let values = try directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard values.isDirectory == true, values.isSymbolicLink != true else { continue }
            let configURL = directory.appendingPathComponent("config.json")
            guard fileManager.isReadableFile(atPath: configURL.path) else { continue }
            let config = try JSONSerialization.jsonObject(with: Data(contentsOf: configURL)) as? [String: Any]
            guard
                let config,
                let rawUDID = config["udid"] as? String,
                let instance = config["instance"] as? String,
                let rawPort = config["ssh_port"]
            else { continue }
            let udid = try BridgeValidation.validateUDID(rawUDID)
            _ = try BridgeValidation.validateInstance(instance)
            let port: Int
            if let value = rawPort as? Int { port = value }
            else if let value = rawPort as? String, let parsed = Int(value) { port = parsed }
            else { continue }
            _ = try BridgeValidation.validatePort(port)
            let alias = config["ssh_host_alias"] as? String ?? ""
            _ = try BridgeValidation.validateHostAlias(alias)
            let pairingURL = directory.appendingPathComponent("pairing-state.json")
            let pairing = (try? JSONSerialization.jsonObject(
                with: Data(contentsOf: pairingURL)
            )) as? [String: Any]
            let wireless = pairing?["wireless"] as? [String: Any]
            let relationship = wireless?["relationship"] as? [String: Any]
            let deviceHash = SHA256.hash(data: Data(udid.utf8))
                .map { String(format: "%02x", $0) }.joined().prefix(24)
            let capabilityURL = supportURL.appendingPathComponent("trusted-device-capabilities")
                .appendingPathComponent("\(deviceHash).json")
            let capability = (try? JSONSerialization.jsonObject(
                with: Data(contentsOf: capabilityURL)
            )) as? [String: Any]
            let profile = DeviceProfile(
                udid: udid,
                name: pairing?["device_name"] as? String
                    ?? relationship?["deviceName"] as? String,
                productType: pairing?["product_type"] as? String,
                osVersion: pairing?["product_version"] as? String,
                buildVersion: pairing?["build_version"] as? String,
                instanceName: instance,
                localPort: port,
                pairingVerified: pairing?["verified"] as? Bool ?? false,
                wirelessEnabled: Self.wirelessVerified(pairing)
                    || capability?["wifiPairingVerified"] as? Bool == true
                    || capability?["wirelessRSDVerified"] as? Bool == true,
                lastSeen: Self.date(pairing?["lastVerifiedAt"]),
                sshHost: config["ssh_host"] as? String ?? "127.0.0.1",
                sshHostAlias: alias,
                sshKeyPath: config["ssh_key"] as? String ?? "",
                knownHostsPath: config["ssh_known_hosts"] as? String
                    ?? directory.appendingPathComponent("device-known-hosts").path,
                macIdentityFingerprint: pairing?["mac_identity_fingerprint"] as? String
            )
            loaded[udid] = profile
        }
        profiles = loaded
        return loaded.values.sorted { $0.instanceName < $1.instanceName }
    }

    public func allProfiles() -> [DeviceProfile] {
        profiles.values.sorted { $0.instanceName < $1.instanceName }
    }

    public func profile(for udid: String) -> DeviceProfile? { profiles[udid] }

    public func update(_ profile: DeviceProfile) throws {
        _ = try BridgeValidation.validateUDID(profile.udid)
        _ = try BridgeValidation.validateInstance(profile.instanceName)
        _ = try BridgeValidation.validatePort(profile.localPort)
        _ = try BridgeValidation.validateHostAlias(profile.sshHostAlias)
        profiles[profile.udid] = profile
        try persistPublicProfile(profile)
    }

    private func persistPublicProfile(_ profile: DeviceProfile) throws {
        let directory = supportURL
            .appendingPathComponent("bridge-profiles", isDirectory: true)
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let destination = directory.appendingPathComponent(profile.instanceName + ".json")
        let temporary = directory.appendingPathComponent(".\(profile.instanceName).\(UUID().uuidString).tmp")
        let data = try JSONEncoder.sky.encode(profile)
        try data.write(to: temporary, options: .withoutOverwriting)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)
        if fileManager.fileExists(atPath: destination.path) {
            _ = try fileManager.replaceItemAt(destination, withItemAt: temporary)
        } else {
            try fileManager.moveItem(at: temporary, to: destination)
        }
    }

    private static func wirelessVerified(_ pairing: [String: Any]?) -> Bool {
        guard let wireless = pairing?["wireless"] as? [String: Any] else { return false }
        return wireless["wirelessRSDVerified"] as? Bool == true
            || (wireless["relationship"] as? [String: Any])?["wifiPairingVerified"] as? Bool == true
    }

    private static func date(_ value: Any?) -> Date {
        if let seconds = value as? TimeInterval { return Date(timeIntervalSince1970: seconds) }
        if let number = value as? NSNumber { return Date(timeIntervalSince1970: number.doubleValue) }
        return .distantPast
    }
}

public extension JSONEncoder {
    static var sky: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }
}
