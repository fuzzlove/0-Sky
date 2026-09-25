import CryptoKit
import Foundation

public struct HostProfileInspection: Sendable {
    public enum State: Sendable { case missing, invalid, valid }
    public let state: State
    public let code: String?
    public let detail: String

    public var ready: Bool { state == .valid }
    public var failed: Bool { state == .invalid }
}

/// Checks the local 0-Sky artifact independently of Apple pairing and SSH.
/// An existing JSON file is not a completed profile until its identity, pin,
/// owner and permissions match the selected device.
public enum HostProfileInspector {
    public static func inspect(supportURL: URL, udid: String) -> HostProfileInspection {
        let instances = supportURL.appendingPathComponent("instances", isDirectory: true)
        let fm = FileManager.default
        guard let directories = try? fm.contentsOfDirectory(
            at: instances, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey]
        ) else {
            return .init(state: .missing, code: nil, detail: "No local host profile exists for this device.")
        }
        var matches: [URL] = []
        for directory in directories {
            guard let properties = try? directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]),
                  properties.isDirectory == true, properties.isSymbolicLink != true else { continue }
            let config = directory.appendingPathComponent("config.json")
            guard let data = try? Data(contentsOf: config),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  object["udid"] as? String == udid else { continue }
            matches.append(directory)
        }
        guard matches.count == 1, let directory = matches.first else {
            return matches.isEmpty
                ? .init(state: .missing, code: nil, detail: "No local host profile exists for this device.")
                : .init(state: .invalid, code: "ERR_PROFILE_STALE",
                        detail: "Multiple local profiles claim this device UDID.")
        }
        let config = directory.appendingPathComponent("config.json")
        guard let data = try? Data(contentsOf: config),
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .init(state: .invalid, code: "ERR_PROFILE_PARSE", detail: "The host profile JSON is invalid.")
        }
        let alias = "0sky-device-" + SHA256.hash(data: Data(udid.utf8))
            .map { String(format: "%02x", $0) }.joined().prefix(24)
        let pin = directory.appendingPathComponent("device-known-hosts")
        let portString = value["ssh_port"] as? String
            ?? (value["ssh_port"] as? NSNumber)?.stringValue
        let port = portString.flatMap(Int.init)
        let configuredPin = (value["ssh_known_hosts"] as? String).map {
            URL(fileURLWithPath: $0).standardizedFileURL.resolvingSymlinksInPath().path
        }
        let canonicalPin = pin.standardizedFileURL.resolvingSymlinksInPath().path
        let expected: [(String, Bool)] = [
            ("schema", value["schema"] as? Int == 2),
            ("instance", value["instance"] as? String == directory.lastPathComponent),
            ("udid", value["udid"] as? String == udid),
            ("ssh_host_alias", value["ssh_host_alias"] as? String == alias),
            ("ssh_known_hosts", configuredPin == canonicalPin),
            ("ssh_host", value["ssh_host"] as? String == "127.0.0.1"),
            ("ssh_port", port.map { (1024...65535).contains($0) } == true),
            ("ssh_key", (value["ssh_key"] as? String)?.hasPrefix("/") == true),
        ]
        if let field = expected.first(where: { !$0.1 })?.0 {
            return .init(state: .invalid, code: "ERR_PROFILE_STALE",
                         detail: "The saved host profile has an invalid \(field) field.")
        }
        guard privateFile(config), privateFile(pin),
              let pinText = try? String(contentsOf: pin, encoding: .ascii),
              !pinText.isEmpty,
              pinText.split(separator: "\n").allSatisfy({ line in
                  let fields = line.split(separator: " ")
                  guard fields.count == 3, fields[0] == alias,
                        ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
                         "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"]
                            .contains(String(fields[1])),
                        let decoded = Data(base64Encoded: String(fields[2])) else { return false }
                  return decoded.count >= 32
              }) else {
            return .init(state: .invalid, code: "ERR_PROFILE_PERMISSION",
                         detail: "The host profile or device SSH pin is missing or unsafe.")
        }
        return .init(state: .valid, code: nil, detail: "Exact-device host profile and SSH pin are present.")
    }

    private static func privateFile(_ url: URL) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              attributes[.type] as? FileAttributeType == .typeRegular,
              let mode = attributes[.posixPermissions] as? NSNumber,
              let owner = attributes[.ownerAccountID] as? NSNumber else { return false }
        return mode.intValue & 0o077 == 0 && owner.intValue == Int(getuid())
    }
}
