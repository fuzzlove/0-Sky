import BridgeCore
import Foundation
import Security

private final class HelperService: NSObject, BridgePrivilegedHelperProtocol {
    func helperVersion(reply: @escaping (String) -> Void) { reply("1.0.0") }

    func installApprovedService(
        identifier: String,
        configuration: Data,
        reply: @escaping (Bool, String?) -> Void
    ) {
        do {
            try validateService(identifier)
            guard configuration.count <= 64 * 1024 else {
                throw BridgeCoreError.unauthorized("service definition exceeds 64 KiB")
            }
            guard let plist = try PropertyListSerialization.propertyList(
                from: configuration, options: [], format: nil
            ) as? [String: Any], plist["Label"] as? String == identifier else {
                throw BridgeCoreError.unauthorized("service plist label mismatch")
            }
            guard let arguments = plist["ProgramArguments"] as? [String],
                  arguments.first == "/Library/PrivilegedHelperTools/com.liquidsky.0sky.bridge.helper" else {
                throw BridgeCoreError.unauthorized("service executable is not approved")
            }
            let destination = URL(fileURLWithPath: "/Library/LaunchDaemons/\(identifier).plist")
            let temporary = URL(fileURLWithPath: destination.path + ".\(UUID().uuidString).tmp")
            try configuration.write(to: temporary, options: .withoutOverwriting)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o644, .ownerAccountID: 0, .groupOwnerAccountID: 0],
                ofItemAtPath: temporary.path
            )
            if FileManager.default.fileExists(atPath: destination.path) {
                _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary)
            } else {
                try FileManager.default.moveItem(at: temporary, to: destination)
            }
            reply(true, nil)
        } catch { reply(false, error.localizedDescription) }
    }

    func setApprovedServiceState(
        identifier: String,
        action: String,
        reply: @escaping (Bool, String?) -> Void
    ) {
        do {
            try validateService(identifier)
            guard HelperAllowlist.serviceActions.contains(action) else {
                throw BridgeCoreError.unauthorized("service action is not approved")
            }
            let arguments: [String]
            switch action {
            case "start":
                arguments = ["bootstrap", "system", "/Library/LaunchDaemons/\(identifier).plist"]
            case "restart":
                arguments = ["kickstart", "-k", "system/\(identifier)"]
            default:
                arguments = ["bootout", "system/\(identifier)"]
            }
            let status = try runLaunchctl(arguments)
            reply(status == 0, status == 0 ? nil : "launchctl exited \(status)")
        } catch { reply(false, error.localizedDescription) }
    }

    func inspectApprovedPath(path: String, reply: @escaping (Data?, String?) -> Void) {
        do {
            let url = try approvedPath(path)
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            let safe: [String: Any] = [
                "path": url.path,
                "exists": true,
                "size": (attributes[.size] as? NSNumber)?.intValue ?? 0,
                "permissions": (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0,
                "owner": (attributes[.ownerAccountID] as? NSNumber)?.intValue ?? -1,
            ]
            reply(try JSONSerialization.data(withJSONObject: safe, options: .sortedKeys), nil)
        } catch { reply(nil, error.localizedDescription) }
    }

    func updateApprovedConfiguration(
        identifier: String,
        configuration: Data,
        reply: @escaping (Bool, String?) -> Void
    ) {
        do {
            try validateService(identifier)
            guard configuration.count <= 64 * 1024,
                  let object = try JSONSerialization.jsonObject(with: configuration) as? [String: Any] else {
                throw BridgeCoreError.unauthorized("bridge configuration is not a bounded JSON object")
            }
            let allowedKeys: Set<String> = ["schema", "enabled", "listenPort", "logLevel", "supportPath"]
            guard Set(object.keys).isSubset(of: allowedKeys),
                  object["schema"] as? Int == 1 else {
                throw BridgeCoreError.unauthorized("bridge configuration schema or key is not approved")
            }
            if let port = object["listenPort"] as? Int { _ = try BridgeValidation.validatePort(port) }
            if let level = object["logLevel"] as? String,
               !["error", "warning", "info", "debug"].contains(level) {
                throw BridgeCoreError.unauthorized("log level is not approved")
            }
            if let path = object["supportPath"] as? String { _ = try approvedPath(path) }
            let redacted = DiagnosticRedactor.redactJSONObject(object)
            let encoded = try JSONSerialization.data(withJSONObject: redacted, options: [.prettyPrinted, .sortedKeys])
            let root = URL(fileURLWithPath: "/Library/Application Support/0-Sky Bridge")
            try FileManager.default.createDirectory(
                at: root, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o755]
            )
            let destination = root.appendingPathComponent(identifier + ".json")
            try encoded.write(to: destination, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600, .ownerAccountID: 0, .groupOwnerAccountID: 0],
                ofItemAtPath: destination.path
            )
            reply(true, nil)
        } catch { reply(false, error.localizedDescription) }
    }

    private func validateService(_ identifier: String) throws {
        guard HelperAllowlist.serviceIdentifiers.contains(identifier) else {
            throw BridgeCoreError.unauthorized("service identifier is not approved")
        }
    }

    private func approvedPath(_ path: String) throws -> URL {
        guard path.hasPrefix("/"), !path.contains("\0") else {
            throw BridgeCoreError.invalidPath(path)
        }
        let candidate = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
        guard HelperAllowlist.pathRoots.contains(where: {
            candidate.path == $0 || candidate.path.hasPrefix($0 + "/")
        }) else { throw BridgeCoreError.unauthorized("path is not approved") }
        return candidate
    }

    private func runLaunchctl(_ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }
}

private final class HelperDelegate: NSObject, NSXPCListenerDelegate {
    private let service = HelperService()

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard Self.authorized(connection) else { return false }
        connection.exportedInterface = NSXPCInterface(with: BridgePrivilegedHelperProtocol.self)
        connection.exportedObject = service
        connection.resume()
        return true
    }

    private static func authorized(_ connection: NSXPCConnection) -> Bool {
        var guest: SecCode?
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: connection.processIdentifier)]
        guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &guest) == errSecSuccess,
              let guest else { return false }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(guest, [], &staticCode) == errSecSuccess,
              let staticCode else { return false }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              values[kSecCodeInfoIdentifier as String] as? String == "com.liquidsky.0sky.bridge" else {
            return false
        }
        guard SecCodeCheckValidity(guest, [], nil) == errSecSuccess else { return false }

        // Production builds must share a signing team. Ad-hoc local builds do
        // not carry a team identifier, so their already-validated bundle
        // identifier remains the reproducible development boundary.
        var selfCode: SecCode?
        var selfStaticCode: SecStaticCode?
        var selfInfo: CFDictionary?
        if SecCodeCopySelf([], &selfCode) == errSecSuccess, let selfCode,
           SecCodeCopyStaticCode(selfCode, [], &selfStaticCode) == errSecSuccess,
           let selfStaticCode,
           SecCodeCopySigningInformation(
                selfStaticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &selfInfo
           ) == errSecSuccess,
           let own = selfInfo as? [String: Any],
           let helperTeam = own[kSecCodeInfoTeamIdentifier as String] as? String {
            guard values[kSecCodeInfoTeamIdentifier as String] as? String == helperTeam else {
                return false
            }
        }
        return true
    }
}

private let delegate = HelperDelegate()
private let listener = NSXPCListener(machServiceName: "com.liquidsky.0sky.bridge.helper")
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
