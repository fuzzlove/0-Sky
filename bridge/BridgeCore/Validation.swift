import Foundation

public enum BridgeValidation {
    private static let udidPattern = try! NSRegularExpression(
        pattern: "^[A-Za-z0-9-]{20,80}$"
    )
    private static let instancePattern = try! NSRegularExpression(
        pattern: "^[a-z0-9](?:[a-z0-9-]{0,62})$"
    )
    private static let hostAliasPattern = try! NSRegularExpression(
        pattern: "^0sky-device-[a-f0-9]{24}$"
    )

    private static func matches(_ expression: NSRegularExpression, _ value: String) -> Bool {
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return expression.firstMatch(in: value, range: range)?.range == range
    }

    public static func validateUDID(_ value: String) throws -> String {
        guard matches(udidPattern, value) else { throw BridgeCoreError.invalidUDID(value) }
        return value
    }

    public static func validateInstance(_ value: String) throws -> String {
        guard matches(instancePattern, value) else { throw BridgeCoreError.invalidPath(value) }
        return value
    }

    public static func validateHostAlias(_ value: String) throws -> String {
        guard matches(hostAliasPattern, value) else { throw BridgeCoreError.invalidPath(value) }
        return value
    }

    public static func validatePort(_ value: Int) throws -> Int {
        guard (1024...65535).contains(value) else {
            throw BridgeCoreError.invalidPath("port \(value)")
        }
        return value
    }

    public static func canonicalPath(_ raw: String, allowedRoots: [URL]) throws -> URL {
        guard raw.hasPrefix("/"), !raw.contains("\0") else {
            throw BridgeCoreError.invalidPath(raw)
        }
        let candidate = URL(fileURLWithPath: raw).standardizedFileURL.resolvingSymlinksInPath()
        let accepted = allowedRoots.contains { root in
            let canonicalRoot = root.standardizedFileURL.resolvingSymlinksInPath().path
            return candidate.path == canonicalRoot || candidate.path.hasPrefix(canonicalRoot + "/")
        }
        guard accepted else { throw BridgeCoreError.invalidPath(raw) }
        return candidate
    }

    public static func executableIsSafe(_ url: URL) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular else {
            throw BridgeCoreError.unsafeExecutable(url.path)
        }
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
        guard permissions & 0o022 == 0, permissions & 0o111 != 0 else {
            throw BridgeCoreError.unsafeExecutable(url.path)
        }
        let owner = (attributes[.ownerAccountID] as? NSNumber)?.intValue ?? -1
        guard owner == 0 || owner == Int(getuid()) else {
            throw BridgeCoreError.unsafeExecutable(url.path)
        }
    }

    public static func safeEnvironment(overrides: [String: String] = [:]) throws -> [String: String] {
        let allowed = try NSRegularExpression(pattern: "^[A-Z][A-Z0-9_]{0,63}$")
        var environment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
            "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
            "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8",
        ]
        for (key, value) in overrides {
            guard matches(allowed, key), !value.contains("\0") else {
                throw BridgeCoreError.invalidPath("environment \(key)")
            }
            environment[key] = value
        }
        return environment
    }
}
