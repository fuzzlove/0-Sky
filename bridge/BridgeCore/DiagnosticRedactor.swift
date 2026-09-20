import Foundation

public enum DiagnosticRedactor {
    private static let rules: [(NSRegularExpression, String)] = {
        let patterns = [
            (#"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"#, ""),
            (#"(?i)(password|passwd|token|secret|authorization)\s*[:=]\s*[^\s,;]+"#, "$1=<redacted>"),
            (#"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"#, "<private-key-redacted>"),
            (#"(?i)ssh-(?:ed25519|rsa)\s+[A-Za-z0-9+/=]{32,}"#, "<public-key-redacted>"),
            (#"(?i)X-TrollStore-Bridge-Token:\s*[^\s]+"#, "X-TrollStore-Bridge-Token: <redacted>"),
            (#"/Users/[^/\s]+"#, "~"),
        ]
        return patterns.compactMap { pattern, replacement in
            guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
            return (regex, replacement)
        }
    }()

    // Legacy machine identifiers remain stable for update compatibility, but
    // they are implementation details and must never leak into researcher-
    // facing logs, diagnostics, errors, or script output.
    private static let legacyBranding = try! NSRegularExpression(
        pattern: "(?i)(?:trollstore|crypstore)"
    )

    public static func redact(_ input: String) -> String {
        var value = input
        for (rule, replacement) in rules {
            let range = NSRange(value.startIndex..<value.endIndex, in: value)
            value = rule.stringByReplacingMatches(
                in: value, range: range, withTemplate: replacement
            )
        }
        let brandingRange = NSRange(value.startIndex..<value.endIndex, in: value)
        value = legacyBranding.stringByReplacingMatches(
            in: value, range: brandingRange, withTemplate: "Commissary"
        )
        return value
    }

    public static func redactJSONObject(_ value: Any) -> Any {
        if let dictionary = value as? [String: Any] {
            return dictionary.reduce(into: [String: Any]()) { result, pair in
                let key = pair.key.lowercased()
                if key.contains("password") || key.contains("token")
                    || key.contains("secret") || key.contains("private")
                    || key.contains("pairingrecord") || key.contains("pairing_record")
                    || key.contains("appleaccount") || key.contains("apple_account") {
                    result[pair.key] = "<redacted>"
                } else {
                    result[pair.key] = redactJSONObject(pair.value)
                }
            }
        }
        if let array = value as? [Any] { return array.map(redactJSONObject) }
        if let string = value as? String { return redact(string) }
        return value
    }

    public static func redactForExport(_ input: String, publicProfile: Bool) -> String {
        var value = redact(input)
        let patterns = [
            #"(?i)\b(?:[0-9a-f]{8}-){3}[0-9a-f]{12}\b|\b[0-9a-f]{24,40}\b"#,
            #"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"#,
            #"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"#,
        ]
        let replacements = ["<device-id-redacted>", "<ip-redacted>", "<account-redacted>"]
        for (pattern, replacement) in zip(patterns, replacements) {
            value = value.replacingOccurrences(of: pattern, with: replacement, options: .regularExpression)
        }
        if publicProfile {
            value = value.replacingOccurrences(
                of: #"(?i)(deviceName|ssid|computerName)\"?\s*[:=]\s*\"?[^\",\n}]*\"?"#,
                with: "$1:<redacted>", options: .regularExpression
            )
        }
        return value
    }
}
