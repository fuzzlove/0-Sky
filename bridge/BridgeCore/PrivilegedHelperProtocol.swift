import Foundation

@objc public protocol BridgePrivilegedHelperProtocol {
    func helperVersion(reply: @escaping (String) -> Void)
    func installApprovedService(
        identifier: String,
        configuration: Data,
        reply: @escaping (Bool, String?) -> Void
    )
    func setApprovedServiceState(
        identifier: String,
        action: String,
        reply: @escaping (Bool, String?) -> Void
    )
    func inspectApprovedPath(
        path: String,
        reply: @escaping (Data?, String?) -> Void
    )
    func updateApprovedConfiguration(
        identifier: String,
        configuration: Data,
        reply: @escaping (Bool, String?) -> Void
    )
}

public enum HelperAllowlist {
    public static let serviceIdentifiers: Set<String> = [
        "com.liquidsky.0sky.bridge.monitor",
    ]
    public static let serviceActions: Set<String> = ["start", "restart", "stop"]
    public static let pathRoots: [String] = [
        "/Library/PrivilegedHelperTools/com.liquidsky.0sky.bridge.helper",
        "/Library/LaunchDaemons/com.liquidsky.0sky.bridge.monitor.plist",
        "/Library/Application Support/0-Sky Bridge",
    ]
}
