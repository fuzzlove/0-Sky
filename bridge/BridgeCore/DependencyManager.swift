import Foundation

public enum HostToolResolver {
    /// PATH is consulted first. Standard and common developer-tool locations
    /// are search candidates for optional diagnostics launched from the GUI.
    /// Mandatory packaged runtime components are resolved directly from Kit
    /// and never accepted from these fallbacks.
    public static func executable(
        _ name: String,
        searchPath: String? = ProcessInfo.processInfo.environment["PATH"],
        fallbackDirectories: [String] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin",
                                         "/opt/homebrew/bin", "/usr/local/bin"]
    ) -> String? {
        guard !name.isEmpty, !name.contains("/"), !name.contains("\0") else { return nil }
        let directories = (searchPath ?? "").split(separator: ":").map(String.init)
            + fallbackDirectories
        for directory in directories where !directory.isEmpty {
            let candidate = URL(fileURLWithPath: directory).appendingPathComponent(name).path
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return URL(fileURLWithPath: candidate).resolvingSymlinksInPath().path
            }
        }
        return nil
    }

    public static func output(_ executable: String, arguments: [String], timeout: TimeInterval = 5) -> String? {
        guard FileManager.default.isExecutableFile(atPath: executable) else { return nil }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = Pipe()
        do { try process.run() } catch { return nil }
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
        if process.isRunning { process.terminate(); process.waitUntilExit(); return nil }
        guard process.terminationStatus == 0 else { return nil }
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        guard data.count <= 8192 else { return nil }
        return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public static func xcrunTool(_ name: String) -> String? {
        guard let xcrun = executable("xcrun"),
              let result = output(xcrun, arguments: ["--find", name]),
              result.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: result) else {
            return nil
        }
        return URL(fileURLWithPath: result).resolvingSymlinksInPath().path
    }
}

public struct DependencyManager: Sendable {
    public static let bundledRuntimeComponents = [
        "python3", "dpkg-deb", "iproxy", "idevice_id",
    ]

    public init() {}

    public func inspect(paths: BridgePaths) -> [DependencyStatus] {
        let fileManager = FileManager.default
        let bundledCandidates: [(String, String)] = [
            ("Bundled Python 3.12", "python3"),
            ("Bundled Debian extractor", "dpkg-deb"),
            ("Bundled USB forwarder", "iproxy"),
            ("Bundled USB device discovery", "idevice_id"),
        ]
        var statuses = bundledCandidates.map { name, command in
            let bundled = paths.bundledKitRoot?
                .appendingPathComponent("host-mac/runtime/bin/\(command)")
            let path: String? = bundled.flatMap {
                fileManager.isExecutableFile(atPath: $0.path) ? $0.path : nil
            }
            return DependencyStatus(
                name: name, path: path, required: true,
                available: path != nil,
                detail: path != nil
                    ? "Present in the application; the installer verifies its manifest hash"
                    : "Missing from the application — reinstall the complete verified package"
            )
        }
        for (name, command) in [("macOS SSH", "ssh"), ("macOS service manager", "launchctl")] {
            let path = HostToolResolver.executable(command)
            statuses.append(DependencyStatus(
                name: name, path: path, required: true, available: path != nil,
                detail: path != nil
                    ? "Provided by macOS"
                    : "Required macOS component missing — install macOS updates or repair macOS"
            ))
        }
        let hostPython = paths.bundledHostPython()?.path
        statuses.append(DependencyStatus(
            name: "Bundled Python version", path: hostPython, required: true,
            available: hostPython.flatMap {
                HostToolResolver.output($0, arguments: ["--version"])
            }?.hasPrefix("Python 3.12.") == true,
            detail: hostPython == nil
                ? "Bundled Python is absent; reinstall the complete verified package"
                : "Must report Python 3.12; the dependency installer performs the final check"
        ))
        let sharedPython = paths.supportRoot.appendingPathComponent("venv/bin/python3")
        let python = try? paths.projectPython()
        let stale = fileManager.isExecutableFile(atPath: sharedPython.path) && python == nil
        statuses.append(DependencyStatus(
            name: "Pinned Python environment", path: python?.path, required: true,
            available: python != nil,
            detail: stale
                ? "Repair required — the existing environment points outside the signed bundled runtime. Click Install All 0-Sky Requirements; the previous environment is preserved in the 0-Sky recovery directory."
                : (python == nil
                    ? "Missing — click Install All 0-Sky Requirements to install it offline from this signed app"
                    : "Available and bound to the signed bundled Python runtime")
        ))
        let coreDevice = HostToolResolver.xcrunTool("devicectl")
        statuses.append(DependencyStatus(
            name: "CoreDevice/devicectl", path: coreDevice, required: false,
            available: coreDevice != nil,
            detail: coreDevice == nil
                ? "Optional Xcode devicectl is unavailable; bundled usbmux discovery remains active"
                : "Available"
        ))
        let kit = try? paths.hostScript("pair.py")
        statuses.append(DependencyStatus(
            name: "0-Sky bridge components", path: kit?.path, required: true,
            available: kit != nil,
            detail: kit == nil ? "Host bridge kit was not found" : "Available"
        ))
        return statuses
    }
}
