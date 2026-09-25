import Foundation

public enum HostToolResolver {
    /// PATH is consulted first. Standard macOS and Homebrew locations are
    /// search candidates for GUI launches with a deliberately small PATH.
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
    public static let requiredHomebrewFormulae = [
        "python@3.12", "dpkg", "libusbmuxd", "zstd", "ldid",
        "autoconf", "automake", "pkgconf",
    ]

    public static let hostPythonCandidates = [
        "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3",
        "/opt/homebrew/bin/python3.12",
        "/usr/local/bin/python3.12",
    ]

    public init() {}

    public func inspect(paths: BridgePaths) -> [DependencyStatus] {
        let fileManager = FileManager.default
        let candidates: [(String, String, Bool)] = [
            ("Xcode CLI Tools", "xcrun", true),
            ("SSH", "ssh", true),
            ("launchctl", "launchctl", true),
            ("dpkg", "dpkg", true),
            ("dpkg-deb", "dpkg-deb", true),
            ("iproxy", "iproxy", true),
            ("ldid", "ldid", true),
            ("zstd", "zstd", true),
            ("Homebrew", "brew", false),
        ]
        var statuses = candidates.map { name, command, required in
            let path = HostToolResolver.executable(command)
            return DependencyStatus(
                name: name, path: path, required: required,
                available: path != nil,
                detail: path != nil ? "Discovered from PATH or a standard tool directory" : (required
                    ? "Missing — select Install All 0-Sky Requirements"
                    : "Not installed; the dependency installer can add it when needed")
            )
        }
        let pythonCandidates = [HostToolResolver.executable("python3.12"),
                                Self.hostPythonCandidates.first(where: { fileManager.isExecutableFile(atPath: $0) })]
            .compactMap { $0 }
        let hostPython = pythonCandidates.first {
            HostToolResolver.output($0, arguments: ["--version"])?.hasPrefix("Python 3.12.") == true
        }
        statuses.append(DependencyStatus(
            name: "Python 3.12 for 0-Sky", path: hostPython, required: true,
            available: hostPython != nil,
            detail: hostPython == nil ? "Python 3.12 was not found or failed its version check"
                : "Version-checked Python 3.12"
        ))
        let sharedPython = paths.supportRoot.appendingPathComponent("venv/bin/python3")
        let instances = paths.supportRoot.appendingPathComponent("instances")
        let instancePython = ((try? fileManager.contentsOfDirectory(
            at: instances, includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )) ?? []).map { $0.appendingPathComponent("venv/bin/python3") }
            .first(where: { fileManager.isExecutableFile(atPath: $0.path) })
        let python = fileManager.isExecutableFile(atPath: sharedPython.path)
            ? sharedPython : instancePython
        statuses.append(DependencyStatus(
            name: "Pinned Python environment", path: python?.path, required: true,
            available: python != nil,
            detail: python == nil
                ? "Missing — installed offline by Install All 0-Sky Requirements"
                : "Available"
        ))
        let coreDevice = HostToolResolver.xcrunTool("devicectl")
        statuses.append(DependencyStatus(
            name: "CoreDevice/devicectl", path: coreDevice, required: false,
            available: coreDevice != nil,
            detail: coreDevice == nil
                ? "Optional devicectl executable is unavailable; usbmux fallback remains active"
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
