import Foundation

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
        let candidates: [(String, [String], Bool)] = [
            ("Xcode CLI Tools", ["/usr/bin/xcrun"], true),
            ("SSH", ["/usr/bin/ssh"], true),
            ("launchctl", ["/bin/launchctl"], true),
            ("Python 3.12 for 0-Sky", Self.hostPythonCandidates, true),
            ("dpkg", ["/opt/homebrew/bin/dpkg", "/usr/local/bin/dpkg"], true),
            ("dpkg-deb", ["/opt/homebrew/bin/dpkg-deb", "/usr/local/bin/dpkg-deb"], true),
            ("iproxy", ["/opt/homebrew/bin/iproxy", "/usr/local/bin/iproxy"], true),
            ("ldid", ["/opt/homebrew/bin/ldid", "/usr/local/bin/ldid"], true),
            ("zstd", ["/opt/homebrew/bin/zstd", "/usr/local/bin/zstd"], true),
            ("Homebrew", ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"], false),
        ]
        var statuses = candidates.map { name, possiblePaths, required in
            let path = possiblePaths.first { fileManager.isExecutableFile(atPath: $0) }
            return DependencyStatus(
                name: name, path: path, required: required,
                available: path != nil,
                detail: path != nil ? "Available" : (required
                    ? "Missing — select Install All 0-Sky Requirements"
                    : "Not installed; the dependency installer can add it when needed")
            )
        }
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
        let coreDeviceCandidates = [
            "/Applications/Xcode.app/Contents/Developer/usr/bin/devicectl",
            "/Applications/Xcode.app/Contents/Developer/Library/PrivateFrameworks/CoreDevice.framework/Versions/A/Resources/bin/devicectl",
        ]
        let coreDevice = coreDeviceCandidates.first {
            fileManager.isExecutableFile(atPath: $0)
        }
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
