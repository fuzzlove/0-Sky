import Foundation

public struct BridgePaths: Sendable {
    public let repositoryRoot: URL?
    public let supportRoot: URL
    public let bundledKitRoot: URL?

    public init(
        repositoryRoot: URL? = BridgePaths.detectRepositoryRoot(),
        supportRoot: URL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/0-Sky"),
        bundledKitRoot: URL? = BridgePaths.detectBundledKitRoot()
    ) {
        self.repositoryRoot = repositoryRoot
        self.supportRoot = supportRoot
        self.bundledKitRoot = bundledKitRoot
    }

    public static func detectBundledKitRoot() -> URL? {
        guard let resources = Bundle.main.resourceURL else { return nil }
        let candidate = resources.appendingPathComponent("Kit")
        return FileManager.default.fileExists(
            atPath: candidate.appendingPathComponent("host-mac/install.py").path
        ) ? candidate : nil
    }

    public func enrollmentInstaller() throws -> URL {
        if let repositoryRoot {
            let candidate = repositoryRoot.appendingPathComponent(
                "exploitdev/srdsh-work/components/zero-sky/kit/host-mac/install.py"
            )
            if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
        }
        if let bundledKitRoot {
            let candidate = bundledKitRoot.appendingPathComponent("host-mac/install.py")
            if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
        }
        throw BridgeCoreError.dependencyMissing("bundled 0-Sky enrollment kit")
    }

    public func dependencyInstaller() throws -> URL {
        let name = "Install 0-Sky Dependencies.command"
        if let repositoryRoot {
            let candidate = repositoryRoot.appendingPathComponent(name)
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
        }
        if let resources = Bundle.main.resourceURL {
            for candidate in [
                resources.appendingPathComponent("Scripts/\(name)"),
                resources.appendingPathComponent(name),
            ] where FileManager.default.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
        }
        throw BridgeCoreError.dependencyMissing(name)
    }

    public func zeroSkyLinkIPA() throws -> URL {
        let relative = "payloads/0-Sky-Link-1.9.0-universal.ipa"
        if let repositoryRoot {
            let candidate = repositoryRoot.appendingPathComponent(
                "exploitdev/srdsh-work/components/zero-sky/kit/\(relative)"
            )
            if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
        }
        if let bundledKitRoot {
            let candidate = bundledKitRoot.appendingPathComponent(relative)
            if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
        }
        throw BridgeCoreError.dependencyMissing("bundled 0-Sky Link IPA")
    }

    public func projectSetupController() throws -> URL {
        if let repositoryRoot {
            let candidate = repositoryRoot.appendingPathComponent(
                "exploitdev/srdsh-work/components/zero-sky/main.py"
            )
            if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
        }
        if let resources = Bundle.main.resourceURL {
            let candidate = resources.appendingPathComponent("Scripts/0sky_project_setup.py")
            if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
        }
        throw BridgeCoreError.dependencyMissing("complete 0-Sky project setup controller")
    }

    public func projectSetupKit() throws -> URL {
        if let repositoryRoot {
            let candidate = repositoryRoot.appendingPathComponent(
                "exploitdev/srdsh-work/components/zero-sky/kit"
            )
            if FileManager.default.isReadableFile(
                atPath: candidate.appendingPathComponent("SHA256SUMS").path
            ) { return candidate }
        }
        if let bundledKitRoot { return bundledKitRoot }
        throw BridgeCoreError.dependencyMissing("verified complete 0-Sky project kit")
    }

    public func projectPython() throws -> URL {
        let candidate = supportRoot.appendingPathComponent("venv/bin/python3")
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw BridgeCoreError.dependencyMissing(
                "pinned 0-Sky Python environment; install missing dependencies first"
            )
        }
        return candidate
    }

    public static func detectRepositoryRoot(from start: URL = URL(
        fileURLWithPath: FileManager.default.currentDirectoryPath
    )) -> URL? {
        var candidate = start.standardizedFileURL
        for _ in 0..<8 {
            if FileManager.default.fileExists(
                atPath: candidate.appendingPathComponent("exploitdev/srdsh-work/components/zero-sky/kit/host-mac/pair.py").path
            ) { return candidate }
            let parent = candidate.deletingLastPathComponent()
            if parent == candidate { break }
            candidate = parent
        }
        return nil
    }

    public func instanceDirectory(_ profile: DeviceProfile) -> URL {
        supportRoot.appendingPathComponent("instances/\(profile.instanceName)")
    }

    public func python(for profile: DeviceProfile) throws -> URL {
        let candidate = instanceDirectory(profile).appendingPathComponent("venv/bin/python3")
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw BridgeCoreError.dependencyMissing(candidate.path)
        }
        return candidate
    }

    public func hostScript(_ name: String, profile: DeviceProfile? = nil) throws -> URL {
        let safeNames: Set<String> = [
            "pair.py", "install.py", "refresh.py", "audit_device.py",
            "bootstrap_device.py", "apple_device_transport.py", "uninstall.py",
            "multi_host_pairing.py",
        ]
        guard safeNames.contains(name) else { throw BridgeCoreError.invalidPath(name) }
        // Pairing/trust logic is security-sensitive and must use the audited
        // application/repository revision. Per-instance copies remain the
        // compatibility fallback for other lifecycle scripts, but an old
        // pair.py must not erase a newer durable wireless proof.
        let requiresCurrentRevision = name == "pair.py" || name == "multi_host_pairing.py"
        if requiresCurrentRevision, let repositoryRoot {
            let source = repositoryRoot.appendingPathComponent(
                "exploitdev/srdsh-work/components/zero-sky/kit/host-mac/\(name)"
            )
            if FileManager.default.isReadableFile(atPath: source.path) { return source }
        }
        if requiresCurrentRevision, let bundledKitRoot {
            let bundled = bundledKitRoot.appendingPathComponent("host-mac/\(name)")
            if FileManager.default.isReadableFile(atPath: bundled.path) { return bundled }
        }
        if let profile {
            let installed = instanceDirectory(profile).appendingPathComponent("host-mac/\(name)")
            if FileManager.default.isReadableFile(atPath: installed.path) { return installed }
        }
        if let repositoryRoot {
            let source = repositoryRoot.appendingPathComponent(
                "exploitdev/srdsh-work/components/zero-sky/kit/host-mac/\(name)"
            )
            if FileManager.default.isReadableFile(atPath: source.path) { return source }
        }
        if let bundledKitRoot {
            let bundled = bundledKitRoot.appendingPathComponent("host-mac/\(name)")
            if FileManager.default.isReadableFile(atPath: bundled.path) { return bundled }
        }
        throw BridgeCoreError.dependencyMissing(name)
    }

    public func toolScript(_ name: String) throws -> URL {
        let safeNames: Set<String> = [
            "zero_sky_fleet.py", "physical_wireless_readiness_test.py",
            "wireless_handoff_test.py", "physical_reboot_pairing_test.py",
            "physical_pair_button_test.py", "physical_locked_pairing_test.py",
        ]
        guard safeNames.contains(name), let repositoryRoot else {
            throw BridgeCoreError.invalidPath(name)
        }
        let candidate = repositoryRoot.appendingPathComponent("tools/\(name)")
        guard FileManager.default.isReadableFile(atPath: candidate.path) else {
            throw BridgeCoreError.dependencyMissing(candidate.path)
        }
        return candidate
    }
}
