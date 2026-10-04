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
        guard !FileManager.default.fileExists(
            atPath: resources.appendingPathComponent(".0sky-incomplete-build").path
        ) else { return nil }
        return hasCompleteKit(at: candidate) ? candidate : nil
    }

    public static func hasCompleteKit(at root: URL) -> Bool {
        let requiredFiles = [
            "SHA256SUMS", "PORTABILITY.json", "RELEASE_KIT_APPROVAL.json",
            "RELEASE_KIT_MANIFEST.json", "WHEEL_INVENTORY.json",
            "host-mac/HOST_RUNTIME_MANIFEST.json",
            "host-mac/runtime/bin/python3", "host-mac/runtime/bin/dpkg-deb",
            "host-mac/runtime/bin/iproxy", "host-mac/runtime/bin/idevice_id",
            "host-mac/install.py", "host-mac/pair.py",
            "host-mac/requirements-lock.txt", "payloads/0-Sky-Link-1.9.0-universal.ipa",
        ]
        var wheelhouseIsDirectory: ObjCBool = false
        let wheelhouse = FileManager.default.fileExists(
            atPath: root.appendingPathComponent("host-mac/wheelhouse").path,
            isDirectory: &wheelhouseIsDirectory
        ) && wheelhouseIsDirectory.boolValue
        return wheelhouse && requiredFiles.allSatisfy {
            FileManager.default.isReadableFile(atPath: root.appendingPathComponent($0).path)
        }
    }

    public func enrollmentInstaller() throws -> URL {
        if let repositoryRoot {
            for relative in ["bridge/0SkyBridge/Resources/Scripts/kit/host-mac/install.py",
                             "exploitdev/srdsh-work/components/zero-sky/kit/host-mac/install.py"] {
                let candidate = repositoryRoot.appendingPathComponent(relative)
                if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
            }
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
            for base in ["bridge/0SkyBridge/Resources/Scripts/kit",
                         "exploitdev/srdsh-work/components/zero-sky/kit"] {
                let candidate = repositoryRoot.appendingPathComponent("\(base)/\(relative)")
                if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
            }
        }
        if let bundledKitRoot {
            let candidate = bundledKitRoot.appendingPathComponent(relative)
            if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
        }
        throw BridgeCoreError.dependencyMissing("bundled 0-Sky Link IPA")
    }

    public func projectSetupController() throws -> URL {
        if let repositoryRoot {
            for relative in ["bridge/0SkyBridge/Resources/Scripts/0sky_project_setup.py",
                             "exploitdev/srdsh-work/components/zero-sky/main.py"] {
                let candidate = repositoryRoot.appendingPathComponent(relative)
                if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
            }
        }
        if let resources = Bundle.main.resourceURL {
            let candidate = resources.appendingPathComponent("Scripts/0sky_project_setup.py")
            if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
        }
        throw BridgeCoreError.dependencyMissing("complete 0-Sky project setup controller")
    }

    public func afc2RootMountController() throws -> URL {
        if let repositoryRoot {
            let candidate = repositoryRoot.appendingPathComponent(
                "bridge/0SkyBridge/Resources/Scripts/afc2_root_mount.py"
            )
            if FileManager.default.isReadableFile(atPath: candidate.path) { return candidate }
        }
        if let resources = Bundle.main.resourceURL {
            for candidate in [
                resources.appendingPathComponent("Scripts/afc2_root_mount.py"),
                resources.appendingPathComponent("afc2_root_mount.py"),
            ] where FileManager.default.isReadableFile(atPath: candidate.path) {
                return candidate
            }
        }
        throw BridgeCoreError.dependencyMissing("AFC2 Finder mount controller")
    }

    public func afc2RootMountPython(for profile: DeviceProfile) throws -> URL {
        var candidates: [URL] = []
        // Source builds use the repository's verified development environment.
        // Release builds use the selected device's pinned, offline-installed
        // environment and never borrow another device profile's interpreter.
        if let repositoryRoot {
            candidates.append(repositoryRoot.appendingPathComponent(".venv/bin/python"))
            candidates.append(repositoryRoot.appendingPathComponent(".venv/bin/python3"))
        }
        candidates.append(instanceDirectory(profile).appendingPathComponent("venv/bin/python3"))
        candidates.append(supportRoot.appendingPathComponent("venv/bin/python3"))
        if let candidate = candidates.first(where: {
            FileManager.default.isExecutableFile(atPath: $0.path)
                && Self.hasAFC2WebDAVModules(python: $0)
        }) {
            return candidate
        }
        throw BridgeCoreError.dependencyMissing(
            "pinned 0-Sky Python environment with pymobiledevice3 WebDAV support"
        )
    }

    private static func hasAFC2WebDAVModules(python: URL) -> Bool {
        let environment = python.deletingLastPathComponent().deletingLastPathComponent()
        let library = environment.appendingPathComponent("lib", isDirectory: true)
        let versions = (try? FileManager.default.contentsOfDirectory(
            at: library, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]
        )) ?? []
        return versions.contains { version in
            let packages = version.appendingPathComponent("site-packages", isDirectory: true)
            return FileManager.default.fileExists(
                atPath: packages.appendingPathComponent("pymobiledevice3", isDirectory: true).path
            ) && FileManager.default.fileExists(
                atPath: packages.appendingPathComponent("asgi_webdav", isDirectory: true).path
            ) && FileManager.default.fileExists(
                atPath: packages.appendingPathComponent("uvicorn", isDirectory: true).path
            )
        }
    }

    public func projectSetupKit() throws -> URL {
        if let bundledKitRoot, Self.hasCompleteKit(at: bundledKitRoot) {
            return bundledKitRoot
        }
        // A distributable app must carry its own complete kit. A source tree
        // found through the launch directory must not silently supply one.
        if Bundle.main.bundleURL.pathExtension.lowercased() == "app" {
            throw BridgeCoreError.dependencyMissing(
                "complete 0-Sky kit in this app bundle; the build or installer is incomplete"
            )
        }
        if let repositoryRoot {
            for base in ["bridge/0SkyBridge/Resources/Scripts/kit",
                         "exploitdev/srdsh-work/components/zero-sky/kit"] {
                let candidate = repositoryRoot.appendingPathComponent(base)
                if FileManager.default.isReadableFile(
                    atPath: candidate.appendingPathComponent("SHA256SUMS").path
                ) && FileManager.default.isReadableFile(
                    atPath: candidate.appendingPathComponent("host-mac/install.py").path
                ) { return candidate }
            }
        }
        throw BridgeCoreError.dependencyMissing(
            "complete 0-Sky kit; build with a verified kit or install a complete release"
        )
    }

    public func projectPython() throws -> URL {
        let candidate = supportRoot.appendingPathComponent("venv/bin/python3")
        guard managedPythonIsApproved(candidate) else {
            throw BridgeCoreError.dependencyMissing(
                "pinned 0-Sky Python environment. Open Dependencies, click "
                + "Install All 0-Sky Requirements, wait for REQUIREMENTS=PASS, "
                + "then return here and choose Resume. The repair uses the "
                + "signed bundled Python and does not require Homebrew."
            )
        }
        return candidate
    }

    public func bundledHostPython() -> URL? {
        guard let bundledKitRoot else { return nil }
        let candidate = bundledKitRoot.appendingPathComponent("host-mac/runtime/bin/python3")
        return FileManager.default.isExecutableFile(atPath: candidate.path) ? candidate : nil
    }

    public static func detectRepositoryRoot(from start: URL = URL(
        fileURLWithPath: FileManager.default.currentDirectoryPath
    )) -> URL? {
        var candidate = start.standardizedFileURL
        for _ in 0..<8 {
            if FileManager.default.fileExists(
                atPath: candidate.appendingPathComponent("exploitdev/srdsh-work/components/zero-sky/kit/host-mac/pair.py").path
            ) || FileManager.default.fileExists(
                atPath: candidate.appendingPathComponent("bridge/0SkyBridge/Resources/Scripts/kit/host-mac/pair.py").path
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
        let candidates = [
            instanceDirectory(profile).appendingPathComponent("venv/bin/python3"),
            supportRoot.appendingPathComponent("venv/bin/python3"),
        ]
        if let candidate = candidates.first(where: managedPythonIsApproved) {
            return candidate
        }
        throw BridgeCoreError.dependencyMissing(
            "an approved instance Python environment. Open Dependencies, click "
            + "Install All 0-Sky Requirements, then retry this exact device."
        )
    }

    private func managedPythonIsApproved(_ candidate: URL) -> Bool {
        let fileManager = FileManager.default
        guard fileManager.isExecutableFile(atPath: candidate.path) else { return false }
        // Source checkouts can use their explicitly prepared venv. A packaged
        // release must bind every managed venv to the signed bundled runtime;
        // otherwise a stale Homebrew/python.org symlink escapes ScriptRunner's
        // executable allowlist and makes the package machine-dependent.
        guard let bundledKitRoot else { return true }
        let runtime = bundledKitRoot
            .appendingPathComponent("host-mac/runtime", isDirectory: true)
            .standardizedFileURL.resolvingSymlinksInPath().path
        let resolved = candidate.standardizedFileURL.resolvingSymlinksInPath().path
        return resolved == runtime || resolved.hasPrefix(runtime + "/")
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
            for base in ["exploitdev/srdsh-work/components/zero-sky/kit",
                         "bridge/0SkyBridge/Resources/Scripts/kit"] {
                let source = repositoryRoot.appendingPathComponent("\(base)/host-mac/\(name)")
                if FileManager.default.isReadableFile(atPath: source.path) { return source }
            }
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
            for base in ["exploitdev/srdsh-work/components/zero-sky/kit",
                         "bridge/0SkyBridge/Resources/Scripts/kit"] {
                let source = repositoryRoot.appendingPathComponent("\(base)/host-mac/\(name)")
                if FileManager.default.isReadableFile(atPath: source.path) { return source }
            }
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
