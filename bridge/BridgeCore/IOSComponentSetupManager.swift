import Foundation

public enum IOSComponentSetupProfile: String, Codable, Sendable {
    /// Complete 0-Sky Project device payload: Link, Control, the runtime,
    /// bundled apps, and the bundled CatVNC research service.
    case completeProject = "COMPLETE_PROJECT"
    /// Runtime Manager, PreferenceLoader, the shared runtime Cryptex, and
    /// 0-Sky Control. This is the recommended first-time configuration.
    case required = "REQUIRED"
    /// Repair/converge only the required runtime packages and Cryptex.
    case coreRuntime = "CORE_RUNTIME"
}

public struct IOSComponentSetupPlan: Codable, Hashable, Sendable {
    public let profile: IOSComponentSetupProfile
    public let tier: RecoveryTier
    public let components: [String]
    public let preservesNewerPackages: Bool

    public init(profile: IOSComponentSetupProfile, tier: RecoveryTier,
                components: [String], preservesNewerPackages: Bool = true) {
        self.profile = profile
        self.tier = tier
        self.components = components
        self.preservesNewerPackages = preservesNewerPackages
    }
}

/// Typed front-end to the audited device bootstrap. The GUI never constructs
/// shell commands and the installer receives only validated instance data.
public actor IOSComponentSetupManager {
    private let runner: ScriptRunner
    private let paths: BridgePaths
    private let coordinator: OperationCoordinator
    private let events: EventBus

    public init(runner: ScriptRunner, paths: BridgePaths,
                coordinator: OperationCoordinator, events: EventBus) {
        self.runner = runner
        self.paths = paths
        self.coordinator = coordinator
        self.events = events
    }

    public static func plan(_ profile: IOSComponentSetupProfile) -> IOSComponentSetupPlan {
        switch profile {
        case .completeProject:
            IOSComponentSetupPlan(
                profile: profile, tier: .highRisk,
                components: [
                    "SRDssh + Procursus", "0-Sky Link", "0-Sky Control", "ElleKit",
                    "0-Sky Runtime Manager", "PreferenceLoader",
                    "Research runtime Cryptex", "Bundled 0-Sky apps",
                    "CatVNC research service", "Filza 4.0 research Cryptex",
                    "Exact-build appregistrard service", "Frida 17.18.0 host/device runtime",
                ]
            )
        case .required:
            IOSComponentSetupPlan(
                profile: profile, tier: .confirmationRequired,
                components: [
                    "ElleKit", "0-Sky Runtime Manager", "PreferenceLoader",
                    "Research runtime Cryptex", "0-Sky Control",
                ]
            )
        case .coreRuntime:
            IOSComponentSetupPlan(
                profile: profile, tier: .confirmationRequired,
                components: [
                    "ElleKit", "0-Sky Runtime Manager", "PreferenceLoader",
                    "Research runtime Cryptex",
                ]
            )
        }
    }

    /// Complete first-device convergence. Unlike the post-enrollment setup
    /// method below, this starts with Apple's exact-UDID RemoteXPC path and can
    /// establish SRDssh before SSH exists. The audited project controller then
    /// performs pairing, runtime, application and postcondition stages as one
    /// evidence-producing workflow.
    public func setupCompleteProject(
        device: SkyDevice,
        confirmed: Bool,
        onEvent: @escaping ScriptRunner.EventHandler = { _ in }
    ) async throws -> BridgeOperationResult {
        let udid = try BridgeValidation.validateUDID(device.udid)
        guard device.usbConnected else {
            throw BridgeCoreError.operationFailed(
                "Complete first-time iOS setup requires this exact selected SRD over USB."
            )
        }
        guard confirmed else {
            throw BridgeCoreError.unauthorized(
                "Complete project setup installs research Cryptexes and may reboot the device; explicit user confirmation is required."
            )
        }
        let python = try paths.projectPython()
        let controller = try paths.projectSetupController()
        let kit = try paths.projectSetupKit()
        let correlation = UUID()
        await events.publish(BridgeEvent(
            event: .iosComponentSetupStarted, deviceID: udid,
            component: "ios_component_setup",
            message: "Confirmed complete iOS project setup started.",
            observed: ["profile": .string(IOSComponentSetupProfile.completeProject.rawValue)],
            correlationID: correlation
        ))
        do {
            let result = try await coordinator.withLock(
                deviceID: udid, operation: "ios-complete-project-setup"
            ) {
                try await runner.run(
                    ScriptSpecification(
                        identifier: "ios-components.complete-project.\(udid)",
                        executableURL: python,
                        arguments: [controller.path, "--udid", udid],
                        environment: ["ZERO_SKY_KIT_ROOT": kit.path],
                        // The bundled Scripts directory is intentionally not a general-purpose
                        // execution root. Run the audited controller from the verified Kit root;
                        // Python still resolves its adjacent configuration module via argv[0].
                        workingDirectory: kit,
                        timeout: .seconds(3_600)
                    ),
                    onEvent: onEvent
                )
            }
            await events.publish(BridgeEvent(
                event: result.succeeded ? .iosComponentSetupSucceeded : .iosComponentSetupFailed,
                deviceID: udid,
                severity: result.succeeded ? .info : .error,
                component: "ios_component_setup",
                message: result.succeeded
                    ? "Complete 0-Sky iOS project installed and verified."
                    : "Complete 0-Sky iOS project setup failed a postcondition.",
                observed: ["exit_code": .number(Double(result.exitCode))],
                correlationID: correlation
            ))
            return result
        } catch {
            await events.publish(BridgeEvent(
                event: .iosComponentSetupFailed, deviceID: udid,
                severity: .error, component: "ios_component_setup",
                message: error.localizedDescription,
                correlationID: correlation
            ))
            throw error
        }
    }

    public func setup(profile device: DeviceProfile,
                      selection: IOSComponentSetupProfile = .required,
                      confirmed: Bool,
                      onEvent: @escaping ScriptRunner.EventHandler = { _ in }) async throws -> BridgeOperationResult {
        let udid = try BridgeValidation.validateUDID(device.udid)
        _ = try BridgeValidation.validateInstance(device.instanceName)
        guard confirmed else {
            throw BridgeCoreError.unauthorized(
                "Installing iOS components is a Tier 2 operation and requires user confirmation."
            )
        }
        let python = try paths.python(for: device)
        let installer = try paths.hostScript("bootstrap_device.py", profile: device)
        var arguments = [
            installer.path,
            "--support", paths.supportRoot.path,
            "--instance-name", device.instanceName,
        ]
        switch selection {
        case .completeProject:
            let linkIPA = try paths.zeroSkyLinkIPA()
            arguments += ["--apps", "--catvnc", "--zero-sky-ipa", linkIPA.path]
        case .required:
            arguments.append("--commissary")
        case .coreRuntime:
            break
        }
        // Capture an immutable value before entering the @Sendable coordinator
        // closure. Swift 6 correctly rejects capturing a mutable local here.
        let setupArguments = arguments
        let correlation = UUID()
        await events.publish(BridgeEvent(
            event: .iosComponentSetupStarted, deviceID: udid,
            component: "ios_component_setup",
            message: "Confirmed iOS component setup started.",
            observed: ["profile": .string(selection.rawValue)],
            correlationID: correlation
        ))
        do {
            let result = try await coordinator.withLock(
                deviceID: udid, operation: "ios-component-setup"
            ) {
                try await runner.run(
                    ScriptSpecification(
                        identifier: "ios-components.\(selection.rawValue.lowercased()).\(device.instanceName)",
                        executableURL: python,
                        arguments: setupArguments,
                        workingDirectory: installer.deletingLastPathComponent(),
                        timeout: .seconds(1_800)
                    ),
                    onEvent: onEvent
                )
            }
            await events.publish(BridgeEvent(
                event: result.succeeded ? .iosComponentSetupSucceeded : .iosComponentSetupFailed,
                deviceID: udid,
                severity: result.succeeded ? .info : .error,
                component: "ios_component_setup",
                message: result.succeeded
                    ? "Required iOS components were installed and converged."
                    : "iOS component setup returned a failure.",
                observed: ["exit_code": .number(Double(result.exitCode))],
                correlationID: correlation
            ))
            return result
        } catch {
            await events.publish(BridgeEvent(
                event: .iosComponentSetupFailed, deviceID: udid,
                severity: .error, component: "ios_component_setup",
                message: error.localizedDescription,
                correlationID: correlation
            ))
            throw error
        }
    }
}
