import CryptoKit
import Darwin
import Foundation
import OSLog

/// Admission control for the unprivileged bridge Mach service.
///
/// The service pins hashes of the GUI and diagnostic client from its own app
/// bundle at process startup. A connection is admitted only when it is from
/// the same effective user, its kernel-reported executable path is one of
/// those pinned siblings, and the file still has the pinned digest. This keeps
/// client authentication synchronous and bounded; Security.framework's live
/// guest lookup can otherwise block the serial NSXPC admission queue while a
/// signed GUI is itself waiting on the reply.
public enum CodeIdentityValidator {
    private struct TrustedExecutable: Sendable {
        let identifier: String
        let digest: SHA256.Digest
    }

    private static let logger = Logger(subsystem: "com.liquidsky.0sky.bridge", category: "xpc-auth")

    /// Initialized before any listener callback on first service admission.
    /// All paths are siblings of the already launched, signed service binary.
    private static let trustedExecutables: [String: TrustedExecutable] = {
        // launchd's BundleProgram may leave argv[0] relative to the app bundle;
        // proc_pidpath gives the kernel-resolved executable location.
        guard let servicePath = processPath(pid: getpid()) else { return [:] }
        let service = URL(fileURLWithPath: servicePath).resolvingSymlinksInPath()
        let directory = service.deletingLastPathComponent()
        let candidates = [
            ("com.liquidsky.0sky.bridge", directory.appendingPathComponent("0SkyBridge")),
            ("com.liquidsky.0sky.bridge.cli", directory.appendingPathComponent("0SkyBridgeCLI")),
        ]
        return Dictionary(uniqueKeysWithValues: candidates.compactMap { identifier, url in
            guard let data = try? Data(contentsOf: url, options: [.mappedIfSafe]) else { return nil }
            return (url.resolvingSymlinksInPath().path,
                    TrustedExecutable(identifier: identifier, digest: SHA256.hash(data: data)))
        })
    }()

    public static func authorize(
        connection: NSXPCConnection,
        allowedIdentifiers: Set<String>,
        requireSameTeamAsCurrentProcess _: Bool = true
    ) -> Bool {
        guard connection.effectiveUserIdentifier == geteuid() else {
            logger.error("Rejected XPC peer: effective user mismatch")
            return false
        }
        let pid = connection.processIdentifier
        guard let originalPath = processPath(pid: pid), kill(pid, 0) == 0 else {
            logger.error("Rejected XPC peer: process is unavailable")
            return false
        }
        let path = URL(fileURLWithPath: originalPath).resolvingSymlinksInPath().path
        guard let trusted = trustedExecutables[path],
              allowedIdentifiers.contains(trusted.identifier) else {
            logger.error("Rejected XPC peer: executable is outside the pinned client set")
            return false
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe]),
              SHA256.hash(data: data) == trusted.digest else {
            logger.error("Rejected XPC peer: executable digest changed")
            return false
        }
        guard processPath(pid: pid).map({
            URL(fileURLWithPath: $0).resolvingSymlinksInPath().path
        }) == path, kill(pid, 0) == 0 else {
            logger.error("Rejected XPC peer: process identity changed during validation")
            return false
        }
        return true
    }

    private static func processPath(pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(
            decoding: buffer.prefix(Int(length)).map { UInt8(bitPattern: $0) },
            as: UTF8.self
        )
    }
}
