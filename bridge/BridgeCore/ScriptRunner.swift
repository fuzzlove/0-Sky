import Foundation
import OSLog

private final class ProcessBox: @unchecked Sendable {
    let process: Process
    private let stdoutCollector: ProcessPipeCollector
    private let stderrCollector: ProcessPipeCollector
    private let stdoutHandle: FileHandle
    private let stderrHandle: FileHandle

    init(_ process: Process, stdoutCollector: ProcessPipeCollector,
         stderrCollector: ProcessPipeCollector, stdoutHandle: FileHandle,
         stderrHandle: FileHandle) {
        self.process = process
        self.stdoutCollector = stdoutCollector
        self.stderrCollector = stderrCollector
        self.stdoutHandle = stdoutHandle
        self.stderrHandle = stderrHandle
    }

    func cancelIO() {
        stdoutCollector.cancel(handle: stdoutHandle)
        stderrCollector.cancel(handle: stderrHandle)
    }
}

/// Drains a process pipe from Foundation's readability source rather than by
/// iterating `FileHandle.AsyncBytes`. A fleet health pass can have many pipes
/// open concurrently; byte iterators may occupy every Swift cooperative-pool
/// worker while waiting for output and consequently delay unrelated XPC
/// requests. The readability callback is driven by Dispatch and never blocks a
/// cooperative executor thread.
private final class ProcessPipeCollector: @unchecked Sendable {
    private let lock = NSLock()
    private let operationID: UUID
    private let stream: ScriptStream
    private let maximumBytes: Int
    private let onEvent: ScriptRunner.EventHandler
    private var collected = Data()
    private var lineBuffer = Data()
    private var truncated = false
    private var continuation: CheckedContinuation<String, Never>?
    private var finished = false

    init(operationID: UUID, stream: ScriptStream, maximumBytes: Int,
         onEvent: @escaping ScriptRunner.EventHandler) {
        self.operationID = operationID
        self.stream = stream
        self.maximumBytes = max(0, maximumBytes)
        self.onEvent = onEvent
    }

    func collect(from handle: FileHandle) async -> String {
        await withCheckedContinuation { continuation in
            lock.lock()
            self.continuation = continuation
            lock.unlock()
            handle.readabilityHandler = { [self] readable in
                let data = readable.availableData
                if data.isEmpty {
                    readable.readabilityHandler = nil
                    finish()
                } else {
                    consume(data)
                }
            }
        }
    }

    private func consume(_ data: Data) {
        var lines: [String] = []
        lock.lock()
        if collected.count < maximumBytes {
            let available = maximumBytes - collected.count
            collected.append(data.prefix(available))
            if data.count > available { truncated = true }
        } else if !data.isEmpty {
            truncated = true
        }
        for byte in data {
            if byte == 0x0A {
                lines.append(String(decoding: lineBuffer, as: UTF8.self))
                lineBuffer.removeAll(keepingCapacity: true)
            } else if lineBuffer.count < 65_536 {
                lineBuffer.append(byte)
            }
        }
        lock.unlock()
        for line in lines { emit(line) }
    }

    private func finish() {
        var partial: String?
        var result = ""
        var pending: CheckedContinuation<String, Never>?
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        if !lineBuffer.isEmpty { partial = String(decoding: lineBuffer, as: UTF8.self) }
        result = String(decoding: collected, as: UTF8.self)
        if truncated { result += "\n<output-truncated>\n" }
        pending = continuation
        continuation = nil
        lock.unlock()
        if let partial { emit(partial) }
        pending?.resume(returning: result)
    }

    func cancel(handle: FileHandle) {
        handle.readabilityHandler = nil
        try? handle.close()
        finish()
    }

    private func emit(_ line: String) {
        onEvent(ScriptOutputEvent(
            operationID: operationID, stream: stream,
            line: DiagnosticRedactor.redact(line), timestamp: Date()
        ))
    }
}

public actor ScriptRunner {
    public typealias EventHandler = @Sendable (ScriptOutputEvent) -> Void

    private let approvedExecutableRoots: [URL]
    private let approvedWorkingRoots: [URL]
    private let events: EventBus?
    private let sessions: ResearchSessionRecorder?
    private let ownedProcesses: OwnedProcessRegistry?
    private var active: [UUID: ProcessBox] = [:]
    private var cancelled: Set<UUID> = []
    private let logger = Logger(subsystem: "com.liquidsky.0sky.bridge", category: "script")

    public init(
        approvedExecutableRoots: [URL] = ScriptRunner.defaultExecutableRoots,
        approvedWorkingRoots: [URL] = ScriptRunner.defaultWorkingRoots,
        events: EventBus? = nil,
        sessions: ResearchSessionRecorder? = nil,
        ownedProcesses: OwnedProcessRegistry? = nil
    ) {
        self.approvedExecutableRoots = approvedExecutableRoots
        self.approvedWorkingRoots = approvedWorkingRoots
        self.events = events
        self.sessions = sessions
        self.ownedProcesses = ownedProcesses
    }

    public static var defaultExecutableRoots: [URL] {
        [
            URL(fileURLWithPath: "/usr/bin"),
            URL(fileURLWithPath: "/bin"),
            URL(fileURLWithPath: "/usr/sbin"),
            URL(fileURLWithPath: "/opt/homebrew/bin"),
            // Homebrew entry points (including venv interpreters) resolve
            // through /opt/homebrew/bin into versioned Cellar directories.
            // Canonical-path validation must approve that immutable tool root
            // or every pinned 0-Sky virtual environment is rejected solely
            // because it is a symlink.
            URL(fileURLWithPath: "/opt/homebrew/Cellar"),
            URL(fileURLWithPath: "/Applications/Xcode.app/Contents/Developer/usr/bin"),
            FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/0-Sky"),
        ]
    }

    public static var defaultWorkingRoots: [URL] {
        [
            FileManager.default.homeDirectoryForCurrentUser,
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath),
            URL(fileURLWithPath: NSTemporaryDirectory()),
        ]
    }

    public func preflight(_ specification: ScriptSpecification) throws {
        guard !specification.requiresPrivilege else {
            throw BridgeCoreError.unauthorized(
                "privileged scripts must use the typed helper client"
            )
        }
        let executable = try BridgeValidation.canonicalPath(
            specification.executableURL.path,
            allowedRoots: approvedExecutableRoots
        )
        try BridgeValidation.executableIsSafe(executable)
        if let directory = specification.workingDirectory {
            _ = try BridgeValidation.canonicalPath(
                directory.path, allowedRoots: approvedWorkingRoots
            )
        }
        for argument in specification.arguments where argument.contains("\0") {
            throw BridgeCoreError.invalidPath("NUL in argument")
        }
        _ = try BridgeValidation.safeEnvironment(overrides: specification.environment)
    }

    public func run(
        _ specification: ScriptSpecification,
        operationID: UUID = UUID(),
        onEvent: @escaping EventHandler = { _ in }
    ) async throws -> BridgeOperationResult {
        try preflight(specification)
        let started = Date()
        return try await withTaskCancellationHandler {
            try await withThrowingTaskGroup(of: BridgeOperationResult.self) { group in
                group.addTask {
                    try await self.execute(
                        specification,
                        operationID: operationID,
                        started: started,
                        onEvent: onEvent
                    )
                }
                group.addTask {
                    try await Task.sleep(for: specification.timeout)
                    await self.cancel(operationID)
                    throw BridgeCoreError.timeout(specification.identifier)
                }
                guard let result = try await group.next() else {
                    throw BridgeCoreError.operationFailed("operation produced no result")
                }
                group.cancelAll()
                return result
            }
        } onCancel: {
            Task { await self.cancel(operationID) }
        }
    }

    private func execute(
        _ specification: ScriptSpecification,
        operationID: UUID,
        started: Date,
        onEvent: @escaping EventHandler
    ) async throws -> BridgeOperationResult {
        let process = Process()
        process.executableURL = specification.executableURL
        process.arguments = specification.arguments
        process.environment = try BridgeValidation.safeEnvironment(
            overrides: specification.environment
        )
        process.currentDirectoryURL = specification.workingDirectory
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        let stdoutCollector = ProcessPipeCollector(
            operationID: operationID, stream: .stdout,
            maximumBytes: specification.maximumOutputBytes, onEvent: onEvent
        )
        let stderrCollector = ProcessPipeCollector(
            operationID: operationID, stream: .stderr,
            maximumBytes: specification.maximumOutputBytes, onEvent: onEvent
        )
        let box = ProcessBox(
            process, stdoutCollector: stdoutCollector,
            stderrCollector: stderrCollector,
            stdoutHandle: stdoutPipe.fileHandleForReading,
            stderrHandle: stderrPipe.fileHandleForReading
        )
        active[operationID] = box
        logger.info("Starting approved operation \(specification.identifier, privacy: .public)")

        do {
            try process.run()
            await ownedProcesses?.register(OwnedProcess(
                pid: process.processIdentifier, processType: "managed-command", deviceID: nil,
                startedAt: started, commandIdentifier: specification.identifier, ownership: "0-Sky"
            ))
        } catch {
            active.removeValue(forKey: operationID)
            throw BridgeCoreError.operationFailed(
                "Could not launch \(specification.identifier): \(error.localizedDescription)"
            )
        }

        async let stdout = stdoutCollector.collect(from: stdoutPipe.fileHandleForReading)
        async let stderr = stderrCollector.collect(from: stderrPipe.fileHandleForReading)

        let status = await Self.wait(for: box)
        let output = await stdout
        let errors = await stderr
        active.removeValue(forKey: operationID)
        await ownedProcesses?.remove(pid: process.processIdentifier)
        let wasCancelled = Task.isCancelled || cancelled.remove(operationID) != nil
        logger.info(
            "Finished approved operation \(specification.identifier, privacy: .public) status=\(status)"
        )
        let result = BridgeOperationResult(
            identifier: specification.identifier,
            startedAt: started,
            finishedAt: Date(),
            exitCode: status,
            stdout: DiagnosticRedactor.redact(output),
            stderr: DiagnosticRedactor.redact(errors),
            cancelled: wasCancelled
        )
        if let sessions {
            try? await sessions.record(command: CommandRecord(
                component: specification.identifier.split(separator: ".").first.map(String.init) ?? "command",
                commandIdentifier: specification.identifier,
                redactedArguments: ResearchSessionRecorder.redactArguments(specification.arguments),
                exitCode: status, durationMS: Int(Date().timeIntervalSince(started) * 1000)
            ))
        }
        if let events {
            await events.publish(BridgeEvent(
                event: .commandCompleted,
                severity: result.succeeded ? .info : .warning,
                component: specification.identifier, message: "Managed command completed.",
                observed: ["exit_code": .number(Double(status)),
                           "duration_ms": .number(result.duration * 1000)]
            ))
        }
        return result
    }

    public func cancel(_ operationID: UUID) {
        guard let box = active[operationID] else { return }
        cancelled.insert(operationID)
        if box.process.isRunning {
            box.process.terminate()
            let process = box.process
            Task.detached {
                try? await Task.sleep(for: .seconds(2))
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            }
        }
        // A descendant can inherit a pipe and keep it open after its parent is
        // terminated. Resolve both collectors explicitly so cancellation can
        // never leave the Bridge UI waiting indefinitely for EOF.
        box.cancelIO()
    }

    public func cancelAll() {
        for id in active.keys { cancel(id) }
    }

    private static func wait(for box: ProcessBox) async -> Int32 {
        await withCheckedContinuation { continuation in
            box.process.terminationHandler = { process in
                continuation.resume(returning: process.terminationStatus)
            }
        }
    }

}
