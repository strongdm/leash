import Foundation
import EndpointSecurity
import os.log
import Darwin

extension LeashMonitor {
    func handle(_ message: UnsafeMutablePointer<es_message_t>) {
        defer { es_release_message(message) }

        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            processNotifyExecMessage(message)
        case ES_EVENT_TYPE_AUTH_EXEC:
            processAuthExecMessage(message)
        case ES_EVENT_TYPE_AUTH_OPEN:
            processAuthOpenMessage(message)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            processExitMessage(message)
        default:
            break
        }
    }

    func processNotifyExecMessage(_ message: UnsafeMutablePointer<es_message_t>) {
        let execEvent = message.pointee.event.exec
        let targetProcess = execEvent.target.pointee

        guard let executablePath = string(from: targetProcess.executable.pointee.path), !executablePath.isEmpty else { return }

        let pid = audit_token_to_pid(targetProcess.audit_token)
        let isLeash = isLeashExecutable(targetProcess, executablePath: executablePath)

        if isLeash && originatesFromInteractiveTerminal(targetProcess) {
            let arguments = extractArguments(from: message)
            let ttyPath = ttyPath(for: targetProcess)
            let cwd = Optional(execEvent.cwd).flatMap { string(from: $0.pointee.path) }
            let signingIdentifier = string(from: targetProcess.signing_id)
            let teamIdentifier = string(from: targetProcess.team_id)

            trackedLeashProcesses[pid] = TrackedLeashProcess(
                pid: pid,
                executablePath: executablePath,
                arguments: arguments,
                ttyPath: ttyPath,
                signingIdentifier: signingIdentifier,
                teamIdentifier: teamIdentifier,
                currentWorkingDirectory: cwd,
                leashPID: pid,
                leashArguments: arguments,
                leashTTYPath: ttyPath,
                leashExecutablePath: executablePath
            )

            os_log("Leash CLI started: pid=%{public}d cwd=%{public}@", log: log, type: .default, pid, cwd ?? "unknown")

            if !authEventsEnabled {
                enableAuthEvents()
            }

            // Sync PIDs to network extension
            syncTrackedPIDsToNetwork()
            return
        }

        if let leashInfo = leashInfo(for: targetProcess) {
            os_log("NOTIFY_EXEC: leash child pid=%{public}d path=%{public}@ leashPID=%{public}d", log: log, type: .debug, pid, executablePath, leashInfo.leashPID ?? -1)

            if trackedLeashProcesses[pid] == nil {
                if let (tracked, event) = buildExecContext(message: message, process: targetProcess, leashInfo: leashInfo) {
                    trackedLeashProcesses[pid] = tracked
                    syncTrackedPIDsToNetwork()

                    let decision = checkPolicyOrAllowDefault(for: event)
                    os_log("Fallback tracked exec pid=%{public}d (%{public}@) decision=%{public}@", log: log, type: .debug, pid, event.processPath, decision.action.rawValue.uppercased())
                    logEventAsync(event, decision: decision.action)
                }
            }
        }
    }

    func processAuthExecMessage(_ message: UnsafeMutablePointer<es_message_t>) {
        let targetProcess = message.pointee.event.exec.target.pointee

        guard let leashInfo = leashInfo(for: targetProcess) else {
            respondAuth(message, action: .allow, cache: false)
            return
        }

        guard let (trackedProcess, event) = buildExecContext(message: message, process: targetProcess, leashInfo: leashInfo) else {
            respondAuth(message, action: .allow, cache: false)
            return
        }

        trackedLeashProcesses[trackedProcess.pid] = trackedProcess

        let decision = checkPolicyOrAllowDefault(for: event)

        os_log("AUTH_EXEC[leash=%{public}d]: %{public}@ (pid=%d) → %{public}@",
               log: log, type: .default,
               leashInfo.leashPID ?? -1,
               event.processPath, event.pid,
               decision.action == .allow ? "ALLOW" : "DENY")

        logEventAsync(event, decision: decision.action)

        syncTrackedPIDsToNetwork()

        respondAuth(message, action: decision.action, cache: false)
    }

    func processAuthOpenMessage(_ message: UnsafeMutablePointer<es_message_t>) {
        let process = message.pointee.process.pointee
        let pid = audit_token_to_pid(process.audit_token)

        let fileEvent = message.pointee.event.open
        let requestedFlags = fileEvent.fflag

        guard let leashInfo = leashInfo(for: process) ?? trackedLeashProcesses[pid] else {
            respondOpen(message, action: .allow, requestedFlags: requestedFlags, cache: false)
            return
        }

        var filePath = resolvePath(for: fileEvent.file)

        let operation: LeashPolicyEvent.FileOperation
        let flags = requestedFlags
        let writeRequested = (flags & FWRITE) != 0
        let createRequested = (flags & O_CREAT) != 0

        if createRequested {
            operation = .create
        } else if writeRequested {
            operation = .write
        } else {
            operation = .open
        }

        if (filePath == nil || filePath?.isEmpty == true) && (createRequested || writeRequested) {
            if let args = trackedLeashProcesses[pid]?.arguments {
                if let candidate = args.dropFirst().first(where: { !$0.isEmpty && !$0.hasPrefix("-") }) {
                    if candidate.hasPrefix("/") {
                        filePath = candidate
                    } else if let cwd = trackedLeashProcesses[pid]?.currentWorkingDirectory {
                        let resolved = URL(fileURLWithPath: candidate, relativeTo: URL(fileURLWithPath: cwd))
                        filePath = resolved.standardized.path
                    } else {
                        filePath = candidate
                    }
                }
            }
        }

        guard var concretePath = filePath?.trimmingCharacters(in: .whitespacesAndNewlines), !concretePath.isEmpty else {
            respondOpen(message, action: .allow, requestedFlags: requestedFlags, cache: false)
            return
        }

        let cwd = trackedLeashProcesses[pid]?.currentWorkingDirectory

        if !concretePath.hasPrefix("/") {
            if let cwd {
                let base = URL(fileURLWithPath: cwd, isDirectory: true)
                concretePath = URL(fileURLWithPath: concretePath, relativeTo: base).standardizedFileURL.path
            } else {
                concretePath = URL(fileURLWithPath: concretePath).standardizedFileURL.path
            }
        } else {
            concretePath = URL(fileURLWithPath: concretePath).standardizedFileURL.path
        }

        let executablePath = trackedLeashProcesses[pid]?.executablePath ?? processPath(pid: pid) ?? ""
        let arguments = trackedLeashProcesses[pid]?.arguments ?? []
        let tty = trackedLeashProcesses[pid]?.ttyPath

        let event = LeashPolicyEvent(
            id: UUID(),
            timestamp: Date(),
            kind: .fileAccess,
            processPath: executablePath,
            processArguments: arguments,
            currentWorkingDirectory: cwd,
            filePath: concretePath,
            fileOperation: operation,
            parentProcessPath: leashInfo.executablePath,
            ttyPath: tty,
            leashProcessPath: leashInfo.executablePath,
            leashPid: leashInfo.leashPID,
            leashArguments: leashInfo.arguments,
            leashTTYPath: leashInfo.ttyPath,
            pid: pid,
            parentPid: process.ppid
        )

        let decision = checkPolicyOrAllowDefault(for: event)

        os_log("AUTH_OPEN[leash=%{public}d]: %{public}@ → %{public}@ (%{public}@) → %{public}@",
               log: log, type: .default,
               leashInfo.leashPID ?? -1,
               executablePath, filePath ?? "", operation.rawValue,
               decision.action == .allow ? "ALLOW" : "DENY")

        logEventAsync(event, decision: decision.action)

        respondOpen(message, action: decision.action, requestedFlags: requestedFlags, cache: false)
    }

    func processExitMessage(_ message: UnsafeMutablePointer<es_message_t>) {
        let process = message.pointee.process.pointee
        let pid = audit_token_to_pid(process.audit_token)

        if let removed = trackedLeashProcesses.removeValue(forKey: pid) {
            os_log("Leash-tracked process exiting: pid=%{public}d", log: log, type: .default, pid)

            // If the leash CLI exited, drop any child state that still references it
            if removed.leashPID == removed.pid {
                let childKeys = trackedLeashProcesses.filter { $0.value.leashPID == removed.pid }.map { $0.key }
                childKeys.forEach { trackedLeashProcesses.removeValue(forKey: $0) }
            }

            syncTrackedPIDsToNetwork()

            if authEventsEnabled && trackedLeashProcesses.isEmpty {
                disableAuthEvents()
            }
        }
    }

    func respondAuth(_ message: UnsafeMutablePointer<es_message_t>,
                             action: LeashPolicyDecision.Action,
                             cache: Bool) {
        guard let client else { return }
        let result: es_auth_result_t = action == .allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
        let response = es_respond_auth_result(client, message, result, cache)
        if response != ES_RESPOND_RESULT_SUCCESS {
            os_log("es_respond_auth_result failed: result=%{public}d eventType=%{public}d",
                   log: log, type: .error,
                   response.rawValue,
                   message.pointee.event_type.rawValue)
        }
    }

    func respondOpen(_ message: UnsafeMutablePointer<es_message_t>,
                             action: LeashPolicyDecision.Action,
                             requestedFlags: Int32,
                             cache: Bool) {
        guard let client else { return }
        let flags: UInt32 = action == .allow ? UInt32.max : 0
        let response = es_respond_flags_result(client, message, flags, cache)
        if response != ES_RESPOND_RESULT_SUCCESS {
            os_log("es_respond_flags_result failed: result=%{public}d eventType=%{public}d",
                   log: log, type: .error,
                   response.rawValue,
                   message.pointee.event_type.rawValue)
        }
    }

    func enableAuthEvents() {
        guard let client, !authEventsEnabled else { return }

        var events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN
        ]
        let result = es_subscribe(client, &events, UInt32(events.count))
        if result == ES_RETURN_SUCCESS {
            authEventsEnabled = true
            os_log("Subscribed to AUTH events", log: log, type: .default)
        } else {
            os_log("Failed to subscribe to AUTH events: %{public}d", log: log, type: .error, result.rawValue)
        }
    }

    func disableAuthEvents() {
        guard let client, authEventsEnabled else { return }

        var events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN
        ]
        if es_unsubscribe(client, &events, UInt32(events.count)) == ES_RETURN_SUCCESS {
            authEventsEnabled = false
            os_log("Unsubscribed from AUTH events", log: log, type: .default)
        } else {
            os_log("Failed to unsubscribe from AUTH events", log: log, type: .error)
        }
    }

    func checkPolicyOrAllowDefault(for event: LeashPolicyEvent) -> LeashPolicyDecision {
        guard let commService else {
            return LeashPolicyDecision(eventID: event.id, action: .allow, scope: .once)
        }

        if let action = commService.checkCachedPolicy(event) {
            return LeashPolicyDecision(eventID: event.id, action: action, scope: .once)
        }

        return LeashPolicyDecision(eventID: event.id, action: .allow, scope: .once)
    }

    func logEventAsync(_ event: LeashPolicyEvent, decision: LeashPolicyDecision.Action) {
        guard let commService else { return }

        DispatchQueue.global(qos: .utility).async {
            commService.logEvent(event, decision: decision)
        }
    }

    func resolvePath(for filePointer: UnsafeMutablePointer<es_file_t>?) -> String? {
        guard let filePointer else { return nil }
        if let existing = string(from: filePointer.pointee.path), !existing.isEmpty {
            return existing
        }
        return nil
    }

    func leashInfo(for process: es_process_t) -> TrackedLeashProcess? {
        if let direct = trackedLeashProcesses[process.ppid] {
            return direct
        }

        let originalParent = process.original_ppid
        if originalParent > 0, let tracked = trackedLeashProcesses[originalParent] {
            return tracked
        }

        return nil
    }

    func isLeashExecutable(_ process: es_process_t, executablePath path: String) -> Bool {
        if matchesEmbeddedLeashExecutable(path: path) {
            return true
        }

        if let signingID = string(from: process.signing_id), !signingID.isEmpty {
            guard signingID == leashSigningIdentifier else {
                return false
            }
            if let teamID = string(from: process.team_id), !teamID.isEmpty {
                return teamID == leashTeamIdentifier
            }
            return true
        }

        guard let lastComponent = path.split(separator: "/").last else { return false }
        return leashExecutableNames.contains(String(lastComponent))
    }

    func matchesEmbeddedLeashExecutable(path: String) -> Bool {
        let normalizedPath = (path as NSString).standardizingPath
        if normalizedPath == embeddedLeashExecutableSuffix {
            return true
        }
        return normalizedPath.hasSuffix(embeddedLeashExecutableSuffix)
    }

    func respondsToAllowedTerminal(_ parentPath: String) -> Bool {
        let name = parentPath.split(separator: "/").last.map(String.init) ?? parentPath
        return terminalExecutableHints.contains(where: { hint in
            name.caseInsensitiveCompare(hint) == .orderedSame || parentPath.localizedCaseInsensitiveContains("/\(hint).app/")
        })
    }

    func originatesFromInteractiveTerminal(_ process: es_process_t) -> Bool {
        if let ttyPointer = process.tty?.pointee.path, let tty = string(from: ttyPointer) {
            if tty.contains("/dev/ttys") || tty.contains("/dev/pts") || tty.contains("/dev/tty.") {
                return true
            }
        }

        if process.ppid > 1, let parentPath = processPath(pid: process.ppid), respondsToAllowedTerminal(parentPath) {
            return true
        }

        return false
    }

    func extractArguments(from message: UnsafeMutablePointer<es_message_t>) -> [String] {
        var execCopy = message.pointee.event.exec
        return withUnsafePointer(to: &execCopy) { pointer -> [String] in
            let count = Int(es_exec_arg_count(pointer))
            guard count > 0 else { return [] }
            var arguments: [String] = []
            arguments.reserveCapacity(count)
            for index in 0..<count {
                let argumentToken = es_exec_arg(pointer, UInt32(index))
                if let argument = string(from: argumentToken) {
                    arguments.append(argument)
                }
            }
            return arguments
        }
    }

    func ttyPath(for process: es_process_t) -> String? {
        guard let ttyPointer = process.tty?.pointee.path else { return nil }
        return string(from: ttyPointer)
    }

    func processPath(pid: pid_t) -> String? {
        guard pid > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        let result = buffer.withUnsafeMutableBufferPointer { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return -1 }
            return proc_pidpath(pid, base, UInt32(ptr.count))
        }
        guard result > 0 else { return nil }
        return String(cString: buffer)
    }

    func buildExecContext(message: UnsafeMutablePointer<es_message_t>,
                                  process: es_process_t,
                                  leashInfo: TrackedLeashProcess) -> (TrackedLeashProcess, LeashPolicyEvent)? {
        guard let executablePath = string(from: process.executable.pointee.path), !executablePath.isEmpty else {
            return nil
        }

        let pid = audit_token_to_pid(process.audit_token)
        let arguments = extractArguments(from: message)
        let execEvent = message.pointee.event.exec
        let cwd = Optional(execEvent.cwd).flatMap { string(from: $0.pointee.path) } ?? leashInfo.currentWorkingDirectory
        let tty = ttyPath(for: process)

        let trackedProcess = TrackedLeashProcess(
            pid: pid,
            executablePath: executablePath,
            arguments: arguments,
            ttyPath: tty,
            signingIdentifier: string(from: process.signing_id),
            teamIdentifier: string(from: process.team_id),
            currentWorkingDirectory: cwd,
            leashPID: leashInfo.leashPID,
            leashArguments: leashInfo.arguments,
            leashTTYPath: leashInfo.ttyPath,
            leashExecutablePath: leashInfo.executablePath
        )

        let event = LeashPolicyEvent(
            id: UUID(),
            timestamp: Date(),
            kind: .processExec,
            processPath: executablePath,
            processArguments: arguments,
            currentWorkingDirectory: cwd,
            filePath: nil,
            fileOperation: nil,
            parentProcessPath: leashInfo.executablePath,
            ttyPath: tty,
            leashProcessPath: leashInfo.executablePath,
            leashPid: leashInfo.leashPID,
            leashArguments: leashInfo.arguments,
            leashTTYPath: leashInfo.ttyPath,
            pid: pid,
            parentPid: process.ppid
        )

        return (trackedProcess, event)
    }

    func string(from token: es_string_token_t?) -> String? {
        guard let token else { return nil }
        return string(from: token)
    }

    func string(from token: es_string_token_t) -> String? {
        guard token.length > 0, let dataPtr = token.data else { return nil }
        let data = Data(bytes: UnsafeRawPointer(dataPtr), count: Int(token.length))
        return String(data: data, encoding: .utf8)
    }

    func notifyFullDiskAccessMissing(reason: String) {
        let userInfo: [String: String] = ["message": reason]
        let notification = LeashNotifications.fullDiskAccessMissing
        DistributedNotificationCenter.default().post(name: notification,
                                                     object: nil,
                                                     userInfo: userInfo)

        DaemonSync.shared.sendEvent(
            name: "es.full_disk_access.missing",
            details: ["reason": reason],
            severity: "warning",
            source: "leash.es"
        )
    }
}

extension es_process_t {
    var pid: pid_t {
        audit_token_to_pid(self.audit_token)
    }
}
