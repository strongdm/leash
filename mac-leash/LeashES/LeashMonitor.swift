import Foundation
import EndpointSecurity
import os.log
import Darwin

struct TrackedLeashProcess {
    let pid: pid_t
    let executablePath: String
    let arguments: [String]
    let ttyPath: String?
    let signingIdentifier: String?
    let teamIdentifier: String?
    let currentWorkingDirectory: String?
    let leashPID: pid_t?
    let leashArguments: [String]?
    let leashTTYPath: String?
    let leashExecutablePath: String?
}

enum LeashMonitorError: Error {
    case clientCreationFailed(es_new_client_result_t)
    case missingFullDiskAccess(String)
    case cacheClearFailed
    case subscriptionFailed(es_return_t)
}

final class LeashMonitor {
    var client: OpaquePointer?
    let callbackQueue = DispatchQueue(label: LeashIdentifiers.namespaced("es.callback"), qos: .userInitiated)
    let log = OSLog(subsystem: LeashIdentifiers.bundle, category: "monitor")

    var trackedLeashProcesses: [pid_t: TrackedLeashProcess] = [:]
    var authEventsEnabled = false

    let terminalExecutableHints: [String] = [
        "Terminal",
        "iTerm2",
        "WezTerm",
        "Alacritty",
        "Kitty",
        "Hyper"
    ]

    let leashExecutableNames: Set<String> = ["leash", "leashcli"]
    let leashSigningIdentifier = LeashIdentifiers.cli
    let leashTeamIdentifier = LeashIdentifiers.teamIdentifier
    let embeddedLeashExecutableSuffix = "/Leash.app/Contents/Resources/leashcli"

    weak var commService: LeashCommunicationService?
    let pidSyncQueue = DispatchQueue(label: LeashIdentifiers.namespaced("pid-sync"), qos: .utility)

    init(commService: LeashCommunicationService) {
        self.commService = commService
    }

    func syncTrackedPIDsToNetwork() {
        os_log("Syncing %{public}d PIDs to network extension...",
               log: log, type: .default, trackedLeashProcesses.count)

        pidSyncQueue.async { [weak self] in
            guard let self, let commService = self.commService else {
                os_log("Cannot sync PIDs: commService unavailable", log: self?.log ?? OSLog.disabled, type: .error)
                return
            }

            let entries: [DaemonSync.PIDEntry] = self.trackedLeashProcesses.map { pid, tracked in
                DaemonSync.PIDEntry(
                    pid: Int32(pid),
                    leashPID: Int32(tracked.leashPID ?? pid),
                    executable: tracked.executablePath,
                    ttyPath: tracked.ttyPath,
                    cwd: tracked.currentWorkingDirectory,
                    description: nil
                )
            }

            commService.pushTrackedPIDs(entries)
        }
    }

    func start() throws {
        guard client == nil else { return }

        var newClient: OpaquePointer?
        let result = es_new_client(&newClient) { [weak self] _, message in
            guard let self else { return }
            let mutableMessage = UnsafeMutablePointer(mutating: message)
            es_retain_message(mutableMessage)
            self.callbackQueue.async {
                self.handle(mutableMessage)
            }
        }

        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            guard let establishedClient = newClient else {
                throw LeashMonitorError.clientCreationFailed(result)
            }
            client = establishedClient
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            let reason = "LeashES requires Full Disk Access to observe Endpoint Security events."
            notifyFullDiskAccessMissing(reason: reason)
            throw LeashMonitorError.missingFullDiskAccess(reason)
        default:
            throw LeashMonitorError.clientCreationFailed(result)
        }

        guard let establishedClient = client else {
            throw LeashMonitorError.clientCreationFailed(result)
        }

        if es_clear_cache(establishedClient) != ES_CLEAR_CACHE_RESULT_SUCCESS {
            os_log("Failed to clear EndpointSecurity cache", log: log, type: .error)
            throw LeashMonitorError.cacheClearFailed
        }

        var events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT
        ]
        let subscribeResult = es_subscribe(establishedClient, &events, UInt32(events.count))
        guard subscribeResult == ES_RETURN_SUCCESS else {
            throw LeashMonitorError.subscriptionFailed(subscribeResult)
        }

        authEventsEnabled = false
        os_log("Leash ES monitor started (passive mode, will enable AUTH when leash detected)", log: log, type: .default)
    }

    func stop() {
        guard let client else { return }

        if authEventsEnabled {
            disableAuthEvents()
        }

        var events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT
        ]
        if es_unsubscribe(client, &events, UInt32(events.count)) != ES_RETURN_SUCCESS {
            os_log("Failed to unsubscribe from EndpointSecurity events", log: log, type: .error)
        }
        if es_delete_client(client) != ES_RETURN_SUCCESS {
            os_log("Failed to delete EndpointSecurity client", log: log, type: .fault)
        }
        self.client = nil
        trackedLeashProcesses.removeAll()
    }

    func enforceDeniedProcesses(rules: [LeashPolicyRule]) {
        guard !rules.isEmpty else { return }

        callbackQueue.async { [weak self] in
            guard let self else { return }

            let denyExecRules = rules.filter { $0.action == .deny && $0.kind == .processExec }
            guard !denyExecRules.isEmpty else { return }

            var terminated: [pid_t] = []

            for (pid, tracked) in self.trackedLeashProcesses {
                let event = LeashPolicyEvent(
                    id: UUID(),
                    timestamp: Date(),
                    kind: .processExec,
                    processPath: tracked.executablePath,
                    processArguments: tracked.arguments,
                    currentWorkingDirectory: tracked.currentWorkingDirectory,
                    filePath: nil,
                    fileOperation: nil,
                    parentProcessPath: tracked.leashExecutablePath,
                    ttyPath: tracked.ttyPath,
                    leashProcessPath: tracked.leashExecutablePath,
                    leashPid: tracked.leashPID,
                    leashArguments: tracked.leashArguments,
                    leashTTYPath: tracked.leashTTYPath,
                    pid: pid,
                    parentPid: tracked.leashPID ?? 0
                )

                if denyExecRules.contains(where: { $0.matches(event) }) {
                    if kill(pid, SIGKILL) == 0 {
                        terminated.append(pid)
                        os_log("Enforced deny rule, terminated pid=%{public}d (%{public}@)", log: self.log, type: .info, pid, tracked.executablePath)
                    } else {
                        let errorCode = errno
                        let message = String(cString: strerror(errorCode))
                        os_log("Failed to terminate pid=%{public}d (%{public}@): %{public}@", log: self.log, type: .error, pid, tracked.executablePath, message)
                    }
                }
            }

            if !terminated.isEmpty {
                for pid in terminated {
                    self.trackedLeashProcesses.removeValue(forKey: pid)
                }
                self.syncTrackedPIDsToNetwork()
            }
        }
    }
}
