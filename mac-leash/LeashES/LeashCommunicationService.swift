import Foundation
import os.log

final class LeashCommunicationService: NSObject {
    let log = OSLog(subsystem: LeashIdentifiers.bundle, category: "communication")
    let daemon = DaemonSync.shared
    let queue = DispatchQueue(label: LeashIdentifiers.namespaced("communication"))
    var eventCache: [UUID: LeashPolicyEvent] = [:]
    var eventOrder: [UUID] = []
    let cacheLimit = 200
    weak var monitor: LeashMonitor?

    var cachedRules: [LeashPolicyRule] = []
    let rulesQueue = DispatchQueue(label: LeashIdentifiers.namespaced("rules-cache"))

    override init() {
        super.init()

        daemon.subscribe(to: "mac.policy.decision") { [weak self] payload in
            self?.handlePolicyDecisionNotification(payload)
        }

        // Subscribe to rule management messages
        daemon.subscribe(to: "mac.rule.add") { [weak self] payload in
            self?.handleRuleAddNotification(payload)
        }

        daemon.subscribe(to: "mac.rule.remove") { [weak self] payload in
            self?.handleRuleRemoveNotification(payload)
        }

        daemon.subscribe(to: "mac.rule.clear") { [weak self] _ in
            self?.handleClearRulesNotification()
        }

        daemon.subscribe(to: "mac.rule.snapshot") { [weak self] payload in
            self?.handleRuleSnapshotNotification(payload)
        }
    }

    func start() {
        os_log("Communication service started (using WebSocket)", log: self.log, type: .info)
        bootstrapState()
    }

    func checkCachedPolicy(_ event: LeashPolicyEvent) -> LeashPolicyDecision.Action? {
        var matchingAction: LeashPolicyDecision.Action?
        rulesQueue.sync {
            for rule in cachedRules {
                if rule.matches(event) {
                    matchingAction = rule.action
                    break
                }
            }
        }

        if let action = matchingAction {
            os_log("Policy match found: %{public}@ → %{public}@",
                   log: log, type: .debug,
                   event.processPath,
                   action == .allow ? "ALLOW" : "DENY")
        }

        return matchingAction
    }

    func logEvent(_ event: LeashPolicyEvent, decision: LeashPolicyDecision.Action) {
        queue.async { [weak self] in
            guard let self else { return }

            self.cacheEvent(event)

            // Send policy event to daemon
            self.daemon.sendPolicyEvent(event) { error in
                if let error {
                    os_log("Failed to send policy event: %{public}@", log: self.log, type: .error, String(describing: error))
                }
            }

            // Also send telemetry event
            var details: [String: String] = [
                "process_path": event.processPath,
                "pid": String(event.pid),
                "kind": event.kind.rawValue,
                "decision": decision == .allow ? "allowed" : "denied"
            ]

            if !event.processArguments.isEmpty {
                details["args"] = event.processArguments.joined(separator: " ")
                details["argc"] = String(event.processArguments.count)
            }
            if let cwd = event.currentWorkingDirectory {
                details["cwd"] = cwd
            }
            if let filePath = event.filePath {
                details["file_path"] = filePath
            }
            if let tty = event.ttyPath {
                details["tty_path"] = tty
            }
            if let leashPid = event.leashPid {
                details["leash_pid"] = String(leashPid)
            }
            if let leashPath = event.leashProcessPath {
                details["leash_process"] = leashPath
            }
            if let parent = event.parentProcessPath {
                details["parent_process"] = parent
            }
            if let leashArgs = event.leashArguments, !leashArgs.isEmpty {
                details["leash_args"] = leashArgs.joined(separator: " ")
            }
            if let leashTTY = event.leashTTYPath {
                details["leash_tty"] = leashTTY
            }
            let eventName: String
            switch event.kind {
            case .processExec:
                eventName = "proc.exec"
            case .fileAccess:
                let fileOperation = event.fileOperation ?? .open
                details["operation"] = fileOperation.rawValue
                switch fileOperation {
                case .create, .write:
                    eventName = "file.open:rw"
                case .open:
                    eventName = "file.open"
                }
            }

            let severity = decision == .allow ? "info" : "warning"
            if decision == .deny {
                details["action"] = "deny"
            } else {
                details["action"] = "allow"
            }

            self.daemon.sendEvent(
                name: eventName,
                details: details,
                severity: severity,
                source: "leash.es",
                ruleID: nil
            )

            os_log("Logged event [leash=%{public}d]: %{public}@ (%{public}@)", log: self.log, type: .default, event.leashPid ?? -1, event.processPath, decision == .allow ? "ALLOW" : "DENY")
        }
    }

    func pushTrackedPIDs(_ entries: [DaemonSync.PIDEntry]) {
        daemon.sendTrackedPIDs(entries)
        os_log("Synced %{public}d tracked PIDs", log: self.log, type: .info, entries.count)
    }

    private func bootstrapState() {
        os_log("Bootstrapping state with daemon", log: log, type: .info)

        // Query initial rules from daemon
        daemon.queryRules { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let rules):
                self.rulesQueue.async {
                    self.cachedRules = rules.sorted(by: Self.ruleSortComparator)
                    os_log("Loaded %d rules from daemon", log: self.log, type: .info, rules.count)
                }
            case .failure(let error):
                os_log("Failed to load rules from daemon: %{public}@", log: self.log, type: .error, String(describing: error))
            }
        }
    }
}
