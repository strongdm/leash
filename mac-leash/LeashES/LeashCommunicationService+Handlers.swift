import Foundation
import os.log

extension LeashCommunicationService {
    // MARK: - Message Handlers

    func handlePolicyDecisionNotification(_ payload: [String: Any]) {
        queue.async { [weak self] in
            guard let self else { return }

            guard let eventIDString = payload["event_id"] as? String,
                  let eventID = UUID(uuidString: eventIDString),
                  let actionString = payload["action"] as? String,
                  let action = LeashPolicyDecision.Action(rawValue: actionString),
                  let scopeDict = payload["scope"] as? [String: Any],
                  let scopeType = scopeDict["type"] as? String else {
                os_log("Invalid policy decision payload", log: self.log, type: .error)
                return
            }

            let scope: LeashPolicyDecision.Scope
            switch scopeType {
            case "once":
                scope = .once
            case "always":
                scope = .always
            case "directory":
                guard let path = scopeDict["path"] as? String else {
                    os_log("Missing path for directory scope", log: self.log, type: .error)
                    return
                }
                scope = .directory(path)
            default:
                os_log("Unknown scope type: %{public}@", log: self.log, type: .error, scopeType)
                return
            }

            let scopeDescription: String
            switch scope {
            case .once:
                scopeDescription = "once"
            case .always:
                scopeDescription = "always"
            case .directory(let path):
                scopeDescription = "directory:\(path)"
            }

            guard let event = self.eventCache[eventID] else {
                os_log("Missing event for decision %{public}@", log: self.log, type: .error, eventID.uuidString)
                return
            }

            os_log("Policy decision processed: %{public}@ → %{public}@ (scope=%{public}@)", log: self.log, type: .info, event.processPath, action == .allow ? "ALLOW" : "DENY", scopeDescription)

            self.eventCache.removeValue(forKey: eventID)
            if let index = self.eventOrder.firstIndex(of: eventID) {
                self.eventOrder.remove(at: index)
            }
        }
    }

    func handleRuleAddNotification(_ payload: [String: Any]) {
        queue.async { [weak self] in
            guard let self else { return }

            guard let rulesData = payload["rules"] as? [[String: Any]] else {
                os_log("Invalid rule add payload", log: self.log, type: .error)
                return
            }

            var newRules: [LeashPolicyRule] = []
            for ruleDict in rulesData {
                guard let idString = ruleDict["id"] as? String,
                      let id = UUID(uuidString: idString),
                      let kindString = ruleDict["kind"] as? String,
                      let kind = LeashPolicyEvent.Kind(rawValue: kindString),
                      let actionString = ruleDict["action"] as? String,
                      let action = LeashPolicyDecision.Action(rawValue: actionString),
                      let executablePath = ruleDict["executable_path"] as? String else {
                    continue
                }

                let rule = LeashPolicyRule(
                    id: id,
                    kind: kind,
                    action: action,
                    executablePath: executablePath,
                    directory: ruleDict["directory"] as? String,
                    filePath: ruleDict["file_path"] as? String,
                    coversCreates: (ruleDict["covers_creates"] as? Bool) ?? false
                )

                newRules.append(rule)
                os_log("Added rule from daemon: %{public}@", log: self.log, type: .info, rule.executablePath)
            }

            if !newRules.isEmpty {
                let denyRules = newRules.filter { $0.action == .deny }
                if !denyRules.isEmpty {
                    self.monitor?.enforceDeniedProcesses(rules: denyRules)
                }
                self.rulesQueue.async {
                    self.cachedRules.append(contentsOf: newRules)
                    self.cachedRules.sort(by: Self.ruleSortComparator)
                }
            }
        }
    }

    func handleRuleRemoveNotification(_ payload: [String: Any]) {
        queue.async { [weak self] in
            guard let self else { return }

            guard let idStrings = payload["ids"] as? [String] else {
                os_log("Invalid rule remove payload", log: self.log, type: .error)
                return
            }

            let idsToRemove = idStrings.compactMap { UUID(uuidString: $0) }
            guard !idsToRemove.isEmpty else { return }

            self.rulesQueue.async {
                let beforeCount = self.cachedRules.count
                self.cachedRules.removeAll { rule in
                    idsToRemove.contains(rule.id)
                }
                self.cachedRules.sort(by: Self.ruleSortComparator)
                let removedCount = beforeCount - self.cachedRules.count
                if removedCount > 0 {
                    os_log("Removed %d rules from cache", log: self.log, type: .info, removedCount)
                }
            }
        }
    }

    func handleClearRulesNotification() {
        queue.async { [weak self] in
            guard let self else { return }
            self.rulesQueue.async {
                let count = self.cachedRules.count
                self.cachedRules.removeAll()
                os_log("Cleared all %d rules per daemon request", log: self.log, type: .info, count)
            }
        }
    }

    func handleRuleSnapshotNotification(_ payload: [String: Any]) {
        queue.async { [weak self] in
            guard let self else { return }

            guard let rulesData = payload["rules"] as? [[String: Any]] else {
                os_log("Invalid rule snapshot payload", log: self.log, type: .error)
                return
            }

            var newRules: [LeashPolicyRule] = []
            for ruleDict in rulesData {
                guard let idString = ruleDict["id"] as? String,
                      let id = UUID(uuidString: idString),
                      let kindString = ruleDict["kind"] as? String,
                      let kind = LeashPolicyEvent.Kind(rawValue: kindString),
                      let actionString = ruleDict["action"] as? String,
                      let action = LeashPolicyDecision.Action(rawValue: actionString),
                      let executablePath = ruleDict["executable_path"] as? String else {
                    continue
                }

                let rule = LeashPolicyRule(
                    id: id,
                    kind: kind,
                    action: action,
                    executablePath: executablePath,
                    directory: ruleDict["directory"] as? String,
                    filePath: ruleDict["file_path"] as? String,
                    coversCreates: (ruleDict["covers_creates"] as? Bool) ?? false
                )

                newRules.append(rule)
            }

            let denyRules = newRules.filter { $0.action == .deny }
            if !denyRules.isEmpty {
                self.monitor?.enforceDeniedProcesses(rules: denyRules)
            }

            self.rulesQueue.async {
                self.cachedRules = newRules.sorted(by: Self.ruleSortComparator)
                os_log("Updated rule cache with %d rules from snapshot", log: self.log, type: .info, newRules.count)
            }
        }
    }

    func cacheEvent(_ event: LeashPolicyEvent) {
        if eventCache[event.id] == nil {
            eventOrder.append(event.id)
        }
        eventCache[event.id] = event

        if eventOrder.count > cacheLimit, let oldest = eventOrder.first {
            eventOrder.removeFirst()
            eventCache.removeValue(forKey: oldest)
        }
    }

    static func ruleSortComparator(_ lhs: LeashPolicyRule, _ rhs: LeashPolicyRule) -> Bool {
        let left = ruleSortKey(lhs)
        let right = ruleSortKey(rhs)
        if left != right {
            return left < right
        }
        return lhs.id.uuidString < rhs.id.uuidString
    }

    static func ruleSortKey(_ rule: LeashPolicyRule) -> (Int, Int, String) {
        let specificity: Int
        if rule.filePath != nil {
            specificity = 0
        } else if rule.directory != nil {
            specificity = 1
        } else {
            specificity = 2
        }
        let actionRank = rule.action == .deny ? 0 : 1
        let scope = rule.filePath ?? rule.directory ?? rule.executablePath
        return (specificity, actionRank, scope)
    }
}
