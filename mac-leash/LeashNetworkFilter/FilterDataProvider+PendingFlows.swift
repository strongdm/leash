import Foundation
import NetworkExtension
import Network
import os.log
import Darwin

extension FilterDataProvider {
// MARK: - Pending Flow Management

    func recordPendingFlow(
        pid: pid_t,
        hostname: String,
        originalHostname: String,
        port: String,
        socketType: String,
        socketProtocolNumber: Int32,
        isDNSQuery: Bool
    ) {
        guard pid > 0 else { return }
        let allowQueue = syncQueue.sync { systemWideEnforcementEnabled }
        guard allowQueue else { return }

        let pending = QueuedFlow(
            pid: pid,
            hostname: hostname,
            originalHostname: originalHostname,
            port: port,
            socketType: socketType,
            socketProtocolNumber: socketProtocolNumber,
            isDNSQuery: isDNSQuery,
            enqueueTime: Date()
        )

        var queued = false
        syncQueue.sync {
            evictExpiredPendingFlowsLocked(now: pending.enqueueTime)
            var queue = pendingFlowsByPID[pid] ?? []
            queue.append(pending)
            if queue.count > maxPendingFlowsPerPID {
                queue.removeFirst(queue.count - maxPendingFlowsPerPID)
            }
            pendingFlowsByPID[pid] = queue
            queued = true
        }

        if queued {
            os_log("NET pending flow queued: pid=%{public}d %{public}@:%{public}@ (dns=%{public}@) awaiting PID metadata",
                   log: log, type: .info,
                   pid, hostname, port,
                   isDNSQuery ? "yes" : "no")
        }
    }

    func evictExpiredPendingFlowsLocked(now: Date) {
        guard !pendingFlowsByPID.isEmpty else { return }
        pendingFlowsByPID = pendingFlowsByPID.compactMapValues { flows in
            let filtered = flows.filter { now.timeIntervalSince($0.enqueueTime) <= pendingFlowTTL }
            return filtered.isEmpty ? nil : filtered
        }
    }

    func dequeuePendingFlowsLocked(
        availableInfo: [pid_t: TrackedPIDInfo],
        now: Date
    ) -> [(TrackedPIDInfo, [QueuedFlow])] {
        guard !pendingFlowsByPID.isEmpty else { return [] }
        evictExpiredPendingFlowsLocked(now: now)

        if pendingFlowsByPID.isEmpty {
            return []
        }

        var drained: [(TrackedPIDInfo, [QueuedFlow])] = []
        for (pid, flows) in pendingFlowsByPID {
            guard let info = availableInfo[pid], !flows.isEmpty else {
                continue
            }
            drained.append((info, flows))
        }

        for (info, _) in drained {
            pendingFlowsByPID.removeValue(forKey: info.pid)
        }

        return drained
    }

    func processPendingFlowBatches(_ batches: [(TrackedPIDInfo, [QueuedFlow])]) {
        let allowFallback = syncQueue.sync { systemWideEnforcementEnabled }
        guard allowFallback else { return }

        for (info, flows) in batches {
            guard !flows.isEmpty else { continue }
            os_log("NET draining %{public}d pending flows for pid=%{public}d leash=%{public}d %{public}@",
                   log: log, type: .info,
                   flows.count, info.pid, info.leashPID, info.executablePath)

            for flow in flows {
                let socketProtocol = describeSocketProtocol(flow.socketProtocolNumber)
                let decision = evaluateFlow(
                    hostname: flow.hostname,
                    port: flow.port,
                    pidInfo: info,
                    pid: flow.pid,
                    socketProtocol: flow.socketProtocolNumber,
                    allowInspection: false,
                    isDNSQuery: flow.isDNSQuery
                )

                let finalDecision: FlowDecision
                switch decision {
                case .allow:
                    finalDecision = .allow
                case .deny(let reason):
                    finalDecision = .deny(reason: reason)
                case .needsInspection:
                    finalDecision = .allow
                }

                emitNetworkEvent(
                    info: info,
                    pid: flow.pid,
                    hostname: flow.hostname,
                    port: flow.port,
                    socketType: flow.socketType,
                    socketProtocol: socketProtocol,
                    decision: finalDecision,
                    isDNSQuery: flow.isDNSQuery,
                    originalHostname: flow.originalHostname
                )

                switch finalDecision {
                case .allow:
                    let inspectionNote: String
                    if case .needsInspection = decision {
                        inspectionNote = " (late metadata; inspection unavailable)"
                    } else {
                        inspectionNote = " (late metadata)"
                    }
                    os_log("NET[leash=%{public}d] %{public}@:%{public}d → %{public}@:%{public}@ (%{public}@ %{public}@) cwd=%{public}@ → ALLOW%{public}@",
                           log: log, type: .default,
                           info.leashPID,
                           info.executablePath, flow.pid,
                           flow.hostname, flow.port,
                           flow.socketType, socketProtocol,
                           info.cwd ?? "none",
                           inspectionNote)
                case .deny(let reason):
                    os_log("NET[leash=%{public}d] %{public}@:%{public}d → %{public}@:%{public}@ (%{public}@ %{public}@) cwd=%{public}@ → DENY (late metadata): %{public}@",
                           log: log, type: .default,
                           info.leashPID,
                           info.executablePath, flow.pid,
                           flow.hostname, flow.port,
                           flow.socketType, socketProtocol,
                           info.cwd ?? "none",
                           reason)
                case .needsInspection:
                    // This branch is unreachable because we coerce .needsInspection to .allow above.
                    break
                }
            }
        }
    }

    func refreshRuntimeConfiguration(reason: String = "provider configuration") {
        let vendorConfiguration = filterConfiguration.vendorConfiguration ?? [:]

        var systemWideEnabled = false
        if let value = vendorConfiguration[LeashIdentifiers.systemWideEnforcementConfigKey] {
            if let bool = value as? Bool {
                systemWideEnabled = bool
            } else if let number = value as? NSNumber {
                systemWideEnabled = number.boolValue
            }
        }

        var delayEnabled = false
        if let value = vendorConfiguration[LeashIdentifiers.flowDelayEnabledConfigKey] {
            if let bool = value as? Bool {
                delayEnabled = bool
            } else if let number = value as? NSNumber {
                delayEnabled = number.boolValue
            }
        }

        var minDelay = FlowDelayDefaults.min
        if let value = vendorConfiguration[LeashIdentifiers.flowDelayMinConfigKey] {
            if let doubleValue = value as? Double {
                minDelay = doubleValue
            } else if let number = value as? NSNumber {
                minDelay = number.doubleValue
            }
        }

        var maxDelay = FlowDelayDefaults.max
        if let value = vendorConfiguration[LeashIdentifiers.flowDelayMaxConfigKey] {
            if let doubleValue = value as? Double {
                maxDelay = doubleValue
            } else if let number = value as? NSNumber {
                maxDelay = number.doubleValue
            }
        }

        minDelay = max(FlowDelayDefaults.lowerBound, minDelay)
        maxDelay = max(minDelay, min(maxDelay, FlowDelayDefaults.upperBound))
        var delayRange: ClosedRange<TimeInterval>? = nil
        if delayEnabled && maxDelay > 0 {
            delayRange = minDelay...maxDelay
        } else {
            delayEnabled = false
        }

        updateSystemWideEnforcementEnabled(systemWideEnabled, reason: reason)
        updateFlowDelayConfiguration(enabled: delayEnabled, range: delayRange, reason: reason)
    }

    func updateSystemWideEnforcementEnabled(_ enabled: Bool, reason: String) {
        var changed = false
        syncQueue.sync {
            if systemWideEnforcementEnabled != enabled {
                systemWideEnforcementEnabled = enabled
                if !enabled {
                    pendingFlowsByPID.removeAll()
                }
               changed = true
           }
       }

       guard changed else { return }
       if enabled {
           os_log("System-wide enforcement enabled (%{public}@). Untracked flows will be evaluated using proc metadata.",
                  log: log, type: .info, reason)
       } else {
           os_log("System-wide enforcement disabled (%{public}@). Flows without PID metadata bypass leash rules.",
                  log: log, type: .info, reason)
       }
   }

    func updateFlowDelayConfiguration(enabled: Bool, range: ClosedRange<TimeInterval>?, reason: String) {
        var changed = false
        var currentEnabled = false
        var currentRange: ClosedRange<TimeInterval>?
        syncQueue.sync {
            let normalizedRange = enabled ? range : nil
            if flowDelayEnabled != (normalizedRange != nil) || flowDelayRange != normalizedRange {
                flowDelayEnabled = normalizedRange != nil
                flowDelayRange = normalizedRange
                changed = true
            }
            currentEnabled = flowDelayEnabled
            currentRange = flowDelayRange
        }

        guard changed else { return }

        if currentEnabled, let range = currentRange {
            let lowerMs = Int(range.lowerBound * 1000)
            let upperMs = Int(range.upperBound * 1000)
            os_log("Flow delay enabled (%{public}@). Applying random delay between %{public}d–%{public}d ms for new flows.",
                   log: log, type: .info, reason, lowerMs, upperMs)
        } else {
            os_log("Flow delay disabled (%{public}@). New flows will be evaluated immediately.",
                   log: log, type: .info, reason)
        }
    }

    
}
