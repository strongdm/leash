import Foundation
import NetworkExtension
import Network
import os.log
import Darwin

class FilterDataProvider: NEFilterDataProvider {
    let log = OSLog(subsystem: LeashIdentifiers.bundle, category: "network-filter")
    var trackedPIDs: [pid_t: TrackedPIDInfo] = [:]
    var networkRules: [NetworkRule] = []
    let syncQueue = DispatchQueue(label: LeashIdentifiers.namespaced("filter.sync"))
    let daemon = DaemonSync.shared
    var domainResolutionCache: [String: DomainResolution] = [:]
    var pendingInspections: [ObjectIdentifier: PendingInspectionState] = [:]
    var pendingDNSInspections: [ObjectIdentifier: DNSInspectionState] = [:]
    var pendingFlowsByPID: [pid_t: [QueuedFlow]] = [:]
    let maxPendingFlowsPerPID = 16
    let pendingFlowTTL: TimeInterval = 60
    var systemWideEnforcementEnabled = false
    var flowDelayEnabled = false
    var flowDelayRange: ClosedRange<TimeInterval>?

    enum FlowDelayDefaults {
        static let min: TimeInterval = 0.1
        static let max: TimeInterval = 0.5
        static let lowerBound: TimeInterval = 0.0
        static let upperBound: TimeInterval = 1.0
    }

    struct DomainResolution {
        let ips: Set<String>
        let expiry: Date
    }

    let domainResolutionTTL: TimeInterval = 300 // seconds

    struct TrackedPIDInfo {
        let pid: pid_t
        let leashPID: pid_t
        let executablePath: String
        let ttyPath: String?
        let cwd: String?
    }

    struct PendingInspectionState {
        var pidInfo: TrackedPIDInfo
        var pid: pid_t
        var originalHostname: String
        var port: String
        var socketType: String
        var socketProtocolName: String
        var socketProtocolNumber: Int32
        var buffer: Data
    }

    struct DNSInspectionState {
        var pidInfo: TrackedPIDInfo
        var pid: pid_t
        var originalHostname: String
        var port: String
        var socketType: String
        var socketProtocolName: String
        var buffer: Data
    }

    struct QueuedFlow {
        let pid: pid_t
        let hostname: String
        let originalHostname: String
        let port: String
        let socketType: String
        let socketProtocolNumber: Int32
        let isDNSQuery: Bool
        let enqueueTime: Date
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        os_log("Network filter starting...", log: log, type: .default)

        daemon.subscribe(to: "mac.pid.sync") { [weak self] payload in
            self?.handlePIDUpdate(payload)
        }

        refreshRuntimeConfiguration(reason: "startup")

        daemon.subscribe(to: "mac.network_rule.update") { [weak self] payload in
            self?.handleNetworkRuleBroadcast(payload)
        }

        reloadNetworkRules()

        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Network filter stopping: reason=%{public}d", log: log, type: .default, reason.rawValue)

        syncQueue.sync {
            trackedPIDs.removeAll()
            networkRules.removeAll()
        }

        completionHandler()
    }
}
