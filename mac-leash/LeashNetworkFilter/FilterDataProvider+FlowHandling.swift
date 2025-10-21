import Foundation
import NetworkExtension
import Network
import os.log
import Darwin

extension FilterDataProvider {
// MARK: - Flow Handling

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        // Extract socket flow information
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // Get source PID from audit token
        guard let auditTokenData = socketFlow.sourceAppAuditToken else {
            return .allow()
        }

        // Convert Data to audit_token_t
        let pid: pid_t = auditTokenData.withUnsafeBytes { buffer in
            guard let pointer = buffer.baseAddress?.assumingMemoryBound(to: audit_token_t.self) else {
                return 0
            }
            return audit_token_to_pid(pointer.pointee)
        }


        let hostname: String
        let port: String

        guard let hostEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
            return .allow()
        }
        hostname = hostEndpoint.hostname
        port = hostEndpoint.port

        let socketType = socketFlow.socketFamily == AF_INET ? "IPv4" :
                        socketFlow.socketFamily == AF_INET6 ? "IPv6" : "unknown"
        let socketProtocolNumber = socketFlow.socketProtocol
        let socketProtocol = describeSocketProtocol(socketProtocolNumber)

        // Check if this is a DNS query (UDP port 53)
        // For now, in the WebUI we are showing the domain that was being resolved
        // Instead of the actual DNS server
        let isDNSQuery = socketFlow.socketProtocol == IPPROTO_UDP && port == "53"
        let hostIsIP = normalizedIPAddress(from: hostname) != nil
        let shouldInspectTLS = hostIsIP && socketFlow.socketProtocol == IPPROTO_TCP && (port == "443" || port == "8443")

        refreshRuntimeConfiguration()
        let allowSystemWideFallback = syncQueue.sync { systemWideEnforcementEnabled }
        let delayRange = syncQueue.sync { flowDelayEnabled ? flowDelayRange : nil }
        if let delayRange {
            let delay = Double.random(in: delayRange)
            if delay > 0 {
                Thread.sleep(forTimeInterval: delay)
            }
        }

        var pidInfo: TrackedPIDInfo?
        syncQueue.sync {
            pidInfo = trackedPIDs[pid]
        }

        var usedFallbackInfo = false
        if pidInfo == nil, allowSystemWideFallback {
            if let inferred = inferTrackedInfo(for: pid) {
                pidInfo = inferred
                usedFallbackInfo = true
            }
        }

        guard let info = pidInfo else {
            if allowSystemWideFallback {
                recordPendingFlow(
                    pid: pid,
                    hostname: hostname,
                    originalHostname: hostname,
                    port: port,
                    socketType: socketType,
                    socketProtocolNumber: socketProtocolNumber,
                    isDNSQuery: isDNSQuery
                )
            } else {
                os_log("NET flow bypassed: pid=%{public}d %{public}@:%{public}@ (system-wide enforcement disabled, metadata missing)",
                       log: log, type: .debug,
                       pid, hostname, port)
            }
            return .allow()
        }

        if usedFallbackInfo {
            os_log("NET metadata fallback: pid=%{public}d leash=%{public}d %{public}@ cwd=%{public}@",
                   log: log, type: .debug,
                   pid, info.leashPID, info.executablePath, info.cwd ?? "none")
        }

        let decision = evaluateFlow(
            hostname: hostname,
            port: port,
            pidInfo: info,
            pid: pid,
            socketProtocol: socketProtocolNumber,
            allowInspection: true,
            isDNSQuery: isDNSQuery
        )

        switch decision {
        case .allow:
            if shouldInspectTLS {
                let flowKey = ObjectIdentifier(flow)
                syncQueue.sync {
                    pendingInspections[flowKey] = PendingInspectionState(
                        pidInfo: info,
                        pid: pid,
                        originalHostname: hostname,
                        port: port,
                        socketType: socketType,
                        socketProtocolName: socketProtocol,
                        socketProtocolNumber: socketFlow.socketProtocol,
                        buffer: Data()
                    )
                }
                os_log("TLS inspection armed for %{public}@:%{public}@ (pid=%{public}d leash=%{public}d)",
                       log: log, type: .debug,
                       hostname, port,
                       pid, info.leashPID)
                return .filterDataVerdict(
                    withFilterInbound: false,
                    peekInboundBytes: 0,
                    filterOutbound: true,
                    peekOutboundBytes: 4096
                )
            }

            if isDNSQuery {
                let flowKey = ObjectIdentifier(flow)
                syncQueue.sync {
                    pendingDNSInspections[flowKey] = DNSInspectionState(
                        pidInfo: info,
                        pid: pid,
                        originalHostname: hostname,
                        port: port,
                        socketType: socketType,
                        socketProtocolName: socketProtocol,
                        buffer: Data()
                    )
                }
                os_log("DNS inspection armed for resolver %{public}@ (pid=%{public}d leash=%{public}d)",
                       log: log, type: .debug,
                       hostname, pid, info.leashPID)
                return .filterDataVerdict(
                    withFilterInbound: false,
                    peekInboundBytes: 0,
                    filterOutbound: true,
                    peekOutboundBytes: 512
                )
            }

            emitNetworkEvent(
                info: info,
                pid: pid,
                hostname: hostname,
                port: port,
                socketType: socketType,
                socketProtocol: socketProtocol,
                decision: decision,
                isDNSQuery: isDNSQuery,
                originalHostname: hostname
            )

            os_log("NET[leash=%{public}d] %{public}@:%{public}d → %{public}@:%{public}@ (%{public}@ %{public}@) cwd=%{public}@ → ALLOW",
                   log: log, type: .default,
                   info.leashPID,
                   info.executablePath, pid,
                   hostname, port,
                   socketType, socketProtocol,
                   info.cwd ?? "none")
            return .allow()

        case .deny(let reason):
            emitNetworkEvent(
                info: info,
                pid: pid,
                hostname: hostname,
                port: port,
                socketType: socketType,
                socketProtocol: socketProtocol,
                decision: decision,
                isDNSQuery: isDNSQuery,
                originalHostname: hostname
            )
            os_log("NET[leash=%{public}d] %{public}@:%{public}d → %{public}@:%{public}@ (%{public}@ %{public}@) cwd=%{public}@ → DENY: %{public}@",
                   log: log, type: .default,
                   info.leashPID,
                   info.executablePath, pid,
                   hostname, port,
                   socketType, socketProtocol,
                   info.cwd ?? "none",
                   reason)
            return .drop()

        case .needsInspection:
            os_log("NET[leash=%{public}d] %{public}@:%{public}d → %{public}@:%{public}@ (%{public}@ %{public}@) → INSPECT",
                   log: log, type: .default,
                   info.leashPID,
                   info.executablePath, pid,
                   hostname, port,
                   socketType, socketProtocol)
            let flowKey = ObjectIdentifier(flow)
            syncQueue.sync {
                pendingInspections[flowKey] = PendingInspectionState(
                    pidInfo: info,
                    pid: pid,
                    originalHostname: hostname,
                    port: port,
                    socketType: socketType,
                    socketProtocolName: socketProtocol,
                    socketProtocolNumber: socketProtocolNumber,
                    buffer: Data()
                )
            }
            return .filterDataVerdict(
                withFilterInbound: false,
                peekInboundBytes: 0,
                filterOutbound: true,
                peekOutboundBytes: 4096
            )
        }
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        let flowKey = ObjectIdentifier(flow)

        guard var state = syncQueue.sync(execute: { pendingInspections[flowKey] }) else {
            if let dnsVerdict = handleDNSOutbound(flow: flow, flowKey: flowKey, readBytes: readBytes) {
                return dnsVerdict
            }
            return .allow()
        }

        state.buffer.append(readBytes)

        let outcome = parseClientHelloSNI(from: state.buffer)

        switch outcome {
        case .needMoreData:
            syncQueue.sync {
                pendingInspections[flowKey]?.buffer = state.buffer
            }
            let peekBytes = min(max(state.buffer.count, 1024), 16384)
            return NEFilterDataVerdict(passBytes: 0, peekBytes: peekBytes)

        case .notTLS, .malformed:
            os_log("Flow %{public}@ lacks TLS ClientHello, allowing without SNI", log: log, type: .info, state.originalHostname)
            syncQueue.sync {
                _ = pendingInspections.removeValue(forKey: flowKey)
            }
            emitNetworkEvent(
                info: state.pidInfo,
                pid: state.pid,
                hostname: state.originalHostname,
                port: state.port,
                socketType: state.socketType,
                socketProtocol: state.socketProtocolName,
                decision: .allow,
                isDNSQuery: false,
                originalHostname: state.originalHostname
            )
            return .allow()

        case .success(let maybeHostname):
            syncQueue.sync {
                _ = pendingInspections.removeValue(forKey: flowKey)
            }

            guard let hostname = maybeHostname, !hostname.isEmpty else {
                os_log("Flow %{public}@ has no SNI hostname, allowing", log: log, type: .info, state.originalHostname)
                return .allow()
            }

            if let ip = normalizedIPAddress(from: state.originalHostname) {
                addResolvedIP(ip, to: normalizeDomain(hostname), pid: state.pid, info: state.pidInfo)
            }

            let decision = evaluateFlow(
                hostname: hostname,
                port: state.port,
                pidInfo: state.pidInfo,
                pid: state.pid,
                socketProtocol: state.socketProtocolNumber,
                allowInspection: false
            )

            emitNetworkEvent(
                info: state.pidInfo,
                pid: state.pid,
                hostname: hostname,
                port: state.port,
                socketType: state.socketType,
                socketProtocol: state.socketProtocolName,
                decision: decision,
                isDNSQuery: false,
                originalHostname: state.originalHostname
            )

            switch decision {
            case .allow, .needsInspection:
                os_log("NET[leash=%{public}d] %{public}@:%{public}d → %{public}@:%{public}@ (%{public}@ %{public}@) cwd=%{public}@ → ALLOW (post-SNI)",
                       log: log, type: .default,
                       state.pidInfo.leashPID,
                       state.pidInfo.executablePath, state.pid,
                       hostname, state.port,
                       state.socketType, state.socketProtocolName,
                       state.pidInfo.cwd ?? "none")
                return .allow()

            case .deny(let reason):
                os_log("NET[leash=%{public}d] %{public}@:%{public}d → %{public}@:%{public}@ (%{public}@ %{public}@) cwd=%{public}@ → DENY (post-SNI): %{public}@",
                       log: log, type: .default,
                       state.pidInfo.leashPID,
                       state.pidInfo.executablePath, state.pid,
                       hostname, state.port,
                       state.socketType, state.socketProtocolName,
                       state.pidInfo.cwd ?? "none",
                       reason)
                return .drop()
            }
        }
    }

    
}
