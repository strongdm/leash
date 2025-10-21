import Foundation
import os.log

extension DaemonSync {
    // MARK: - Public API

    func sendTrackedPIDs(_ pids: [PIDEntry]) {
        guard !pids.isEmpty else { return }
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            let entriesPayload: [[String: Any]] = pids.map { entry in
                var dict: [String: Any] = [
                    "pid": Int(entry.pid),
                    "leash_pid": Int(entry.leashPID),
                    "executable": entry.executable
                ]
                if let tty = entry.ttyPath { dict["tty_path"] = tty }
                if let cwd = entry.cwd { dict["cwd"] = cwd }
                if let description = entry.description { dict["description"] = description }
                return dict
            }

            self.sendEnvelope(
                type: "mac.pid.sync",
                payload: ["entries": entriesPayload],
                requestID: nil
            )
        }
    }

    func sendRuleSnapshot(ruleSet: RuleSet) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            let fileRules = ruleSet.fileRules.map { rule -> [String: Any] in
                var dict: [String: Any] = [
                    "id": rule.id,
                    "action": rule.action,
                    "executable": rule.executable
                ]
                if let directory = rule.directory { dict["directory"] = directory }
                if let file = rule.file { dict["file"] = file }
                if let kind = rule.kind { dict["kind"] = kind }
                return dict
            }

            let execRules = ruleSet.execRules.map { rule -> [String: Any] in
                var dict: [String: Any] = [
                    "id": rule.id,
                    "action": rule.action,
                    "executable": rule.executable
                ]
                if let argsHash = rule.argsHash { dict["args_hash"] = argsHash }
                return dict
            }

            let networkRules = ruleSet.networkRules.map { rule -> [String: Any] in
                var dict: [String: Any] = [
                    "id": rule.id,
                    "action": rule.action,
                    "target_type": rule.targetType,
                    "target_value": rule.targetValue,
                    "enabled": rule.enabled
                ]
                if let name = rule.name { dict["name"] = name }
                if let cwd = rule.cwd { dict["cwd"] = cwd }
                return dict
            }

            let payload: [String: Any] = [
                "file_rules": fileRules,
                "exec_rules": execRules,
                "network_rules": networkRules,
                "version": ruleSet.version
            ]

            self.sendEnvelope(type: "mac.rule.sync", payload: payload, requestID: nil)
        }
    }

    func sendEvent(name: String, details: [String: String]? = nil, severity: String? = nil, source: String? = nil, ruleID: String? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            let formatter = ISO8601DateFormatter()
            var payload: [String: Any] = [
                "time": formatter.string(from: Date()),
                "event": name
            ]
            if let details { payload["details"] = details }
            if let severity { payload["severity"] = severity }
            if let source { payload["source"] = source }
            if let ruleID { payload["rule_id"] = ruleID }

            self.sendEnvelope(type: "mac.event", payload: payload, requestID: nil)
        }
    }

    // MARK: - Policy Events & Decisions

    func sendPolicyEvent(_ event: LeashPolicyEvent, completion: ((Error?) -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            let payload: [String: Any] = [
                "id": event.id.uuidString,
                "timestamp": ISO8601DateFormatter().string(from: event.timestamp),
                "kind": event.kind.rawValue,
                "process_path": event.processPath,
                "process_arguments": event.processArguments,
                "current_working_directory": event.currentWorkingDirectory as Any,
                "file_path": event.filePath as Any,
                "file_operation": event.fileOperation?.rawValue as Any,
                "parent_process_path": event.parentProcessPath as Any,
                "tty_path": event.ttyPath as Any,
                "leash_process_path": event.leashProcessPath as Any,
                "leash_pid": event.leashPid as Any,
                "leash_arguments": event.leashArguments as Any,
                "leash_tty_path": event.leashTTYPath as Any,
                "pid": event.pid,
                "parent_pid": event.parentPid
            ]

            self.sendRequest(type: "mac.policy.event", payload: payload) { result in
                switch result {
                case .success:
                    completion?(nil)
                case .failure(let error):
                    completion?(error)
                }
            }
        }
    }

    func sendPolicyDecision(_ decision: LeashPolicyDecision, completion: ((Error?) -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            var scopeDict: [String: Any] = [:]
            switch decision.scope {
            case .once:
                scopeDict = ["type": "once"]
            case .always:
                scopeDict = ["type": "always"]
            case .directory(let path):
                scopeDict = ["type": "directory", "path": path]
            }

            let payload: [String: Any] = [
                "event_id": decision.eventID.uuidString,
                "action": decision.action.rawValue,
                "scope": scopeDict
            ]

            self.sendRequest(type: "mac.policy.decision", payload: payload) { result in
                switch result {
                case .success:
                    completion?(nil)
                case .failure(let error):
                    completion?(error)
                }
            }
        }
    }

    // MARK: - Rules Management

    func queryRules(completion: @escaping (Result<[LeashPolicyRule], Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            self.sendRequest(type: "mac.rule.query", payload: [:]) { result in
                switch result {
                case .success(let payload):
                    guard let rulesData = payload["rules"] as? [[String: Any]] else {
                        completion(.success([]))
                        return
                    }

                    let rules = rulesData.compactMap { ruleDict -> LeashPolicyRule? in
                        guard let idString = ruleDict["id"] as? String,
                              let id = UUID(uuidString: idString),
                              let kindString = ruleDict["kind"] as? String,
                              let kind = LeashPolicyEvent.Kind(rawValue: kindString),
                              let actionString = ruleDict["action"] as? String,
                              let action = LeashPolicyDecision.Action(rawValue: actionString),
                              let executablePath = ruleDict["executable_path"] as? String else {
                            return nil
                        }

                        return LeashPolicyRule(
                            id: id,
                            kind: kind,
                            action: action,
                            executablePath: executablePath,
                            directory: ruleDict["directory"] as? String,
                            filePath: ruleDict["file_path"] as? String,
                            coversCreates: (ruleDict["covers_creates"] as? Bool) ?? false
                        )
                    }

                    completion(.success(rules))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
    }

    func addRules(_ rules: [LeashPolicyRule], completion: ((Error?) -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            let rulesPayload = rules.map { rule -> [String: Any] in
                var dict: [String: Any] = [
                    "id": rule.id.uuidString,
                    "kind": rule.kind.rawValue,
                    "action": rule.action.rawValue,
                    "executable_path": rule.executablePath
                ]
                if let directory = rule.directory {
                    dict["directory"] = directory
                }
                if let filePath = rule.filePath {
                    dict["file_path"] = filePath
                }
                if rule.coversCreates {
                    dict["covers_creates"] = true
                }
                return dict
            }

            self.sendRequest(type: "mac.rule.add", payload: ["rules": rulesPayload]) { result in
                switch result {
                case .success:
                    completion?(nil)
                case .failure(let error):
                    completion?(error)
                }
            }
        }
    }

    func removeRules(ids: [UUID], completion: ((Error?) -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            let payload = ["ids": ids.map { $0.uuidString }]

            self.sendRequest(type: "mac.rule.remove", payload: payload) { result in
                switch result {
                case .success:
                    completion?(nil)
                case .failure(let error):
                    completion?(error)
                }
            }
        }
    }

    func clearAllRules(completion: ((Error?) -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            self.sendRequest(type: "mac.rule.clear", payload: [:]) { result in
                switch result {
                case .success:
                    completion?(nil)
                case .failure(let error):
                    completion?(error)
                }
            }
        }
    }

    // MARK: - Network Rules Management

    func updateNetworkRules(_ rules: [NetworkRule], completion: ((Error?) -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            let rulesPayload = rules.map { rule -> [String: Any] in
                var dict: [String: Any] = [
                    "id": rule.id.uuidString,
                    "name": rule.name,
                    "action": rule.action.rawValue,
                    "enabled": rule.enabled,
                    "created_at": ISO8601DateFormatter().string(from: rule.createdAt)
                ]

                switch rule.target {
                case .domain(let domain):
                    dict["target_type"] = "domain"
                    dict["target_value"] = domain
                case .ipAddress(let ip):
                    dict["target_type"] = "ipAddress"
                    dict["target_value"] = ip
                case .ipRange(let cidr):
                    dict["target_type"] = "ipRange"
                    dict["target_value"] = cidr
                }

                if let cwd = rule.currentWorkingDirectory {
                    dict["cwd"] = cwd
                }

                return dict
            }

            self.sendRequest(type: "mac.network_rule.update", payload: ["rules": rulesPayload]) { result in
                switch result {
                case .success:
                    completion?(nil)
                case .failure(let error):
                    completion?(error)
                }
            }
        }
    }

    func queryNetworkRules(completion: @escaping (Result<[NetworkRule], Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            self.sendRequest(type: "mac.network_rule.query", payload: [:]) { result in
                switch result {
                case .success(let payload):
                    guard let rulesData = payload["rules"] as? [[String: Any]] else {
                        completion(.success([]))
                        return
                    }

                    let rules = rulesData.compactMap { NetworkRule.fromDictionary($0) }

                    completion(.success(rules))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
    }

    // MARK: - Tracked PIDs Query

    func queryTrackedPIDs(completion: @escaping (Result<[PIDEntry], Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            // For now, tracked PIDs come via mac.pid.sync broadcasts
            // We don't have a query endpoint yet, so return empty
            // The daemon will broadcast when PIDs are synced
            completion(.success([]))
        }
    }

    // MARK: - Message Subscriptions

    func subscribe(to messageType: String, handler: @escaping MessageHandler) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.messageHandlers[messageType] == nil {
                self.messageHandlers[messageType] = []
            }
            self.messageHandlers[messageType]?.append(handler)
        }
    }

    func unsubscribe(from messageType: String) {
        queue.async { [weak self] in
            guard let self else { return }
            self.messageHandlers.removeValue(forKey: messageType)
        }
    }

    // MARK: - Connection Lifecycle

    func ensureConnection() {
        if let currentTask = task {
            switch currentTask.state {
            case .running, .suspended:
                return
            case .completed:
                task = nil
            case .canceling:
                return
            @unknown default:
                return
            }
        }
        os_log("Attempting websocket connection to %{public}@...", log: log, type: .info, endpointURL.absoluteString)
        connectAttempts += 1
        shimID = UUID().uuidString

        let url = endpointURL
        let task = session.webSocketTask(with: url)
        task.maximumMessageSize = 16 * 1024 * 1024 // allow up to 16MB payloads
        self.task = task
        isConnected = false
        task.resume()

        os_log("Connecting to leash daemon websocket at %{public}@", log: log, type: .info, url.absoluteString)
        listen()
        sendHello()
    }

    func listen() {
        guard let task else { return }

        task.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                if let urlError = error as? URLError, urlError.code == .cancelled {
                    os_log("Websocket receive cancelled", log: self.log, type: .debug)
                } else {
                    os_log("Websocket receive error: %{public}@", log: self.log, type: .error, error.localizedDescription)
                }
                self.queue.async {
                    self.isConnected = false
                    self.scheduleReconnect()
                }
            case .success(let message):
                self.queue.async {
                    self.isConnected = true
                }
                switch message {
                case .string(let text):
                    os_log("Websocket message len=%{public}d", log: self.log, type: .debug, text.utf8.count)
                    self.queue.async {
                        self.handleIncomingMessages(text)
                    }
                case .data(let data):
                    os_log("Websocket binary message (%{public}d bytes)", log: self.log, type: .debug, data.count)
                    if let text = String(data: data, encoding: .utf8) {
                        self.queue.async {
                            self.handleIncomingMessages(text)
                        }
                    }
                @unknown default:
                    os_log("Websocket unknown message", log: self.log, type: .error)
                }
                self.listen()
            }
        }
    }

    func sendHello() {
        let helloPayload: [String: Any] = [
            "platform": "darwin",
            "capabilities": capabilities,
            "version": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev"
        ]
        sendEnvelope(type: "client.hello", payload: helloPayload, requestID: nil)
        isConnected = true
        connectAttempts = 0
        os_log("Websocket hello sent (capabilities=%{public}@)", log: log, type: .info, capabilities.joined(separator: ","))
    }

    func scheduleReconnect() {
        reconnectWorkItem?.cancel()
        reconnectWorkItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.task?.cancel(with: .goingAway, reason: nil)
            self.task = nil
            self.ensureConnection()
        }
        let delay = min(pow(2.0, Double(connectAttempts)), 30.0)
        let delayString = String(format: "%.1f", delay)
        os_log("Scheduling websocket reconnect in %{public}@ seconds (attempt %{public}d)", log: log, type: .info, delayString, connectAttempts)
        queue.asyncAfter(deadline: .now() + delay, execute: reconnectWorkItem!)
    }

    func sendEnvelope(type: String, payload: [String: Any], requestID: String?) {
        var envelope: [String: Any] = [
            "type": type,
            "version": 1,
            "session_id": sessionID,
            "shim_id": shimID
        ]
        if let requestID {
            envelope["request_id"] = requestID
        }
        envelope["payload"] = payload

        guard JSONSerialization.isValidJSONObject(envelope) else {
            os_log("Failed to encode websocket payload (invalid JSON) type=%{public}@", log: log, type: .error, type)
            return
        }

        do {
            let data = try JSONSerialization.data(withJSONObject: envelope)
            guard let string = String(data: data, encoding: .utf8) else {
                os_log("Failed to encode websocket message as UTF8", log: log, type: .error)
                return
            }
            os_log("Sending websocket message type=%{public}@ size=%{public}d bytes requestID=%{public}@", log: log, type: .debug, type, string.utf8.count, requestID ?? "none")
            sendRaw(string)
        } catch {
            os_log("Failed to encode websocket payload: %{public}@", log: log, type: .error, error.localizedDescription)
        }
    }

    func sendRequest(type: String, payload: [String: Any], timeout: TimeInterval = 30.0, completion: @escaping (Result<[String: Any], Error>) -> Void) {
        let requestID = UUID().uuidString

        pendingRequests[requestID] = completion

        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard let self else { return }
            if let handler = self.pendingRequests.removeValue(forKey: requestID) {
                handler(.failure(NSError(domain: LeashIdentifiers.namespaced("daemon-sync"), code: -1, userInfo: [NSLocalizedDescriptionKey: "Request timed out"])))
            }
        }

        guard JSONSerialization.isValidJSONObject(payload) else {
            completion(.failure(NSError(domain: LeashIdentifiers.namespaced("daemon-sync"), code: -2, userInfo: [NSLocalizedDescriptionKey: "Failed to encode payload"])))
            return
        }

        sendEnvelope(type: type, payload: payload, requestID: requestID)
    }

    func handleIncomingMessages(_ text: String) {
        let lines = text.components(separatedBy: .newlines)
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            handleIncomingMessage(trimmed)
        }
    }

    func handleIncomingMessage(_ text: String) {
        guard let data = text.data(using: .utf8) else {
            os_log("Failed to decode incoming message as UTF-8", log: log, type: .error)
            return
        }

        // Try to decode as envelope first
        do {
            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase
            let envelope = try decoder.decode(IncomingEnvelope.self, from: data)

            os_log("Received message type=%{public}@ requestID=%{public}@", log: log, type: .debug, envelope.type, envelope.requestID ?? "none")

            // Convert AnyCodable payload to [String: Any]
            let payload = envelope.payload.mapValues { $0.value }

            // Check if this is a response to a pending request
            if let requestID = envelope.requestID, let handler = pendingRequests.removeValue(forKey: requestID) {
                handler(.success(payload))
                return
            }

            // Otherwise, route to message handlers
            if let handlers = messageHandlers[envelope.type] {
                for handler in handlers {
                    handler(payload)
                }
            }
        } catch {
            // Silently ignore messages that aren't envelopes (like bulk LogEntry objects)
            // These are historical events sent on connection and don't need processing
            if data.count < 1000 {
                os_log("Received non-envelope message (likely historical event)", log: log, type: .debug)
            }
        }
    }

    func sendRaw(_ string: String) {
        guard let task else {
            os_log("No active websocket task, dropping message", log: log, type: .error)
            return
        }
        task.send(.string(string)) { [weak self] error in
            if let error {
                if let urlError = error as? URLError, urlError.code == .cancelled {
                    os_log("Websocket send cancelled", log: self?.log ?? .disabled, type: .debug)
                } else {
                    os_log("Websocket send failed: %{public}@", log: self?.log ?? .disabled, type: .error, error.localizedDescription)
                }
                self?.queue.async {
                    self?.isConnected = false
                    self?.scheduleReconnect()
                }
            } else {
                os_log("Websocket send succeeded", log: self?.log ?? .disabled, type: .debug)
            }
        }
    }
}
