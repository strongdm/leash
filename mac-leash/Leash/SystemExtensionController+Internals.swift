import Combine
import Foundation
import SystemExtensions

extension SystemExtensionController {
    func checkAndActivateIfNeeded() async {
        await checkCurrentStatus(activateIfNeeded: true,
                                 force: extensionVersionNeedsReplacement)
    }

    func checkCurrentStatus(activateIfNeeded: Bool, force: Bool = false) async {
        status = .checking
        do {
            let state = try await extensionState()
            if case .active = state {
                fullDiskAccessIssue = nil
            } else if let issue = fullDiskAccessIssue {
                status = .requiresFullDiskAccess
                lastErrorMessage = issue
                pendingRequest = nil
                return
            }
            switch state {
            case .active:
                if force {
                    if let request = pendingRequest, request.identifier == extensionIdentifier {
                        status = .activating
                        return
                    }
                    submitActivationRequest(force: true)
                    return
                }
                status = .active
                pendingRequest = nil
                lastErrorMessage = nil
                recordEmbeddedExtensionVersionAsInstalledIfAvailable()
                return
            case .installedButDisabled(let detail):
                pendingRequest = nil
                status = .installedButDisabled
                lastErrorMessage = detail
                if force {
                    submitActivationRequest(force: force)
                }
                return
            case .notInstalled:
                pendingRequest = nil
            }

            lastErrorMessage = nil
            if activateIfNeeded {
                submitActivationRequest(force: force)
            } else {
                status = .inactive
            }
        } catch {
            let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            lastErrorMessage = message
            if activateIfNeeded {
                submitActivationRequest(force: force)
            } else {
                status = .failed(message)
            }
        }
    }

    private func recordEmbeddedExtensionVersionAsInstalledIfAvailable() {
        guard let version = embeddedExtensionVersion else { return }
        SystemExtensionController.storeExtensionVersion(version, forKey: versionStorageKey)
        extensionVersionNeedsReplacement = false
    }

    static func embeddedExtensionVersion(for identifier: String) -> ExtensionVersion? {
        guard let bundle = embeddedExtensionBundle(for: identifier) else { return nil }
        return ExtensionVersion(bundle: bundle)
    }

    private static func embeddedExtensionBundle(for identifier: String) -> Bundle? {
        let fileManager = FileManager.default
        let searchRoots: [URL] = [
            Bundle.main.bundleURL
                .appendingPathComponent("Contents", isDirectory: true)
                .appendingPathComponent("Library", isDirectory: true)
                .appendingPathComponent("SystemExtensions", isDirectory: true),
            Bundle.main.builtInPlugInsURL
        ].compactMap { $0 }

        for root in searchRoots {
            guard fileManager.fileExists(atPath: root.path) else { continue }
            guard let enumerator = fileManager.enumerator(at: root,
                                                          includingPropertiesForKeys: nil,
                                                          options: [.skipsHiddenFiles]) else { continue }
            for case let candidate as URL in enumerator where candidate.pathExtension == "systemextension" {
                guard let bundle = Bundle(url: candidate) else { continue }
                if bundle.bundleIdentifier == identifier {
                    return bundle
                }
            }
        }
        return nil
    }

    static func storedExtensionVersion(forKey key: String) -> ExtensionVersion? {
        guard let dictionary = UserDefaults.standard.dictionary(forKey: key) else { return nil }
        return ExtensionVersion(dictionary: dictionary)
    }

    static func storeExtensionVersion(_ version: ExtensionVersion, forKey key: String) {
        UserDefaults.standard.set(version.propertyListRepresentation, forKey: key)
    }

    func registerFullDiskAccessNotifications() {
        guard extensionIdentifier == LeashIdentifiers.endpointSecurityExtension else { return }

        let center = DistributedNotificationCenter.default()

        let missingObserver = center.addObserver(forName: LeashNotifications.fullDiskAccessMissing,
                                                 object: nil,
                                                 queue: .main) { [weak self] notification in
            let message = (notification.userInfo?["message"] as? String) ??
            "LeashES requires Full Disk Access to observe Endpoint Security events."
            Task { [weak self] in
                guard let self else { return }
                await MainActor.run {
                    self.fullDiskAccessIssue = message
                    self.lastErrorMessage = message
                    self.pendingRequest = nil
                    self.pendingRequestKind = nil
                    self.status = .requiresFullDiskAccess
                }
            }
        }
        distributedNotificationObservers.append(missingObserver)

        let readyObserver = center.addObserver(forName: LeashNotifications.fullDiskAccessReady,
                                               object: nil,
                                               queue: .main) { [weak self] _ in
            Task { [weak self] in
                guard let self else { return }
                let needsRecheck = await MainActor.run { () -> Bool in
                    self.fullDiskAccessIssue = nil
                    self.lastErrorMessage = nil
                    if case .requiresFullDiskAccess = self.status {
                        self.status = .checking
                        return true
                    }
                    return false
                }
                if needsRecheck {
                    await self.checkCurrentStatus(activateIfNeeded: false,
                                                  force: self.extensionVersionNeedsReplacement)
                }
            }
        }
        distributedNotificationObservers.append(readyObserver)
    }

    private func submitActivationRequest(force: Bool) {
        if pendingRequest != nil && !force {
            status = .activating
            return
        }

        lastErrorMessage = nil
        status = .activating
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionIdentifier,
                                                                  queue: DispatchQueue.main)
        request.delegate = self
        pendingRequest = request
        pendingRequestKind = .activation
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func extensionState() async throws -> ExtensionState {
        let identifier = extensionIdentifier
        return try await withCheckedThrowingContinuation { continuation in
            workQueue.async {
                do {
                    let process = Process()
                    let pipe = Pipe()

                    guard FileManager.default.isExecutableFile(atPath: "/usr/bin/systemextensionsctl") else {
                        throw ControllerError.commandNotFound
                    }

                    process.executableURL = URL(fileURLWithPath: "/usr/bin/systemextensionsctl")
                    process.arguments = ["list"]
                    process.standardOutput = pipe
                    process.standardError = pipe

                    try process.run()
                    process.waitUntilExit()

                    let data = pipe.fileHandleForReading.readDataToEndOfFile()
                    guard let output = String(data: data, encoding: .utf8) else {
                        throw ControllerError.unreadableOutput
                    }

                    if process.terminationStatus != 0 {
                        if process.terminationStatus == 69 {
                            Task { @MainActor in
                                self.lastErrorMessage = "Unable to read system extension status without administrator privileges. Continuing assuming the extension is inactive."
                            }
                            continuation.resume(returning: ExtensionState.notInstalled)
                            return
                        }
                        throw ControllerError.commandFailed(process.terminationStatus, output)
                    }

                    let state = SystemExtensionController.parseExtensionState(from: output,
                                                                           identifier: identifier)
                    continuation.resume(returning: state)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    nonisolated private static func parseExtensionState(from output: String, identifier: String) -> ExtensionState {
        let lowercasedIdentifier = identifier.lowercased()
        var disabledDetail: String?

        for rawLine in output.split(separator: "\n") {
            guard rawLine.lowercased().contains(lowercasedIdentifier) else { continue }
            guard let entry = interpretExtensionEntry(line: String(rawLine)) else { continue }

            if entry.isActive {
                return .active
            }

            if entry.isInstalledButDisabled {
                if disabledDetail == nil || disabledDetail?.isEmpty == true {
                    disabledDetail = entry.stateDescription
                }
            }
        }

        if let detail = disabledDetail {
            return .installedButDisabled(detail)
        }

        return .notInstalled
    }
}

private extension SystemExtensionController {
    nonisolated static func interpretExtensionEntry(line: String) -> (isActive: Bool, isInstalledButDisabled: Bool, stateDescription: String?)? {
        let components = line.split(separator: "\t", omittingEmptySubsequences: false)
        guard !components.isEmpty else { return nil }

        func columnContainsStar(_ index: Int) -> Bool {
            guard components.indices.contains(index) else { return false }
        return components[index].contains("*")
    }

    let isEnabledColumnSet = columnContainsStar(0)
    let isActiveColumnSet = columnContainsStar(1)

    let stateDescription: String?
    if let stateComponent = components.last {
        let trimmed = stateComponent.trimmingCharacters(in: .whitespacesAndNewlines)
        let unwrapped = trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        stateDescription = unwrapped.isEmpty ? nil : unwrapped
    } else {
        stateDescription = nil
    }

    let normalizedState = stateDescription?.lowercased() ?? ""

    let isActive = (isEnabledColumnSet && isActiveColumnSet) || normalizedState.contains("activated enabled")

    let isInstalledButDisabled: Bool
    if isEnabledColumnSet && !isActiveColumnSet {
        isInstalledButDisabled = true
    } else if normalizedState.contains("disabled") || normalizedState.contains("inactive") || normalizedState.contains("paused") {
        isInstalledButDisabled = true
    } else {
        isInstalledButDisabled = false
    }

    return (isActive, isInstalledButDisabled, stateDescription)
}

}

extension SystemExtensionController: OSSystemExtensionRequestDelegate {
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        guard request.identifier == extensionIdentifier else { return }
        status = .requiresApproval
        lastErrorMessage = "Open System Settings › Privacy & Security to allow the Leash system extension."
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        guard request.identifier == extensionIdentifier else { return }
        let requestKind = pendingRequestKind
        pendingRequest = nil
        pendingRequestKind = nil
        switch result {
        case .completed:
            switch requestKind {
            case .activation, .none:
                status = .active
                recordEmbeddedExtensionVersionAsInstalledIfAvailable()
            case .deactivation:
                status = .inactive
            }
            lastErrorMessage = nil
        default:
            let message = "Extension activation finished with result code \(result.rawValue)."
            status = .failed(message)
            lastErrorMessage = message
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        guard request.identifier == extensionIdentifier else { return }
        pendingRequest = nil
        pendingRequestKind = nil
        let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        status = .failed(message)
        lastErrorMessage = message
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        guard request.identifier == extensionIdentifier else { return .cancel }
        return .replace
    }
}

extension SystemExtensionController.ActivationStatus {
    var isError: Bool {
        switch self {
        case .failed, .installedButDisabled, .requiresFullDiskAccess:
            return true
        default:
            return false
        }
    }
}

