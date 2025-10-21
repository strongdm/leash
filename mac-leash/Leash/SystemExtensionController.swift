import Combine
import Foundation
import SystemExtensions

@MainActor
final class SystemExtensionController: NSObject, ObservableObject {
    enum ActivationStatus: Equatable {
        case checking
        case inactive
        case activating
        case deactivating
        case requiresApproval
        case installedButDisabled
        case requiresFullDiskAccess
        case active
        case failed(String)

        var statusText: String {
            switch self {
            case .checking:
                return "Checking extension state…"
            case .inactive:
                return "Extension not installed"
            case .activating:
                return "Requesting extension activation…"
            case .deactivating:
                return "Removing extension…"
            case .requiresApproval:
                return "Awaiting user approval in System Settings"
            case .installedButDisabled:
                return "Extension disabled in System Settings"
            case .requiresFullDiskAccess:
                return "Grant Full Disk Access in System Settings"
            case .active:
                return "Extension is active"
            case .failed:
                return "Extension activation failed"
            }
        }
    }

    enum ControllerError: Error, LocalizedError {
        case commandNotFound
        case commandFailed(Int32, String)
        case unreadableOutput

        var errorDescription: String? {
            switch self {
            case .commandNotFound:
                return "Unable to locate systemextensionsctl command."
            case .commandFailed(let status, let output):
                let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.isEmpty {
                    return "systemextensionsctl exited with status \(status)."
                }
                return "systemextensionsctl failed (status \(status)): \(trimmed)"
            case .unreadableOutput:
                return "Failed to decode systemextensionsctl output."
            }
        }
    }

    @Published var status: ActivationStatus = .checking
    @Published var lastErrorMessage: String?

    let extensionIdentifier: String
    let workQueue = DispatchQueue(label: LeashIdentifiers.namespaced("systemextension"), qos: .userInitiated)
    var pendingRequest: OSSystemExtensionRequest?
    var pendingRequestKind: RequestKind?
    let autoActivate: Bool
    var fullDiskAccessIssue: String?
    var distributedNotificationObservers: [NSObjectProtocol] = []
    let versionStorageKey: String
    let embeddedExtensionVersion: ExtensionVersion?
    var extensionVersionNeedsReplacement: Bool

    enum RequestKind {
        case activation
        case deactivation
    }

    enum ExtensionState {
        case active
        case installedButDisabled(String?)
        case notInstalled
    }

    struct ExtensionVersion: Equatable {
        let bundleVersion: String
        let shortVersion: String?

        init?(bundle: Bundle) {
            guard let bundleVersion = bundle.infoDictionary?["CFBundleVersion"] as? String,
                  !bundleVersion.isEmpty else {
                return nil
            }
            let shortValue = bundle.infoDictionary?["CFBundleShortVersionString"] as? String
            shortVersion = shortValue?.isEmpty == false ? shortValue : nil
            self.bundleVersion = bundleVersion
        }

        init?(dictionary: [String: Any]) {
            guard let bundleVersion = dictionary["bundleVersion"] as? String,
                  !bundleVersion.isEmpty else {
                return nil
            }
            let shortValue = dictionary["shortVersion"] as? String
            self.bundleVersion = bundleVersion
            self.shortVersion = shortValue?.isEmpty == false ? shortValue : nil
        }

        var propertyListRepresentation: [String: String] {
            var payload: [String: String] = ["bundleVersion": bundleVersion]
            if let shortVersion {
                payload["shortVersion"] = shortVersion
            }
            return payload
        }
    }

    init(extensionIdentifier: String? = nil,
         autoActivate: Bool = true) {
        let resolvedIdentifier = extensionIdentifier ?? LeashIdentifiers.endpointSecurityExtension
        let storageKey = "systemextension.version.\(resolvedIdentifier)"
        let embeddedVersion = SystemExtensionController.embeddedExtensionVersion(for: resolvedIdentifier)
        let storedVersion = SystemExtensionController.storedExtensionVersion(forKey: storageKey)

        self.extensionIdentifier = resolvedIdentifier
        self.autoActivate = autoActivate
        self.versionStorageKey = storageKey
        self.embeddedExtensionVersion = embeddedVersion
        if let embeddedVersion, let storedVersion {
            self.extensionVersionNeedsReplacement = storedVersion != embeddedVersion
        } else {
            self.extensionVersionNeedsReplacement = false
        }
        super.init()
        registerFullDiskAccessNotifications()
        if autoActivate {
            Task { [weak self] in
                await self?.checkAndActivateIfNeeded()
            }
        }
    }

    func ensureExtensionIsActive() {
        Task { [weak self] in
            guard let self else { return }
            await self.checkCurrentStatus(activateIfNeeded: true,
                                          force: self.extensionVersionNeedsReplacement)
        }
    }

    func refreshStatus() {
        Task { [weak self] in
            guard let self else { return }
            await self.checkCurrentStatus(activateIfNeeded: false,
                                           force: self.extensionVersionNeedsReplacement)
        }
    }

    func retryActivation() {
        Task { [weak self] in
            await self?.checkCurrentStatus(activateIfNeeded: true, force: true)
        }
    }

    func requestDeactivation() {
        guard pendingRequest == nil else { return }
        lastErrorMessage = nil
        status = .deactivating
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: DispatchQueue.main
        )
        request.delegate = self
        pendingRequest = request
        pendingRequestKind = .deactivation
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    deinit {
        let center = DistributedNotificationCenter.default()
        for observer in distributedNotificationObservers {
            center.removeObserver(observer)
        }
        distributedNotificationObservers.removeAll()
    }
}
