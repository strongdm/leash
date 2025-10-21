import SwiftUI
import AppKit
import NetworkExtension
import os.log

extension MainStatusView {
    var endpointSecuritySection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(statusColor(for: endpointSecurityController.status))
                        .frame(width: 8, height: 8)
                    Text(endpointSecurityController.status.statusText)
                        .font(.system(size: 13, weight: .medium))
                    Spacer()
                }

                if let subtitle = endpointSubtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                if case .requiresFullDiskAccess = endpointSecurityController.status {
                    Button {
                        openFullDiskAccessSettings()
                    } label: {
                        Text("Open Full Disk Access Settings")
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                }

                HStack(spacing: 8) {
                    Button {
                        Task { @MainActor in
                            endpointSecurityController.retryActivation()
                        }
                    } label: {
                        Text("Activate")
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)

                    Button {
                        Task { @MainActor in
                            endpointSecurityController.refreshStatus()
                        }
                    } label: {
                        Text("Refresh")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)

                    Button {
                        openFullDiskAccessSettings()
                    } label: {
                        Text("Check Full Disk Access")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)

                    Spacer()

                    Button(role: .destructive) {
                        removeEndpointExtension()
                    } label: {
                        Text("Remove")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
            .padding(2)
        } label: {
            Label("Endpoint Security", systemImage: "eye.circle.fill")
                .font(.system(size: 13, weight: .semibold))
        }
    }

    var networkFilterSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(statusColor(for: networkExtensionController.status))
                        .frame(width: 8, height: 8)
                    Text("Extension: \(networkExtensionController.status.statusText)")
                        .font(.system(size: 13, weight: .medium))
                    Spacer()
                }

                HStack(spacing: 8) {
                    Circle()
                        .fill(networkFilterStatus.color)
                        .frame(width: 8, height: 8)
                    Text("Filter: \(networkFilterStatus.label)")
                        .font(.system(size: 13, weight: .medium))
                    Spacer()
                }

                if let subtitle = networkSubtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                if let filterSubtitle = networkFilterStatus.subtitle, !filterSubtitle.isEmpty {
                    Text(filterSubtitle)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: 8) {
                    Button {
                        activateNetworkFilter()
                    } label: {
                        Text("Activate")
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)

                    Button {
                        refreshNetworkFilterStatus()
                        Task { @MainActor in
                            networkExtensionController.refreshStatus()
                        }
                    } label: {
                        Text("Refresh")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)

                    Spacer()

                    Button(role: .destructive) {
                        Task {
                            await removeNetworkFilter()
                        }
                    } label: {
                        Text("Remove")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
            .padding(2)
        } label: {
            Label("Network Filter", systemImage: "network")
                .font(.system(size: 13, weight: .semibold))
        }
    }

    var webInterfaceSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(apiStatus.color)
                        .frame(width: 8, height: 8)
                    Text(apiStatus.label)
                        .font(.system(size: 13, weight: .medium))
                    Spacer()
                }

                if let subtitle = apiStatus.subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Text("http://127.0.0.1:18080/")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)

                HStack(spacing: 8) {
                    Button {
                        openControlUI()
                    } label: {
                        Text("Open in Browser")
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)

                    Button {
                        checkAPIStatus()
                    } label: {
                        Text("Refresh")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)

                    Spacer()
                }
            }
            .padding(2)
        } label: {
            Label("WebSocket API", systemImage: "network")
                .font(.system(size: 13, weight: .semibold))
        }
    }

    func statusColor(for status: SystemExtensionController.ActivationStatus) -> Color {
        switch status {
        case .active:
            return .green
        case .requiresApproval, .installedButDisabled:
            return .orange
        case .requiresFullDiskAccess, .failed:
            return .red
        case .checking, .activating, .deactivating:
            return .yellow
        case .inactive:
            return .red
        }
    }

    var endpointSubtitle: String? {
        if case .requiresFullDiskAccess = endpointSecurityController.status {
            let instructions = "Open System Settings › Privacy & Security › Full Disk Access and enable LeashES."
            if let details = endpointSecurityController.lastErrorMessage, !details.isEmpty {
                return "\(instructions) (Details: \(details))"
            }
            return instructions
        }

        if case .installedButDisabled = endpointSecurityController.status {
            let instructions = "Open System Settings › General › Login Items & Extensions › Endpoint Security Extensions and enable the Leash Endpoint Security extension."
            if let details = endpointSecurityController.lastErrorMessage, !details.isEmpty {
                return "\(instructions) (Current state: \(details).)"
            }
            return instructions
        }

        if case .requiresApproval = endpointSecurityController.status {
            return "Open System Settings › General › Login Items & Extensions › Endpoint Security Extensions and enable the Leash Endpoint Security extension."
        }

        if let message = endpointSecurityController.lastErrorMessage, !message.isEmpty {
            return message
        }
        return nil
    }

    var networkSubtitle: String? {
        if case .installedButDisabled = networkExtensionController.status {
            let instructions = "Open System Settings › General › Login Items & Extensions › Network Extensions and enable the Leash Network Filter extension."
            if let details = networkExtensionController.lastErrorMessage, !details.isEmpty {
                return "\(instructions) (Current state: \(details).)"
            }
            return instructions
        }

        if case .requiresApproval = networkExtensionController.status {
            return "Open System Settings › General › Login Items & Extensions › Network Extensions and enable the Leash Network Filter extension."
        }

        if let message = networkExtensionController.lastErrorMessage, !message.isEmpty {
            return message
        }
        return nil
    }


    func openControlUI() {
        guard let url = URL(string: "http://127.0.0.1:18080/") else { return }
        NSWorkspace.shared.open(url)
    }

    func openFullDiskAccessSettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles") else { return }
        NSWorkspace.shared.open(url)
    }

    func activateNetworkFilter() {
        networkFilterStatus = .loading
        Task {
            await MainActor.run {
                networkExtensionController.retryActivation()
            }
            do {
                try await NetworkFilterManager.shared.activate()
                await MainActor.run {
                    networkFilterStatus = .active
                }
            } catch {
                await MainActor.run {
                    networkFilterStatus = .error(error.localizedDescription)
                }
            }
        }
    }

    func refreshNetworkFilterStatus() {
        networkFilterStatus = .loading
        Task {
            let state = await NetworkFilterManager.shared.currentState()
            await MainActor.run {
                switch state {
                case .configuredEnabled:
                    networkFilterStatus = .active
                case .configuredDisabled:
                    networkFilterStatus = .installedButDisabled
                case .notConfigured:
                    networkFilterStatus = .inactive
                }
            }
        }
    }

    func removeEndpointExtension() {
        endpointSecurityController.requestDeactivation()
    }

    func removeNetworkFilter() async {
        networkFilterStatus = .loading
        do {
            try await NetworkFilterManager.shared.deactivate()
            await MainActor.run {
                networkExtensionController.requestDeactivation()
                networkFilterStatus = .inactive
                networkExtensionController.refreshStatus()
            }
        } catch {
            await MainActor.run {
                networkFilterStatus = .error(error.localizedDescription)
            }
        }
    }

    func checkAPIStatus() {
        apiStatus = .loading
        Task {
            guard let url = URL(string: "http://127.0.0.1:18080/healthz") else {
                await MainActor.run {
                    apiStatus = .error("Invalid health check URL")
                }
                return
            }
            var request = URLRequest(url: url)
            request.timeoutInterval = 3.0
            do {
                let (_, response) = try await URLSession.shared.data(for: request)
                if let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) {
                    await MainActor.run {
                        apiStatus = .reachable
                    }
                } else {
                    let code = (response as? HTTPURLResponse)?.statusCode ?? -1
                    await MainActor.run {
                        apiStatus = .error("Unexpected status code \(code)")
                    }
                }
            } catch {
                await MainActor.run {
                    apiStatus = .error(error.localizedDescription)
                }
            }
        }
    }
}

extension MainStatusView {
    enum FilterStatus {
        case loading
        case active
        case inactive
        case installedButDisabled
        case error(String)

        var label: String {
            switch self {
            case .loading:
                return "Checking network filter status…"
            case .active:
                return "Network filter is active"
            case .inactive:
                return "Network filter is inactive"
            case .installedButDisabled:
                return "Network filter is disabled"
            case .error:
                return "Network filter error"
            }
        }

        var subtitle: String? {
            switch self {
            case .installedButDisabled:
                return "Open System Settings › General › Login Items & Extensions › Network Extensions and enable the Leash Network Filter."
            case .error(let message):
                return message
            default:
                return nil
            }
        }

        var color: Color {
            switch self {
            case .loading:
                return .yellow
            case .active:
                return .green
            case .inactive:
                return .red
            case .installedButDisabled:
                return .orange
            case .error:
                return .red
            }
        }
    }

    enum APIStatus {
        case loading
        case reachable
        case error(String)

        var label: String {
            switch self {
            case .loading:
                return "Checking WebSocket API…"
            case .reachable:
                return "WebSocket API is reachable"
            case .error:
                return "WebSocket API unavailable"
            }
        }

        var subtitle: String? {
            switch self {
            case .error(let message):
                return message
            default:
                return nil
            }
        }

        var color: Color {
            switch self {
            case .loading:
                return .yellow
            case .reachable:
                return .green
            case .error:
                return .red
            }
        }
    }
}

@MainActor
class NetworkFilterManager {
    static let shared = NetworkFilterManager()

    enum State {
        case notConfigured
        case configuredEnabled
        case configuredDisabled
    }

    struct FilterPreferences: Equatable {
        var systemWideEnforcement: Bool = false
        var flowDelayEnabled: Bool = false
        var flowDelayMin: Double = FlowDelayDefaults.min
        var flowDelayMax: Double = FlowDelayDefaults.max

        func normalized() -> FilterPreferences {
            var copy = self
            copy.flowDelayMin = min(max(copy.flowDelayMin, FlowDelayDefaults.lowerBound), FlowDelayDefaults.upperBound)
            copy.flowDelayMax = min(max(copy.flowDelayMax, copy.flowDelayMin), FlowDelayDefaults.upperBound)
            return copy
        }
    }

    enum FlowDelayDefaults {
        static let min: Double = 0.1
        static let max: Double = 0.5
        static let lowerBound: Double = 0.0
        static let upperBound: Double = 1.0
    }

    private init() {}

    func activate() async throws {
        let manager = NEFilterManager.shared()

        try await manager.loadFromPreferences()

        let config = NEFilterProviderConfiguration()
        config.filterDataProviderBundleIdentifier = LeashIdentifiers.networkFilterExtension
        config.filterSockets = true
        config.filterPackets = false

        manager.providerConfiguration = config
        manager.localizedDescription = "Leash Network Filter"
        manager.isEnabled = true

        try await manager.saveToPreferences()
    }

    func currentState() async -> State {
        let manager = NEFilterManager.shared()

        do {
            try await manager.loadFromPreferences()
            guard
                let provider = manager.providerConfiguration,
                provider.filterDataProviderBundleIdentifier == LeashIdentifiers.networkFilterExtension
            else {
                return .notConfigured
            }

            return manager.isEnabled ? .configuredEnabled : .configuredDisabled
        } catch {
            return .notConfigured
        }
    }

    func currentFilterPreferences() async -> FilterPreferences {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            guard
                let provider = manager.providerConfiguration,
                provider.filterDataProviderBundleIdentifier == LeashIdentifiers.networkFilterExtension
            else {
                return FilterPreferences()
            }

            var preferences = FilterPreferences()

            if let value = provider.vendorConfiguration?[LeashIdentifiers.systemWideEnforcementConfigKey] {
                if let bool = value as? Bool {
                    preferences.systemWideEnforcement = bool
                } else if let number = value as? NSNumber {
                    preferences.systemWideEnforcement = number.boolValue
                }
            }

            if let value = provider.vendorConfiguration?[LeashIdentifiers.flowDelayEnabledConfigKey] {
                if let bool = value as? Bool {
                    preferences.flowDelayEnabled = bool
                } else if let number = value as? NSNumber {
                    preferences.flowDelayEnabled = number.boolValue
                }
            }

            if let value = provider.vendorConfiguration?[LeashIdentifiers.flowDelayMinConfigKey] {
                if let doubleValue = value as? Double {
                    preferences.flowDelayMin = doubleValue
                } else if let number = value as? NSNumber {
                    preferences.flowDelayMin = number.doubleValue
                }
            }

            if let value = provider.vendorConfiguration?[LeashIdentifiers.flowDelayMaxConfigKey] {
                if let doubleValue = value as? Double {
                    preferences.flowDelayMax = doubleValue
                } else if let number = value as? NSNumber {
                    preferences.flowDelayMax = number.doubleValue
                }
            }

            return preferences.normalized()
        } catch {
            return FilterPreferences()
        }
    }

    func updateFilterPreferences(_ preferences: FilterPreferences) async throws {
        let manager = NEFilterManager.shared()
        try await manager.loadFromPreferences()

        let config: NEFilterProviderConfiguration
        if let existing = manager.providerConfiguration {
            config = existing
        } else {
            config = NEFilterProviderConfiguration()
        }

        config.filterDataProviderBundleIdentifier = LeashIdentifiers.networkFilterExtension
        config.filterSockets = true
        config.filterPackets = false

        var vendorConfiguration = config.vendorConfiguration ?? [:]
        let normalized = preferences.normalized()
        vendorConfiguration[LeashIdentifiers.systemWideEnforcementConfigKey] = normalized.systemWideEnforcement
        vendorConfiguration[LeashIdentifiers.flowDelayEnabledConfigKey] = normalized.flowDelayEnabled
        vendorConfiguration[LeashIdentifiers.flowDelayMinConfigKey] = normalized.flowDelayMin
        vendorConfiguration[LeashIdentifiers.flowDelayMaxConfigKey] = normalized.flowDelayMax
        config.vendorConfiguration = vendorConfiguration

        manager.providerConfiguration = config
        manager.localizedDescription = "Leash Network Filter"
        try await manager.saveToPreferences()
    }

    func deactivate() async throws {
        let manager = NEFilterManager.shared()

        try await manager.loadFromPreferences()

        guard manager.isEnabled else { return }

        manager.isEnabled = false
        try await manager.saveToPreferences()
    }
}
