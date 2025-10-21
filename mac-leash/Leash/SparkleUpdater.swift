import Combine
import Foundation
import os.log
import Sparkle

@MainActor
final class SparkleUpdater: NSObject, ObservableObject {
    @Published private(set) var canCheckForUpdates = false
    @Published private(set) var lastErrorDescription: String?

    private lazy var updaterController: SPUStandardUpdaterController = {
        SPUStandardUpdaterController(startingUpdater: false,
                                     updaterDelegate: self,
                                     userDriverDelegate: nil)
    }()
    private var canCheckObservation: NSKeyValueObservation?
    private var initialCheckTask: Task<Void, Never>?
    private let log = OSLog(subsystem: LeashIdentifiers.bundle, category: "sparkle")

    override init() {
        super.init()

        let controller = updaterController
        controller.updater.automaticallyChecksForUpdates = true
        controller.updater.automaticallyDownloadsUpdates = false

        canCheckObservation = controller.updater.observe(\.canCheckForUpdates,
                                                         options: [.initial, .new]) { [weak self] updater, change in
            let newValue = change.newValue ?? updater.canCheckForUpdates
            Task { [weak self] in
                await self?.applyCanCheckForUpdates(newValue)
            }
        }

        controller.startUpdater()
        scheduleInitialBackgroundCheck()
    }

    deinit {
        canCheckObservation?.invalidate()
        initialCheckTask?.cancel()
    }

    func checkForUpdates() {
        guard canCheckForUpdates else {
            os_log("Sparkle updater not ready; rejecting manual check", log: log, type: .info)
            return
        }
        updaterController.checkForUpdates(nil)
    }

    private func scheduleInitialBackgroundCheck() {
        initialCheckTask?.cancel()
        initialCheckTask = Task { [weak self] in
            do {
                try await Task.sleep(for: .seconds(10))
            } catch {
                return
            }

            guard !Task.isCancelled else { return }
            await self?.performInitialBackgroundCheck()
        }
    }

    @MainActor
    private func applyCanCheckForUpdates(_ value: Bool) {
        canCheckForUpdates = value
    }

    @MainActor
    private func performInitialBackgroundCheck() {
        guard updaterController.updater.canCheckForUpdates else { return }
        os_log("Performing initial Sparkle background check", log: log, type: .info)
        updaterController.updater.checkForUpdatesInBackground()
    }

    private func configuredFeedURL() -> String? {
        if let disable = ProcessInfo.processInfo.environment["LEASH_DISABLE_SPARKLE"],
           disable == "1" || disable.lowercased() == "true" {
            os_log("Sparkle updates disabled via LEASH_DISABLE_SPARKLE", log: log, type: .info)
            return nil
        }

        if let override = ProcessInfo.processInfo.environment["LEASH_SPARKLE_FEED_URL"], !override.isEmpty {
            return override
        }

        if let defaultsURL = UserDefaults.standard.string(forKey: "SUFeedURL"), !defaultsURL.isEmpty {
            return defaultsURL
        }

        if let infoURL = Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String, !infoURL.isEmpty {
            return infoURL
        }

        return nil
    }
}

extension SparkleUpdater: SPUUpdaterDelegate {
    func feedURLString(for updater: SPUUpdater) -> String? {
        let feed = configuredFeedURL()
        if feed == nil {
            os_log("Sparkle feed URL not configured; update checks disabled", log: log, type: .info)
        }
        return feed
    }

    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) {
        os_log("Sparkle updater aborted: %{public}@", log: log, type: .error, error.localizedDescription)
        lastErrorDescription = error.localizedDescription
    }
}
