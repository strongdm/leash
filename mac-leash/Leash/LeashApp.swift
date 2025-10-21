import SwiftUI
import AppKit
import os.log

@main
struct leashApp: App {
    @StateObject private var endpointSecurityController = SystemExtensionController()
    @StateObject private var networkExtensionController = SystemExtensionController(
        extensionIdentifier: LeashIdentifiers.networkFilterExtension,
        autoActivate: false
    )
    @StateObject private var sparkleUpdater = SparkleUpdater()
    init() {
        let appLog = OSLog(subsystem: LeashIdentifiers.bundle, category: "app")
        os_log("Leash.app starting up...", log: appLog, type: .default)

        let msg = "Leash.app starting up (via stderr)\n"
        write(STDERR_FILENO, msg, msg.utf8.count)

        DaemonSync.shared.sendEvent(name: "app.boot", details: ["version": (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "dev"], severity: "info", source: "leash.app")
    }

    var body: some Scene {
        WindowGroup {
            MainStatusView(
                endpointSecurityController: endpointSecurityController,
                networkExtensionController: networkExtensionController
            )
                .onAppear {
                    let appLog = OSLog(subsystem: LeashIdentifiers.bundle, category: "app")
                    os_log("Leash.app UI appeared", log: appLog, type: .default)
                }
        }
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Leash") {
                    showAboutPanel()
                }
            }
            CommandGroup(after: .appInfo) {
                Button("Check for Updates…") {
                    sparkleUpdater.checkForUpdates()
                }
                .disabled(!sparkleUpdater.canCheckForUpdates)
            }
        }

        Settings {
            LeashSettingsContainerView()
        }
    }

    private func showAboutPanel() { // 😉
        let credits = NSAttributedString(string: String(data: Data(base64Encoded: "WW91J3JlIGFic29sdXRlbHkgcmlnaHQh")!, encoding: .utf8)!, attributes: [.font: NSFont.systemFont(ofSize: 13)])

        NSApp.activate(ignoringOtherApps: true)
        NSApp.orderFrontStandardAboutPanel(options: [.credits: credits])
    }
}
