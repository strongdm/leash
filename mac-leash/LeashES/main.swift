import Foundation
import os.log

let startup = "LeashES starting up...\n"
write(STDERR_FILENO, startup, startup.utf8.count)

let startupLog = OSLog(subsystem: LeashIdentifiers.bundle, category: "startup")

os_log("LeashES system extension starting up...", log: startupLog, type: .default)

DaemonSync.shared.sendEvent(name: "es.boot", details: nil, severity: "info", source: "leash.es")

let commService = LeashCommunicationService()
os_log("Communication service created", log: startupLog, type: .default)

let monitor = LeashMonitor(commService: commService)
commService.monitor = monitor

os_log("LeashMonitor created", log: startupLog, type: .default)

do {
    let msg = "Creating ES monitor...\n"
    write(STDERR_FILENO, msg, msg.utf8.count)

    os_log("Attempting to start ES monitor...", log: startupLog, type: .default)
    try monitor.start()

    let success = "Monitor started!\n"
    write(STDERR_FILENO, success, success.utf8.count)
    os_log("LeashES monitor started successfully", log: startupLog, type: .default)
    DistributedNotificationCenter.default().post(name: LeashNotifications.fullDiskAccessReady,
                                                 object: nil,
                                                 userInfo: nil)
    DaemonSync.shared.sendEvent(name: "es.full_disk_access.ready",
                                details: nil,
                                severity: "info",
                                source: "leash.es")
} catch LeashMonitorError.missingFullDiskAccess(let reason) {
    let err = "ERROR: \(reason)\n"
    write(STDERR_FILENO, err, err.utf8.count)
    os_log("Missing Full Disk Access: %{public}@", log: startupLog, type: .fault, reason)
    exit(EXIT_FAILURE)
} catch {
    let err = "ERROR: \(error)\n"
    write(STDERR_FILENO, err, err.utf8.count)
    os_log("Failed to start Leash monitor: %{public}@", log: startupLog, type: .fault, String(describing: error))
    exit(EXIT_FAILURE)
}

commService.start()
os_log("Communication service started", log: startupLog, type: .default)

os_log("Entering dispatch main loop", log: startupLog, type: .default)
let loop = "Entering main loop...\n"
write(STDERR_FILENO, loop, loop.utf8.count)

dispatchMain()
