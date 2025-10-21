import Foundation
import NetworkExtension
import os.log

autoreleasepool {
    let log = OSLog(subsystem: LeashIdentifiers.bundle, category: "network-filter-main")
    os_log("LeashNetworkFilter system extension starting...", log: log, type: .default)

    NEProvider.startSystemExtensionMode()
}

dispatchMain()
