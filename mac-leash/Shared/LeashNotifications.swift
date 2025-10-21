import Foundation

enum LeashNotifications {
    static let fullDiskAccessMissing = Notification.Name(LeashIdentifiers.namespaced("fullDiskAccessMissing"))
    static let fullDiskAccessReady = Notification.Name(LeashIdentifiers.namespaced("fullDiskAccessReady"))
}
