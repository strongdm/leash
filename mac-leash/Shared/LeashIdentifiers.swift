import Foundation

enum LeashIdentifiers {
    static let bundle: String = {
        if let override = ProcessInfo.processInfo.environment["LEASH_BUNDLE_IDENTIFIER"], !override.isEmpty {
            return override
        }

        if let bundleIdentifier = Bundle.main.bundleIdentifier {
            for suffix in ["LeashES", "LeashNetworkFilter", "cli"] {
                let suffixWithSeparator = ".\(suffix)"
                if bundleIdentifier.hasSuffix(suffixWithSeparator) {
                    return String(bundleIdentifier.dropLast(suffixWithSeparator.count))
                }
            }
            return bundleIdentifier
        }

        return "com.strongdm.leash"
    }()

    static let teamIdentifier: String = {
        if let override = ProcessInfo.processInfo.environment["LEASH_TEAM_IDENTIFIER"], !override.isEmpty {
            return override
        }

        let bundle = Bundle.main
        if let prefix = bundle.object(forInfoDictionaryKey: "AppIdentifierPrefix") {
            let sanitize: (String) -> String = { value in
                value.trimmingCharacters(in: CharacterSet(charactersIn: "."))
            }

            if let string = prefix as? String {
                return sanitize(string)
            }

            if let array = prefix as? [String], let first = array.first {
                return sanitize(first)
            }
        }

        return "W5HSYBBJGA"
    }()

    static let endpointSecurityExtension = "\(bundle).LeashES"
    static let networkFilterExtension = "\(bundle).LeashNetworkFilter"
    static let cli = "\(bundle).cli"
    static let systemWideEnforcementConfigKey = "systemwide_enforcement"
    static let flowDelayEnabledConfigKey = "flow_delay_enabled"
    static let flowDelayMinConfigKey = "flow_delay_min_seconds"
    static let flowDelayMaxConfigKey = "flow_delay_max_seconds"

    static func namespaced(_ suffix: String) -> String {
        "\(bundle).\(suffix)"
    }
}
