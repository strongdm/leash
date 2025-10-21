import Foundation

/// Network filtering rule
struct NetworkRule: Identifiable, Equatable {
    let id: UUID
    let name: String
    let target: Target
    let action: Action
    let currentWorkingDirectory: String? // Scope rule to specific CWD
    let enabled: Bool
    let createdAt: Date
    
    enum Target: Equatable {
        case domain(String)           // e.g., "example.com"
        case ipAddress(String)        // e.g., "192.168.1.1"
        case ipRange(String)          // e.g., "192.168.1.0/24"
        
        var displayValue: String {
            switch self {
            case .domain(let value): return value
            case .ipAddress(let value): return value
            case .ipRange(let value): return value
            }
        }

        var typeString: String {
            switch self {
            case .domain: return "Domain"
            case .ipAddress: return "IP Address"
            case .ipRange: return "IP Range"
            }
        }
    }

    enum Action: String, Codable {
        case allow
        case deny
    }

    init(
        id: UUID = UUID(),
        name: String,
        target: Target,
        action: Action,
        currentWorkingDirectory: String? = nil,
        enabled: Bool = true,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.target = target
        self.action = action
        self.currentWorkingDirectory = currentWorkingDirectory
        self.enabled = enabled
        self.createdAt = createdAt
    }
}

extension NetworkRule {
    private static let isoFormatterWithFractional: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    private static let isoFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    static func fromDictionary(_ dict: [String: Any]) -> NetworkRule? {
        guard let idString = dict["id"] as? String,
              let id = UUID(uuidString: idString),
              let targetTypeRaw = dict["target_type"] as? String,
              let targetValueRaw = dict["target_value"] as? String,
              let actionString = dict["action"] as? String,
              let action = NetworkRule.Action(rawValue: actionString.lowercased()),
              let enabled = dict["enabled"] as? Bool else {
            return nil
        }

        let targetValue = targetValueRaw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !targetValue.isEmpty else { return nil }

        let targetType = targetTypeRaw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let target: NetworkRule.Target
        switch targetType {
        case "domain":
            target = .domain(targetValue)
        case "ip", "ipaddress":
            target = .ipAddress(targetValue)
        case "cidr", "iprange":
            target = .ipRange(targetValue)
        default:
            return nil
        }

        let rawName = (dict["name"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let name = (rawName?.isEmpty == false ? rawName! : targetValue)

        let createdAt: Date
        if let createdAtString = dict["created_at"] as? String {
            if let parsed = isoFormatterWithFractional.date(from: createdAtString) ?? isoFormatter.date(from: createdAtString) {
                createdAt = parsed
            } else {
                createdAt = Date()
            }
        } else {
            createdAt = Date()
        }

        return NetworkRule(
            id: id,
            name: name,
            target: target,
            action: action,
            currentWorkingDirectory: dict["cwd"] as? String,
            enabled: enabled,
            createdAt: createdAt
        )
    }
}
