import Foundation

struct LeashPolicyEvent: Codable, Identifiable {
    enum Kind: String, Codable {
        case processExec
        case fileAccess
    }

    enum FileOperation: String, Codable {
        case open
        case create
        case write
    }

    let id: UUID
    let timestamp: Date
    let kind: Kind
    let processPath: String
    let processArguments: [String]
    let currentWorkingDirectory: String?
    let filePath: String?
    let fileOperation: FileOperation?
    let parentProcessPath: String?
    let ttyPath: String?
    let leashProcessPath: String?
    let leashPid: Int32?
    let leashArguments: [String]?
    let leashTTYPath: String?
    let pid: Int32
    let parentPid: Int32
}

struct LeashPolicyDecision: Codable {
    enum Action: String, Codable {
        case allow
        case deny
    }

    enum Scope: Codable {
        case once
        case always
        case directory(String)
    }

    let eventID: UUID
    let action: Action
    let scope: Scope
}

struct LeashPolicyRule: Codable, Identifiable, Equatable {
    let id: UUID
    let kind: LeashPolicyEvent.Kind
    let action: LeashPolicyDecision.Action
    let executablePath: String
    let directory: String?
    let filePath: String?
    let coversCreates: Bool

    init(id: UUID = UUID(), kind: LeashPolicyEvent.Kind, action: LeashPolicyDecision.Action, executablePath: String, directory: String? = nil, filePath: String? = nil, coversCreates: Bool = false) {
        self.id = id
        self.kind = kind
        self.action = action
        self.executablePath = executablePath
        self.directory = directory
        self.filePath = filePath
        if filePath != nil {
            self.coversCreates = true
        } else {
            self.coversCreates = coversCreates
        }
    }

    func matches(_ event: LeashPolicyEvent) -> Bool {
        guard kind == event.kind else { return false }
        if !executablePath.isEmpty && executablePath != "*" {
            guard event.processPath == executablePath else { return false }
        }
        if let directory {
            let normalizedDirectory = normalizeDirectoryPath(directory)
            if kind == .fileAccess {
                guard let rawPath = event.filePath else { return false }
                let normalizedPath = normalizeFilePath(rawPath)
                let directoryExact = String(normalizedDirectory.dropLast())
                if normalizedPath != directoryExact && !normalizedPath.hasPrefix(normalizedDirectory) {
                    return false
                }
            } else {
                guard let cwd = event.currentWorkingDirectory else { return false }
                let normalizedCWD = normalizeDirectoryPath(cwd)
                if normalizedCWD != normalizedDirectory {
                    return false
                }
            }
        }
        if let filePath {
            guard let eventFilePath = event.filePath, eventFilePath == filePath else { return false }
        }

        if event.fileOperation == .create && !coversCreates {
            return false
        }

        return true
    }

    private func normalizeDirectoryPath(_ path: String) -> String {
        var normalized = normalizeFilePath(path)
        if !normalized.hasSuffix("/") {
            normalized += "/"
        }
        return normalized
    }

    private func normalizeFilePath(_ path: String) -> String {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return trimmed }
        return URL(fileURLWithPath: trimmed).standardized.path
    }
}
