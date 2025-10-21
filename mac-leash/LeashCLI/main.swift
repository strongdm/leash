import Foundation
import Darwin

private struct CLIConfig {
    var verbose = false
    var directory: String?
    var command: [String] = []
}

private enum CLIError: LocalizedError {
    case missingCommand
    case missingDirectoryValue
    case unknownOption(String)
    case executableNotFound(String)

    var errorDescription: String? {
        switch self {
        case .missingCommand:
            return "No command specified."
        case .missingDirectoryValue:
            return "Option -C/--directory requires a value."
        case .unknownOption(let option):
            return "Unrecognized option: \(option)."
        case .executableNotFound(let executable):
            return "Unable to locate executable '\(executable)' in PATH."
        }
    }
}

private func parseArguments(_ arguments: [String]) throws -> CLIConfig {
    var config = CLIConfig()
    var command: [String] = []

    var index = 0
    while index < arguments.count {
        let arg = arguments[index]

        if !command.isEmpty {
            command.append(contentsOf: arguments[index...])
            break
        }

        switch arg {
        case "-v", "--verbose":
            config.verbose = true
        case "-C", "--directory":
            index += 1
            guard index < arguments.count else {
                throw CLIError.missingDirectoryValue
            }
            config.directory = arguments[index]
        case "--":
            let remaining = arguments.suffix(from: index + 1)
            command.append(contentsOf: remaining)
            index = arguments.count
            continue
        default:
            if arg.hasPrefix("-") {
                throw CLIError.unknownOption(arg)
            }
            command.append(contentsOf: arguments.suffix(from: index))
            index = arguments.count
            continue
        }

        index += 1
    }

    config.command = command
    return config
}

private func resolveExecutable(_ executable: String, env: [String: String]) -> String? {
    if executable.contains("/") {
        return executable
    }
    let searchPaths = env["PATH"]?.split(separator: ":") ?? []
    for path in searchPaths {
        let candidate = URL(fileURLWithPath: String(path)).appendingPathComponent(executable)
        if FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate.path
        }
    }
    return nil
}

private func runCommand(config: CLIConfig) throws -> Int32 {
    guard !config.command.isEmpty else {
        throw CLIError.missingCommand
    }

    let environment = ProcessInfo.processInfo.environment
    let executable = config.command[0]
    let resolvedExecutable = resolveExecutable(executable, env: environment) ?? executable

    guard FileManager.default.isExecutableFile(atPath: resolvedExecutable) else {
        throw CLIError.executableNotFound(executable)
    }

    // Give the Endpoint Security extension a brief moment to switch into AUTH mode
    // before spawning the child. Without this pause, very short-lived commands can
    // finish before the monitor subscribes.
    Thread.sleep(forTimeInterval: 0.5)

    var pid: pid_t = 0
    var attrs: posix_spawnattr_t?
    var fileActions: posix_spawn_file_actions_t?

    posix_spawnattr_init(&attrs)
    posix_spawn_file_actions_init(&fileActions)

    defer {
        posix_spawnattr_destroy(&attrs)
        posix_spawn_file_actions_destroy(&fileActions)
    }

    var argv: [UnsafeMutablePointer<CChar>?] = config.command.map { strdup($0) }
    argv.append(nil)

    let env = environment

    let argsTail = config.command.dropFirst().joined(separator: " ")

    if config.verbose {
        FileHandle.standardError.write(Data("[leashcli] launching \(resolvedExecutable) \(argsTail)\n".utf8))
    }

    var envp: [UnsafeMutablePointer<CChar>?] = env.map { key, value in strdup("\(key)=\(value)") }
    envp.append(nil)

    defer {
        argv.forEach { free($0) }
        envp.forEach { free($0) }
    }

    if let directory = config.directory {
        let addResult: Int32 = directory.withCString { dirPath in
            posix_spawn_file_actions_addchdir_np(&fileActions, dirPath)
        }
        guard addResult == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: addResult) ?? .EPERM)
        }
    }

    let spawnResult = resolvedExecutable.withCString { execPath in
        posix_spawnp(&pid, execPath, &fileActions, &attrs, &argv, &envp)
    }

    guard spawnResult == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: spawnResult) ?? .ENOENT)
    }

    var status: Int32 = 0
    waitpid(pid, &status, 0)

    let exitStatus = Int32((status >> 8) & 0xff)

    if config.verbose {
        FileHandle.standardError.write(Data("[leashcli] command exited with status \(exitStatus)\n".utf8))
    }

    return exitStatus
}

private func printUsage(to handle: FileHandle = .standardError) {
    let usage = """
    Usage: leashcli [-v] [-C directory] [--] command [args...]

    Options:
      -v, --verbose         Print diagnostic output.
      -C, --directory PATH  Change to PATH before running the command.
      --                    Treat the rest of the arguments as the command.
    """
    handle.write(Data(usage.utf8))
}

func main() {
    var args = CommandLine.arguments
    _ = args.removeFirst()

    do {
        let config = try parseArguments(args)
        if config.command.isEmpty {
            printUsage()
            throw CLIError.missingCommand
        }

        let status = try runCommand(config: config)
        exit(status)
    } catch let error as CLIError {
        FileHandle.standardError.write(Data("leashcli: \(error.localizedDescription)\n".utf8))
        printUsage()
        exit(64)
    } catch {
        FileHandle.standardError.write(Data("leashcli: \(error.localizedDescription)\n".utf8))
        exit(70)
    }
}

main()
