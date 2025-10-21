import Foundation
import NetworkExtension
import Network
import os.log
import Darwin

extension FilterDataProvider {
// MARK: - PID Metadata Recovery

    func inferTrackedInfo(for pid: pid_t) -> TrackedPIDInfo? {
        guard pid > 0 else { return nil }
        guard let executablePath = processPath(for: pid) else { return nil }

        var leashPID: pid_t = pid
        if let bsdInfo = bsdInfo(for: pid), bsdInfo.pbi_ppid > 0 {
            leashPID = pid_t(bsdInfo.pbi_ppid)
        }

        let cwd = cwdPath(for: pid)

        return TrackedPIDInfo(
            pid: pid,
            leashPID: leashPID,
            executablePath: executablePath,
            ttyPath: nil,
            cwd: cwd
        )
    }

    func processPath(for pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        let result = buffer.withUnsafeMutableBufferPointer { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return -1 }
            return proc_pidpath(pid, base, UInt32(ptr.count))
        }
        guard result > 0 else { return nil }
        return String(cString: buffer)
    }

    func bsdInfo(for pid: pid_t) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let result = withUnsafeMutablePointer(to: &info) { pointer -> Int32 in
            return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, pointer, size)
        }
        guard result == size else { return nil }
        return info
    }

    func cwdPath(for pid: pid_t) -> String? {
        var vnodeInfo = proc_vnodepathinfo()
        let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        let result = withUnsafeMutablePointer(to: &vnodeInfo) { pointer -> Int32 in
            return proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, pointer, size)
        }
        guard result == size else { return nil }

        return withUnsafePointer(to: vnodeInfo.pvi_cdir.vip_path) { ptr -> String? in
            let charPtr = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            if charPtr.pointee == 0 {
                return nil
            }
            return String(cString: charPtr)
        }
    }

    
}
