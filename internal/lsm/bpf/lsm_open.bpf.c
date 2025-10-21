// SPDX-License-Identifier: GPL-2.0

// Define basic types first
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

// Define network types
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __wsum;

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Define missing types
typedef int bool;
#define true 1
#define false 0

// BPF map types
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0

char LICENSE[] SEC("license") = "GPL";

#define MAX_PATH_LEN 256
#define MAX_ENTRIES 8192
// BPF verifier-friendly constant bound for policy rules (max 256 with loop-based implementation)
#define MAX_POLICY_RULES 256

// Operation types (must match Go constants)
#define OP_OPEN 0    // open (any mode)
#define OP_OPEN_RO 1 // open:ro (read-only)
#define OP_OPEN_RW 2 // open:rw (any write mode)

struct open_event {
    u32 pid;
    u32 tgid;
    u64 timestamp;
    u64 cgroup_id;
    char comm[16];  // Task command name
    char path[MAX_PATH_LEN];
    u32 operation;  // OP_OPEN, OP_OPEN_RO, OP_OPEN_RW
    s32 result;     // Result of the open operation (0 = allowed, -EACCES = denied)
};

// Policy rule structure for BPF map
struct policy_rule {
    u32 action;      // 0 = deny, 1 = allow
    u32 operation;   // 0 = open, 1 = open:ro, 2 = open:rw
    u32 path_len;
    char path[MAX_PATH_LEN];
    u32 is_directory; // 1 if path ends with /
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Map to store the target cgroup ID for filtering (root of subtree to monitor)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgroup SEC(".maps");

// Map to store multiple cgroup IDs to monitor (for descendants)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u8);
} allowed_cgroups SEC(".maps");

// Map to store policy rules (indexed by rule number, supports up to 256 rules)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, u32);
    __type(value, struct policy_rule);
} policy_rules SEC(".maps");

// Map to store the number of policy rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} num_rules SEC(".maps");

// Map to store the default policy result (0 = deny, 1 = allow)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} default_policy SEC(".maps");

// Helper to check if we're in a target cgroup or descendant
static __always_inline bool is_target_cgroup()
{
    u32 key = 0;
    u64 *target_cgroup_id = bpf_map_lookup_elem(&target_cgroup, &key);
    if (!target_cgroup_id || *target_cgroup_id == 0) {
        // No target cgroup set, don't monitor anything
        return false;
    }

    // Get the current cgroup ID
    u64 current_cgroup_id = bpf_get_current_cgroup_id();

    // Check if this cgroup ID is in our allowed list
    // The userspace program populates this with all descendant cgroup IDs
    u8 *allowed = bpf_map_lookup_elem(&allowed_cgroups, &current_cgroup_id);
    if (allowed && *allowed == 1) {
        return true;
    }

    return false;
}

// Bounded loop string comparison with disabled unrolling for BPF verifier
static __always_inline int simple_string_starts_with(const char *s, const char *p, __u32 max_len)
{
    if (max_len > 64) max_len = 64;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < 64; i++) {
        if (i >= max_len) break;          // dominates the byte loads
        if (s[i] != p[i]) return 0;
    }
    return 1;
}

// Check if path is a Linux namespace FD from nsfs
static __always_inline bool is_nsfs_path(const char *path)
{
    // nsfs paths have the pattern: namespace_type:[inode_number]
    // Examples: mnt:[4026537166], net:[4026532621], ipc:[4026537168]

    // Check for common namespace types followed by :[ pattern
    const char *nsfs_prefixes[] = {
        "mnt:[", "net:[", "ipc:[", "pid:[",
        "uts:[", "user:[", "cgroup:[", "time:["
    };

    // Check each prefix with a bounded loop for BPF verifier
    #pragma clang loop unroll(disable)
    for (int prefix_idx = 0; prefix_idx < 8; prefix_idx++) {
        const char *prefix;
        int prefix_len;

        // Manually set prefix and length for each case to avoid dynamic array access
        if (prefix_idx == 0) { prefix = "mnt:["; prefix_len = 5; }
        else if (prefix_idx == 1) { prefix = "net:["; prefix_len = 5; }
        else if (prefix_idx == 2) { prefix = "ipc:["; prefix_len = 5; }
        else if (prefix_idx == 3) { prefix = "pid:["; prefix_len = 5; }
        else if (prefix_idx == 4) { prefix = "uts:["; prefix_len = 5; }
        else if (prefix_idx == 5) { prefix = "user:["; prefix_len = 6; }
        else if (prefix_idx == 6) { prefix = "cgroup:["; prefix_len = 8; }
        else if (prefix_idx == 7) { prefix = "time:["; prefix_len = 6; }
        else continue;

        // Check if path starts with this prefix
        bool matches = true;
        #pragma clang loop unroll(disable)
        for (int i = 0; i < 8; i++) {
            if (i >= prefix_len) break;
            if (path[i] != prefix[i]) {
                matches = false;
                break;
            }
        }

        if (matches) {
            // Verify there are digits after the colon-bracket
            int digit_pos = prefix_len;
            bool found_digit = false;
            #pragma clang loop unroll(disable)
            for (int i = 0; i < 16; i++) { // Check up to 16 chars for inode number
                if (digit_pos + i >= MAX_PATH_LEN) break;
                char c = path[digit_pos + i];
                if (c >= '0' && c <= '9') {
                    found_digit = true;
                } else if (c == ']' && found_digit) {
                    return true; // Found valid nsfs pattern
                } else if (c == '\0') {
                    break; // End of string
                } else if (c != '0' && c != '1' && c != '2' && c != '3' && c != '4' &&
                         c != '5' && c != '6' && c != '7' && c != '8' && c != '9') {
                    break; // Invalid character in inode number
                }
            }
        }
    }

    return false;
}

// Helper to determine operation type from file mode
static __always_inline u32 get_file_operation_type(struct file *file)
{
    // Read file mode flags
    fmode_t f_mode = BPF_CORE_READ(file, f_mode);

    // Check if file has write capabilities
    if (f_mode & FMODE_WRITE) {
        return OP_OPEN_RW; // Any write mode counts as rw
    }

    // Check if file has only read capabilities
    if (f_mode & FMODE_READ) {
        return OP_OPEN_RO; // Read-only
    }

    // Default to general open if we can't determine
    return OP_OPEN;
}

// Clean loop-based policy check for up to 256 rules with BPF verifier compatibility
static __always_inline int check_path_policy(const char *path, u32 file_op_type)
{
    __u32 key = 0;
    __u32 *nptr = bpf_map_lookup_elem(&num_rules, &key);
    __u32 n = nptr ? *nptr : 0;
    if (n == 0) {
        // No rules defined, use default policy from userspace
        __u32 *default_ptr = bpf_map_lookup_elem(&default_policy, &key);
        return default_ptr ? *default_ptr : 0; // Default to deny if map lookup fails
    }
    if (n > 256) n = 256;

    #pragma clang loop unroll(disable)
    for (__u32 i = 0; i < 256; i++) {
        if (i >= n) break;

        key = i;
        struct policy_rule *rule = bpf_map_lookup_elem(&policy_rules, &key);
        if (!rule) continue;

        __u32 len = rule->path_len;
        if (len == 0 || len > 64) continue;

        // Simple prefix matching - Go code handles directory expansion
        if (simple_string_starts_with(path, rule->path, len)) {
            // Check if operation types match
            if (rule->operation == OP_OPEN) {
                // "open" matches any file operation type
                return rule->action;
            } else if (rule->operation == file_op_type) {
                // Exact operation match (open:ro or open:rw)
                return rule->action;
            }
            // Path matches but operation doesn't, continue to next rule
        }
    }

    // No matching rule found, use default policy from userspace
    key = 0;
    __u32 *default_ptr = bpf_map_lookup_elem(&default_policy, &key);
    return default_ptr ? *default_ptr : 0; // Default to deny if map lookup fails
}

SEC("lsm/file_open")
int BPF_PROG(lsm_open, struct file *file)
{
    // Check if we should monitor this cgroup
    if (!is_target_cgroup()) {
        return 0;
    }

    struct open_event *event;
    char path[MAX_PATH_LEN];
    int policy_result = 0;

    // Get file path first - file pointer is already trusted from BPF_PROG macro
    int ret = bpf_d_path(&file->f_path, path, sizeof(path));
    if (ret < 0) {
        // If d_path fails, try to at least get the filename
        struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
        const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
        bpf_probe_read_kernel_str(path, sizeof(path), name);
    }

    // Skip logging nsfs (namespace filesystem) paths
    if (is_nsfs_path(path)) {
        return 0; // Allow but don't log namespace FDs
    }

    // Determine file operation type from file mode
    u32 file_op_type = get_file_operation_type(file);

    // Check policy for this path and operation type
    policy_result = check_path_policy(path, file_op_type);

    // Reserve ringbuf space
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        // Still need to enforce policy even if we can't log
        return policy_result ? 0 : -13; // -EACCES = 13
    }

    // Get process information
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tgid = pid_tgid & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();

    // Get process command name
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // Special case: allow all operations for apt-get, dpkg*, and update*
    bool is_apt_get = true;
    bool is_dpkg = true;
    bool is_update = true;

    // Check for "apt-get"
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 8; i++) {
        if (i >= 7) break; // "apt-get" is 7 characters
        char expected = (i == 0) ? 'a' :
                       (i == 1) ? 'p' :
                       (i == 2) ? 't' :
                       (i == 3) ? '-' :
                       (i == 4) ? 'g' :
                       (i == 5) ? 'e' :
                       (i == 6) ? 't' : '\0';
        if (event->comm[i] != expected) {
            is_apt_get = false;
            break;
        }
    }

    // Check for "dpkg" prefix
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 5; i++) {
        if (i >= 4) break; // "dpkg" is 4 characters
        char expected = (i == 0) ? 'd' :
                       (i == 1) ? 'p' :
                       (i == 2) ? 'k' :
                       (i == 3) ? 'g' : '\0';
        if (event->comm[i] != expected) {
            is_dpkg = false;
            break;
        }
    }

    // Check for "update" prefix
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 7; i++) {
        if (i >= 6) break; // "update" is 6 characters
        char expected = (i == 0) ? 'u' :
                       (i == 1) ? 'p' :
                       (i == 2) ? 'd' :
                       (i == 3) ? 'a' :
                       (i == 4) ? 't' :
                       (i == 5) ? 'e' : '\0';
        if (event->comm[i] != expected) {
            is_update = false;
            break;
        }
    }

    if ((is_apt_get && event->comm[7] == '\0') || is_dpkg || is_update) {
        policy_result = 1; // Force allow for apt-get, dpkg*, or update* executables
    }

    // Copy path to event with BPF verifier-friendly bounded loop
    #pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        event->path[i] = path[i];
        if (path[i] == '\0') break;
    }

    // Record the resolved operation so userspace can distinguish read vs write opens
    event->operation = file_op_type;

    // Set result based on policy
    event->result = policy_result ? 0 : -13; // 0 = allowed, -EACCES = denied

    bpf_ringbuf_submit(event, 0);

    // Return policy decision: 0 = allow, negative = deny
    return policy_result ? 0 : -13; // -EACCES = 13
}
