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
// BPF verifier-friendly constant bound for policy rules (max 64 to reduce instruction count)
#define MAX_POLICY_RULES 64

// Operation types (must match Go constants)
#define OP_EXEC 3    // exec

struct exec_event {
    u32 pid;
    u32 _padding;      // Explicit padding for 8-byte alignment
    u64 timestamp;
    u64 cgroup_id;
    char comm[16];     // Task command name
    char path[MAX_PATH_LEN];
    s32 result;        // Result of the exec operation (0 = allowed, -EACCES = denied)
    s32 argc;          // Number of arguments
    char detailed_args[6][24]; // Individual args from tracepoint (up to 6 args, 24 chars each)
};

// Policy rule structure for BPF map
struct exec_policy_rule {
    u32 action;        // 0 = deny, 1 = allow
    u32 operation;     // Always OP_EXEC for this program
    u32 path_len;
    char path[MAX_PATH_LEN];
    u32 is_directory;  // 1 if path ends with /
    
    // Argument matching
    u32 arg_count;     // Number of args to match (0 = match any)
    u32 has_wildcard;  // 1 if rule ends with * (allow rules only)
    char args[4][32];  // Up to 4 args, 32 chars each
    u32 arg_lens[4];   // Length of each arg for efficient matching
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_events SEC(".maps");

// Map to store the target cgroup ID for filtering (root of subtree to monitor)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} exec_target_cgroup SEC(".maps");

// Map to store multiple cgroup IDs to monitor (for descendants)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u8);
} exec_allowed_cgroups SEC(".maps");

// Map to store policy rules (indexed by rule number, supports up to 256 rules)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, u32);
    __type(value, struct exec_policy_rule);
} exec_policy_rules SEC(".maps");

// Map to store the number of policy rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} exec_num_rules SEC(".maps");

// Map to store the default policy result (0 = deny, 1 = allow)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} exec_default_policy SEC(".maps");

// Helper to check if we're in a target cgroup or descendant
static __always_inline bool is_exec_target_cgroup()
{
    u32 key = 0;
    u64 *target_cgroup_id = bpf_map_lookup_elem(&exec_target_cgroup, &key);
    if (!target_cgroup_id || *target_cgroup_id == 0) {
        // No target cgroup set, don't monitor anything
        return false;
    }
    
    // Get the current cgroup ID
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    
    // Check if this cgroup ID is in our allowed list
    u8 *allowed = bpf_map_lookup_elem(&exec_allowed_cgroups, &current_cgroup_id);
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

// Tracepoint argument structure for sys_enter_execve (from tracepoint implementation)
struct sys_enter_execve_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

// Structure for storing exec arguments in correlation map
struct pending_exec_args {
    u64 timestamp;
    u32 argc;
    char original_path[MAX_PATH_LEN];  // Original path from tracepoint (may be symlinked)
    char detailed_args[6][24];         // Individual arguments (up to 6 args, 24 chars each)
};

// Map for correlating tracepoint args with LSM hook (keyed by PID)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);  // PID
    __type(value, struct pending_exec_args);
} pending_exec_args SEC(".maps");

// Simple policy check
static __always_inline int check_exec_policy(const char *path)
{
    __u32 key = 0;
    __u32 *nptr = bpf_map_lookup_elem(&exec_num_rules, &key);
    __u32 n = nptr ? *nptr : 0;
    if (n == 0) {
        // No rules defined, use default policy from userspace
        __u32 *default_ptr = bpf_map_lookup_elem(&exec_default_policy, &key);
        return default_ptr ? *default_ptr : 0; // Default to deny if map lookup fails
    }
    if (n > 64) n = 64;

    #pragma clang loop unroll(disable)
    for (__u32 i = 0; i < n && i < 64; i++) {
        key = i;
        struct exec_policy_rule *rule = bpf_map_lookup_elem(&exec_policy_rules, &key);
        if (!rule || rule->path_len == 0 || rule->path_len > 64) continue;

        // Simple prefix matching - Go code handles directory expansion
        if (simple_string_starts_with(path, rule->path, rule->path_len)) {
            // Path matches, now check arguments if rule has any
            if (rule->arg_count == 0) {
                // No arguments specified = match any (implicit wildcard)
                return rule->action; // Return immediately (back to original logic)
            }
            
            // Get correlated arguments from tracepoint
            u64 pid_tgid = bpf_get_current_pid_tgid();
            u32 pid = pid_tgid >> 32;
            struct pending_exec_args *pending = bpf_map_lookup_elem(&pending_exec_args, &pid);
            
            // Argument blacklist: deny if any blacklisted arg is found
            if (pending && pending->argc > 1 && rule->arg_count > 0 && rule->action == 0) {
                // Deny rule: check if any policy arg matches any actual arg (blacklist)
                for (u32 p = 0; p < rule->arg_count && p < 3; p++) {
                    for (u32 a = 1; a < pending->argc && a < 4; a++) { // Skip argv[0]
                        int match = 1;
                        for (u32 j = 0; j < rule->arg_lens[p] && j < 16; j++) {
                            if (pending->detailed_args[a][j] != rule->args[p][j]) {
                                match = 0;
                                break;
                            }
                        }
                        if (match) return 0; // Deny - found blacklisted arg
                    }
                }
            }
            
            // Continue to next rule
            continue;
        }
    }
    
    // No matching rule found, use default policy from userspace
    key = 0;
    __u32 *default_ptr = bpf_map_lookup_elem(&exec_default_policy, &key);
    return default_ptr ? *default_ptr : 0; // Default to deny if map lookup fails
}

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_exec, struct linux_binprm *bprm)
{
    // Check if we should monitor this cgroup
    if (!is_exec_target_cgroup()) {
        return 0;
    }

    struct exec_event *event;
    char path[MAX_PATH_LEN];
    int policy_result = 0;
    
    // Get executable path from the file
    int ret = bpf_d_path(&bprm->file->f_path, path, sizeof(path));
    if (ret < 0) {
        // If d_path fails, try to get filename from bprm
        char *filename = BPF_CORE_READ(bprm, filename);
        if (filename) {
            bpf_probe_read_kernel_str(path, sizeof(path), filename);
        } else {
            // Last resort: try to get from dentry
            struct dentry *dentry = BPF_CORE_READ(bprm->file, f_path.dentry);
            const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
            bpf_probe_read_kernel_str(path, sizeof(path), name);
        }
    }
    
    // Check policy for this path (arguments temporarily disabled due to BPF size limits)
    policy_result = check_exec_policy(path);
    
    // Reserve ringbuf space
    event = bpf_ringbuf_reserve(&exec_events, sizeof(*event), 0);
    if (!event) {
        // Still need to enforce policy even if we can't log
        return policy_result ? 0 : -13; // -EACCES = 13
    }

    // Get process information
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->_padding = 0;  // Initialize padding field
    event->timestamp = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    
    // Get process command name
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // Copy path to event efficiently
    __builtin_memcpy(event->path, path, MAX_PATH_LEN);
    event->path[MAX_PATH_LEN-1] = '\0'; // Ensure null termination
    
    // Look up correlated arguments from tracepoint hook
    u32 pid = pid_tgid >> 32;
    struct pending_exec_args *pending = bpf_map_lookup_elem(&pending_exec_args, &pid);
    
    if (pending) {
        // Use detailed arguments from tracepoint
        event->argc = pending->argc;
        
        // Copy detailed args efficiently
        __builtin_memcpy(event->detailed_args, pending->detailed_args, sizeof(event->detailed_args));
        
        // Clean up correlation entry (critical!)
        bpf_map_delete_elem(&pending_exec_args, &pid);
        
    } else {
        // No correlation data found - fallback to empty args
        event->argc = 0;
        __builtin_memset(event->detailed_args, 0, sizeof(event->detailed_args));
    }
    
    // Set result based on policy
    event->result = policy_result ? 0 : -13; // 0 = allowed, -EACCES = denied

    bpf_ringbuf_submit(event, 0);
    
    // Return policy decision: 0 = allow, negative = deny
    return policy_result ? 0 : -13; // -EACCES = 13
}

// Tracepoint hook for detailed argument capture and correlation storage
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct sys_enter_execve_args *ctx)
{
    // Check if we should monitor this cgroup
    if (!is_exec_target_cgroup()) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // Prepare correlation data for LSM hook
    struct pending_exec_args pending = {};
    pending.timestamp = bpf_ktime_get_ns();
    pending.argc = 0;
    
    // Store original path from tracepoint
    if (ctx->filename) {
        bpf_probe_read_user_str(pending.original_path, sizeof(pending.original_path), ctx->filename);
    }
    
    // Capture detailed arguments (up to 6 args)
    if (ctx->argv) {
        #pragma clang loop unroll(disable)
        for (int i = 0; i < 6; i++) {
            char *arg_ptr;
            
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &ctx->argv[i]) != 0) {
                break;
            }
            
            if (!arg_ptr) {
                break;
            }
            
            if (bpf_probe_read_user_str(pending.detailed_args[i], 24, arg_ptr) <= 0) {
                break;
            }
            
            pending.argc++;
        }
    }
    
    // Fallback if no args captured
    if (pending.argc == 0) {
        pending.argc = 1;
        bpf_get_current_comm(pending.detailed_args[0], 16);
    }
    
    // Store in correlation map for LSM hook to find
    bpf_map_update_elem(&pending_exec_args, &pid, &pending, BPF_ANY);
    
    return 0;
}
