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
#include <bpf/bpf_endian.h>

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

#define MAX_HOSTNAME_LEN 128
#define MAX_ENTRIES 8192
// BPF verifier-friendly constant bound for policy rules (max 256 with loop-based implementation)
#define MAX_POLICY_RULES 256

// Operation types (must match Go constants)
#define OP_CONNECT 4    // connect

// TCP socket states
#define TCP_ESTABLISHED 1

struct connect_event {
    u32 pid;
    u32 tgid;
    u64 timestamp;
    u64 cgroup_id;
    char comm[16];         // Task command name
    u32 family;            // AF_INET, AF_INET6
    u32 protocol;          // IPPROTO_TCP, IPPROTO_UDP
    u32 dest_ip;           // IPv4 destination (network byte order)
    u16 dest_port;         // Destination port (network byte order)
    s32 result;            // Result of the connect operation (0 = allowed, -EACCES = denied)
    char dest_hostname[MAX_HOSTNAME_LEN]; // Resolved hostname if available
};

// Policy rule structure for BPF map
struct connect_policy_rule {
    u32 action;            // 0 = deny, 1 = allow
    u32 operation;         // Always OP_CONNECT for this program
    u32 dest_ip;           // IPv4 destination (0 = any IP, for hostname rules)
    u16 dest_port;         // Destination port (0 = any port)
    char hostname[MAX_HOSTNAME_LEN]; // Hostname pattern (empty for IP-only rules)
    u32 hostname_len;      // Length of hostname for efficient matching
    u32 is_wildcard;       // 1 if hostname starts with *.
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} connect_events SEC(".maps");

// Map to store the target cgroup ID for filtering (root of subtree to monitor)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} connect_target_cgroup SEC(".maps");

// Map to store multiple cgroup IDs to monitor (for descendants)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u8);
} connect_allowed_cgroups SEC(".maps");

// Map to store policy rules (indexed by rule number, supports up to 256 rules)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, u32);
    __type(value, struct connect_policy_rule);
} connect_policy_rules SEC(".maps");

// Map to store the number of policy rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, s32);
} connect_num_rules SEC(".maps");

// Map to store default policy result (0 = deny, 1 = allow)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} connect_default_policy SEC(".maps");

// DNS hostname cache: IP -> hostname mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);   // IPv4 address
    __type(value, char[MAX_HOSTNAME_LEN]); // Hostname
} dns_cache SEC(".maps");

// Helper to check if current cgroup should be monitored
static __always_inline bool is_connect_target_cgroup(void)
{
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    
    // Check if monitoring is enabled
    u32 key = 0;
    u64 *target_ptr = bpf_map_lookup_elem(&connect_target_cgroup, &key);
    if (!target_ptr || *target_ptr == 0) {
        return false;
    }
    
    // Check if current cgroup is in the allowed set
    u8 *allowed = bpf_map_lookup_elem(&connect_allowed_cgroups, &current_cgroup_id);
    return allowed != NULL;
}

// Helper function for simple string prefix matching (BPF verifier friendly)
static __always_inline bool hostname_starts_with(const char *hostname, const char *prefix, u32 prefix_len)
{
    if (prefix_len == 0) return true;
    
    #pragma clang loop unroll(disable)
    for (u32 i = 0; i < MAX_HOSTNAME_LEN && i < prefix_len; i++) {
        if (hostname[i] != prefix[i]) {
            return false;
        }
        if (hostname[i] == '\0') {
            // hostname is shorter than prefix
            return false;
        }
    }
    return true;
}

// Helper function for wildcard hostname matching (*.example.com)
static __always_inline bool hostname_matches_wildcard(const char *hostname, const char *pattern, u32 pattern_len)
{
    if (pattern_len < 3) return false; // At least "*.x"
    if (pattern[0] != '*' || pattern[1] != '.') return false;
    
    // Extract the suffix (remove "*.")
    const char *suffix = pattern + 2;
    u32 suffix_len = pattern_len - 2;
    
    // Find the hostname length
    u32 hostname_len = 0;
    #pragma clang loop unroll(disable)
    for (u32 i = 0; i < MAX_HOSTNAME_LEN; i++) {
        if (hostname[i] == '\0') {
            hostname_len = i;
            break;
        }
    }
    
    if (hostname_len < suffix_len) return false;
    
    // Check if hostname ends with the suffix
    u32 start_pos = hostname_len - suffix_len;
    #pragma clang loop unroll(disable)
    for (u32 i = 0; i < suffix_len && i < MAX_HOSTNAME_LEN; i++) {
        if (hostname[start_pos + i] != suffix[i]) {
            return false;
        }
    }
    
    // Ensure there's a subdomain (hostname is longer than suffix or has a dot before suffix)
    if (hostname_len == suffix_len) {
        return false; // Exact match, not a subdomain
    }
    if (start_pos > 0 && hostname[start_pos - 1] != '.') {
        return false; // Not a proper subdomain boundary
    }
    
    return true;
}

// Check connect policy for destination IP and port (hostname matching disabled for compatibility)
static __always_inline int check_connect_policy(u32 dest_ip, u16 dest_port)
{
    u32 key = 0;
    s32 *num_rules_ptr = bpf_map_lookup_elem(&connect_num_rules, &key);
    if (!num_rules_ptr) {
        return 0; // Default to deny if no rules loaded
    }
    
    s32 num_rules = *num_rules_ptr;
    if (num_rules <= 0) {
        // No rules, check default policy
        u32 *default_ptr = bpf_map_lookup_elem(&connect_default_policy, &key);
        return default_ptr ? *default_ptr : 0; // Default to deny
    }
    
    // Check each policy rule (rules are sorted by specificity in userspace)
    #pragma clang loop unroll(disable)
    for (u32 i = 0; i < MAX_POLICY_RULES; i++) {
        if (i >= (u32)num_rules) break;
        u32 rule_key = i;
        struct connect_policy_rule *rule = bpf_map_lookup_elem(&connect_policy_rules, &rule_key);
        if (!rule) continue;
        
        // Check IP match (0 means any IP, for hostname-only rules)
        if (rule->dest_ip != 0 && rule->dest_ip != dest_ip) {
            continue;
        }
        
        // Check port match (0 means any port)
        if (rule->dest_port != 0 && rule->dest_port != dest_port) {
            continue;
        }
        
        // Rule matches
        return rule->action;
    }
    
    // No matching rule found, use default policy
    u32 *default_ptr = bpf_map_lookup_elem(&connect_default_policy, &key);
    return default_ptr ? *default_ptr : 0; // Default to deny
}

// Helper function to process network events and apply policy (shared between hooks)
static __always_inline int process_network_event(struct socket *sock, u32 dest_ip, u16 dest_port, u16 family)
{
    struct connect_event *event;
    int policy_result = 0;
    char hostname[MAX_HOSTNAME_LEN] = {0};
    
    // Try to lookup hostname from DNS cache
    char *cached_hostname = bpf_map_lookup_elem(&dns_cache, &dest_ip);
    if (cached_hostname) {
        // Copy cached hostname
        #pragma clang loop unroll(disable)
        for (int i = 0; i < MAX_HOSTNAME_LEN - 1; i++) {
            hostname[i] = cached_hostname[i];
            if (cached_hostname[i] == '\0') break;
        }
        hostname[MAX_HOSTNAME_LEN - 1] = '\0';
    }
    
    // Check policy for this destination (hostname ignored for enforcement)
    policy_result = check_connect_policy(dest_ip, dest_port);
    
    // Reserve ringbuf space for event logging
    event = bpf_ringbuf_reserve(&connect_events, sizeof(*event), 0);
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
    
    // Set network details
    event->family = family;
    event->protocol = BPF_CORE_READ(sock, sk, sk_protocol);
    event->dest_ip = dest_ip;
    event->dest_port = dest_port;
    
    // Copy hostname if available
    #pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_HOSTNAME_LEN; i++) {
        event->dest_hostname[i] = hostname[i];
        if (hostname[i] == '\0') break;
    }
    
    // Set result based on policy
    event->result = policy_result ? 0 : -13; // 0 = allowed, -EACCES = denied
    
    bpf_ringbuf_submit(event, 0);
    
    // Return policy decision: 0 = allow, negative = deny
    return policy_result ? 0 : -13; // -EACCES = 13
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    // Check if we should monitor this cgroup
    if (!is_connect_target_cgroup()) {
        return 0;
    }
    
    u32 dest_ip = 0;
    u16 dest_port = 0;
    
    // Only handle IPv4 for now (address is a USER pointer in this LSM hook)
    u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), &address->sa_family) != 0) {
        return 0;
    }
    if (family != AF_INET) {
        return 0; // Allow non-IPv4 connections
    }
    
    // Extract destination IP and port from sockaddr_in via user read
    struct sockaddr_in uaddr = {};
    if (bpf_probe_read_user(&uaddr, sizeof(uaddr), address) != 0) {
        return 0;
    }
    dest_ip = uaddr.sin_addr.s_addr; // Network byte order
    dest_port = uaddr.sin_port;      // Network byte order
    
    return process_network_event(sock, dest_ip, dest_port, family);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(lsm_sendmsg, struct socket *sock, void *msg, int size)
{
    // Check if we should monitor this cgroup
    if (!is_connect_target_cgroup()) {
        return 0;
    }
    
    // Handle both connectionless sockets (UDP, raw) and any sends with explicit destinations
    // Note: Connected sockets may also be caught here, but that provides additional coverage
    
    u32 dest_ip = 0;
    u16 dest_port = 0;
    u16 family = 0;
    void *msg_name = NULL;
    
    // Read msg_name pointer from msghdr structure
    if (bpf_probe_read_kernel(&msg_name, sizeof(msg_name), msg) != 0) {
        return 0;
    }
    
    // Check if message has destination address
    if (!msg_name) {
        return 0; // No destination address, likely a connected socket
    }
    
    // Read the address family from msg_name (kernel pointer, not user)
    if (bpf_probe_read_kernel(&family, sizeof(family), msg_name) != 0) {
        return 0;
    }
    
    if (family != AF_INET) {
        return 0; // Only handle IPv4
    }
    
    // Extract destination IP and port from sockaddr_in
    struct sockaddr_in kaddr = {};
    if (bpf_probe_read_kernel(&kaddr, sizeof(kaddr), msg_name) != 0) {
        return 0;
    }
    dest_ip = kaddr.sin_addr.s_addr; // Network byte order
    dest_port = kaddr.sin_port;      // Network byte order
    
    return process_network_event(sock, dest_ip, dest_port, family);
}
