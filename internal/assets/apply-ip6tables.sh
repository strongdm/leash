#!/bin/sh
# Mirror of apply-iptables.sh, but for ip6tables
# Usage: sh -s <MITM_PORT> [LEASH_PORT] [TARGET_CGROUP]
#
# NOTE: We intentionally do NOT use set -e here. Each rule is applied
# individually with error handling to provide better diagnostics and
# allow partial functionality when some ip6tables features aren't available.

MITM_PORT=${1:-18000}
LEASH_PORT=${2:-}
TARGET_CGROUP=${3:-}
PROXY_MARK=${PROXY_MARK:-0x2000}

RULE_ERRORS=0

ip6tables_cmd() {
    ip6tables -w "$@"
}

ensure_rule() {
    if ip6tables_cmd "$@" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Helper to apply a rule with error handling
apply_rule() {
    desc="$1"; shift
    if ! "$@" 2>/dev/null; then
        echo "leash: WARNING: failed to apply ip6tables rule: $desc" >&2
        RULE_ERRORS=$((RULE_ERRORS + 1))
        return 1
    fi
    return 0
}

# Early returns to avoid loops and honor proxy mark
if ! ensure_rule -t nat -C OUTPUT -p tcp --dport "$MITM_PORT" -j RETURN; then
    apply_rule "nat OUTPUT return for MITM port" ip6tables_cmd -t nat -I OUTPUT 1 -p tcp --dport "$MITM_PORT" -j RETURN
fi

if ! ensure_rule -t nat -C OUTPUT -m mark --mark "$PROXY_MARK" -j RETURN; then
    apply_rule "nat OUTPUT return for proxy mark" ip6tables_cmd -t nat -I OUTPUT 2 -m mark --mark "$PROXY_MARK" -j RETURN
fi

# HTTP/HTTPS redirects over TCPv6
if ! ensure_rule -t nat -C OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports "$MITM_PORT"; then
    apply_rule "nat OUTPUT redirect HTTP" ip6tables_cmd -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports "$MITM_PORT"
fi

if ! ensure_rule -t nat -C OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$MITM_PORT"; then
    apply_rule "nat OUTPUT redirect HTTPS" ip6tables_cmd -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$MITM_PORT"
fi

# Kill QUIC over IPv6 to force TLS over TCP through the MITM
if ! ensure_rule -t mangle -C OUTPUT -p udp --dport 443 -j DROP; then
    apply_rule "mangle OUTPUT drop QUIC" ip6tables_cmd -t mangle -A OUTPUT -p udp --dport 443 -j DROP
fi

# Block target container from reaching leashd control plane on any interface (IPv6).
# This prevents a compromised agent from accessing the leashd API.
# SECURITY: This is a REQUIRED security control - failure is fatal.
# Requires --cgroupns=host on the container to see host cgroup paths.
if [ -n "$TARGET_CGROUP" ] && [ -n "$LEASH_PORT" ]; then
    if ! ensure_rule -t filter -C OUTPUT -m cgroup --path "$TARGET_CGROUP" -p tcp --dport "$LEASH_PORT" -j REJECT; then
        if ip6tables_cmd -t filter -A OUTPUT -m cgroup --path "$TARGET_CGROUP" -p tcp --dport "$LEASH_PORT" -j REJECT --reject-with tcp-reset 2>&1; then
            echo "leash: blocked target cgroup $TARGET_CGROUP from reaching control plane port $LEASH_PORT (ip6tables)"
        else
            echo "leash: FATAL: could not apply cgroup-based control plane isolation (IPv6)" >&2
            echo "leash: This security control is required to prevent target container from accessing leashd API" >&2
            exit 1
        fi
    fi
fi

# Report summary and exit successfully even if some rules failed
if [ "$RULE_ERRORS" -gt 0 ]; then
    echo "leash: WARNING: $RULE_ERRORS ip6tables rule(s) failed to apply (IPv6 network interception may be incomplete)" >&2
fi
exit 0

