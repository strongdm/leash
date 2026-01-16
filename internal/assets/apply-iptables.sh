#!/bin/sh
# NOTE: We intentionally do NOT use set -e here. Each rule is applied
# individually with error handling to provide better diagnostics and
# allow partial functionality when some iptables features aren't available.

MITM_PORT=${1:-18000}
LEASH_PORT=${2:-}
TARGET_CGROUP=${3:-}
PROXY_MARK=${PROXY_MARK:-0x2000}

RULE_ERRORS=0

iptables_cmd() {
    iptables -w "$@"
}

ensure_rule() {
    if iptables_cmd "$@" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Helper to apply a rule with error handling
apply_rule() {
    desc="$1"; shift
    if ! "$@" 2>/dev/null; then
        echo "leash: WARNING: failed to apply iptables rule: $desc" >&2
        RULE_ERRORS=$((RULE_ERRORS + 1))
        return 1
    fi
    return 0
}

# Early return for MITM port to avoid loops
if ! ensure_rule -t nat -C OUTPUT -p tcp --dport "$MITM_PORT" -j RETURN; then
    apply_rule "nat OUTPUT return for MITM port" iptables_cmd -t nat -I OUTPUT 1 -p tcp --dport "$MITM_PORT" -j RETURN
fi

# Early return for marked packets to avoid loops
if ! ensure_rule -t nat -C OUTPUT -m mark --mark "$PROXY_MARK" -j RETURN; then
    apply_rule "nat OUTPUT return for proxy mark" iptables_cmd -t nat -I OUTPUT 2 -m mark --mark "$PROXY_MARK" -j RETURN
fi

# Redirect HTTP to MITM proxy
if ! ensure_rule -t nat -C OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports "$MITM_PORT"; then
    apply_rule "nat OUTPUT redirect HTTP" iptables_cmd -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports "$MITM_PORT"
fi

# Redirect HTTPS to MITM proxy
if ! ensure_rule -t nat -C OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$MITM_PORT"; then
    apply_rule "nat OUTPUT redirect HTTPS" iptables_cmd -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$MITM_PORT"
fi

# Drop QUIC to force TLS over TCP through the MITM
if ! ensure_rule -t mangle -C OUTPUT -p udp --dport 443 -j DROP; then
    apply_rule "mangle OUTPUT drop QUIC" iptables_cmd -t mangle -A OUTPUT -p udp --dport 443 -j DROP
fi

# Block target container from reaching leashd control plane on any interface.
# This prevents a compromised agent from accessing the leashd API.
# SECURITY: This is a REQUIRED security control - failure is fatal.
# Requires --cgroupns=host on the container to see host cgroup paths.
if [ -n "$TARGET_CGROUP" ] && [ -n "$LEASH_PORT" ]; then
    if ! ensure_rule -t filter -C OUTPUT -m cgroup --path "$TARGET_CGROUP" -p tcp --dport "$LEASH_PORT" -j REJECT; then
        if iptables_cmd -t filter -A OUTPUT -m cgroup --path "$TARGET_CGROUP" -p tcp --dport "$LEASH_PORT" -j REJECT --reject-with tcp-reset 2>&1; then
            echo "leash: blocked target cgroup $TARGET_CGROUP from reaching control plane port $LEASH_PORT"
        else
            echo "leash: FATAL: could not apply cgroup-based control plane isolation" >&2
            echo "leash: This security control is required to prevent target container from accessing leashd API" >&2
            exit 1
        fi
    fi
fi

# Report summary and exit successfully even if some rules failed
# (we log warnings above for failed rules)
if [ "$RULE_ERRORS" -gt 0 ]; then
    echo "leash: WARNING: $RULE_ERRORS iptables rule(s) failed to apply (network interception may be incomplete)" >&2
fi
exit 0
