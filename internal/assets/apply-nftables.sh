#!/bin/sh
# Apply nftables rules for both IPv4 and IPv6 with idempotency.
# - NAT OUTPUT redirect for tcp/{80,443} to MITM_PORT
# - Early return for MITM_PORT and PROXY_MARK to avoid loops
# - Drop QUIC (udp/443) via inet route hook
# - Block target cgroup from reaching leashd control plane
#
# NOTE: We intentionally do NOT use set -e here. Each rule is applied
# individually with error handling to provide better diagnostics and
# allow partial functionality when some nftables features aren't available.

MITM_PORT=${1:-18000}
LEASH_PORT=${2:-}
TARGET_CGROUP=${3:-}
PROXY_MARK=${PROXY_MARK:-0x2000}
NFT=${NFT:-nft}

RULE_ERRORS=0

nft_cmd() {
    "$NFT" "$@"
}

ensure_table() {
    fam=$1; tbl=$2
    if ! nft_cmd list table "$fam" "$tbl" >/dev/null 2>&1; then
        if ! nft_cmd add table "$fam" "$tbl" 2>/dev/null; then
            echo "leash: WARNING: failed to create nftables table $fam $tbl" >&2
            RULE_ERRORS=$((RULE_ERRORS + 1))
            return 1
        fi
    fi
    return 0
}

ensure_chain() {
    fam=$1; tbl=$2; chain=$3; shift 3
    # Remaining args are chain definition words, e.g. { type nat hook output priority -100; }
    if ! nft_cmd list chain "$fam" "$tbl" "$chain" >/dev/null 2>&1; then
        if ! nft_cmd add chain "$fam" "$tbl" "$chain" "$@" 2>/dev/null; then
            echo "leash: WARNING: failed to create nftables chain $fam $tbl $chain" >&2
            RULE_ERRORS=$((RULE_ERRORS + 1))
            return 1
        fi
    fi
    return 0
}

ensure_rule() {
    fam=$1; tbl=$2; chain=$3; shift 3
    comment=$1; shift 1
    # Remaining args are rule words
    if nft_cmd list chain "$fam" "$tbl" "$chain" 2>/dev/null | grep -F "comment \"$comment\"" >/dev/null; then
        return 0
    fi
    if ! nft_cmd add rule "$fam" "$tbl" "$chain" "$@" comment "$comment" 2>/dev/null; then
        echo "leash: WARNING: failed to add nftables rule $comment" >&2
        RULE_ERRORS=$((RULE_ERRORS + 1))
        return 1
    fi
    return 0
}

# IPv4 NAT OUTPUT
ensure_table ip leash
ensure_chain ip leash out_nat { type nat hook output priority -100\; }
ensure_rule ip leash out_nat "leash:return-mitm" tcp dport $MITM_PORT return
ensure_rule ip leash out_nat "leash:return-mark" meta mark $PROXY_MARK return
ensure_rule ip leash out_nat "leash:redir-80-443" tcp dport {80,443} redirect to :$MITM_PORT

# IPv6 NAT OUTPUT
ensure_table ip6 leash6
ensure_chain ip6 leash6 out_nat { type nat hook output priority -100\; }
ensure_rule ip6 leash6 out_nat "leash:return-mitm" tcp dport $MITM_PORT return
ensure_rule ip6 leash6 out_nat "leash:return-mark" meta mark $PROXY_MARK return
ensure_rule ip6 leash6 out_nat "leash:redir-80-443" tcp dport {80,443} redirect to :$MITM_PORT

# inet route hook to drop QUIC for both families
ensure_table inet leash
ensure_chain inet leash out_route { type route hook output priority 0\; }
ensure_rule inet leash out_route "leash:drop-quic" udp dport 443 drop

# Block target cgroup from reaching leashd control plane on any interface.
# This prevents a compromised agent from accessing the leashd API.
# Uses inet family to cover both IPv4 and IPv6.
# SECURITY: This is a REQUIRED security control - failure is fatal.
# Requires --cgroupns=host on the container to see host cgroup paths.
if [ -n "$TARGET_CGROUP" ] && [ -n "$LEASH_PORT" ]; then
    ensure_chain inet leash out_filter { type filter hook output priority 0\; }
    # Check if rule already exists
    if nft_cmd list chain inet leash out_filter 2>/dev/null | grep -F "leash:block-control-plane" >/dev/null; then
        : # Rule already exists, nothing to do
    elif nft_cmd add rule inet leash out_filter socket cgroupv2 level 1 "$TARGET_CGROUP" tcp dport $LEASH_PORT reject with tcp reset comment "leash:block-control-plane" 2>&1; then
        echo "leash: blocked target cgroup $TARGET_CGROUP from reaching control plane port $LEASH_PORT (nftables)"
    else
        echo "leash: FATAL: could not apply cgroup-based control plane isolation (nftables)" >&2
        echo "leash: This security control is required to prevent target container from accessing leashd API" >&2
        exit 1
    fi
fi

# Report summary and exit successfully even if some rules failed
if [ "$RULE_ERRORS" -gt 0 ]; then
    echo "leash: WARNING: $RULE_ERRORS nftables rule(s) failed to apply (network interception may be incomplete)" >&2
fi
exit 0

