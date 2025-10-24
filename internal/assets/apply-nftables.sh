#!/bin/sh
set -e

# Apply nftables rules for both IPv4 and IPv6 with idempotency.
# - NAT OUTPUT redirect for tcp/{80,443} to MITM_PORT
# - Early return for MITM_PORT and PROXY_MARK to avoid loops
# - Drop QUIC (udp/443) via inet route hook

MITM_PORT=${1:-18000}
PROXY_MARK=${PROXY_MARK:-0x2000}
NFT=${NFT:-nft}

nft_cmd() {
    "$NFT" "$@"
}

ensure_table() {
    fam=$1; tbl=$2
    if ! nft_cmd list table "$fam" "$tbl" >/dev/null 2>&1; then
        nft_cmd add table "$fam" "$tbl"
    fi
}

ensure_chain() {
    fam=$1; tbl=$2; chain=$3; shift 3
    # Remaining args are chain definition words, e.g. { type nat hook output priority -100; }
    if ! nft_cmd list chain "$fam" "$tbl" "$chain" >/dev/null 2>&1; then
        nft_cmd add chain "$fam" "$tbl" "$chain" "$@"
    fi
}

ensure_rule() {
    fam=$1; tbl=$2; chain=$3; shift 3
    comment=$1; shift 1
    # Remaining args are rule words
    if nft_cmd list chain "$fam" "$tbl" "$chain" 2>/dev/null | grep -F "comment \"$comment\"" >/dev/null; then
        return 0
    fi
    nft_cmd add rule "$fam" "$tbl" "$chain" "$@" comment "$comment"
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

