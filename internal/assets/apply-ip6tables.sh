#!/bin/sh
set -e

# Mirror of apply-iptables.sh, but for ip6tables
# Usage: sh -s <MITM_PORT>

MITM_PORT=${1:-18000}
CONTROL_PORT=${2:-}
PROXY_MARK=${PROXY_MARK:-0x2000}

ip6tables_cmd() {
    ip6tables -w "$@"
}

ensure_rule() {
    if ip6tables_cmd "$@" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Early returns to avoid loops and honor proxy mark
if ! ensure_rule -t nat -C OUTPUT -p tcp --dport "$MITM_PORT" -j RETURN; then
    ip6tables_cmd -t nat -I OUTPUT 1 -p tcp --dport "$MITM_PORT" -j RETURN
fi

# Make the OUTPUT chain’s second rule a guard that matches packets carrying
# the connection mark value $PROXY_MARK
#
# Net effect: any packet the proxy already marked (so it won’t be re-intercepted)
# immediately returns from the NAT chain, preventing loops or re-redirection
if ! ensure_rule -t nat -C OUTPUT -m mark --mark "$PROXY_MARK" -j RETURN; then
    ip6tables_cmd -t nat -I OUTPUT 2 -m mark --mark "$PROXY_MARK" -j RETURN
fi

# HTTP/HTTPS redirects over TCPv6
if ! ensure_rule -t nat -C OUTPUT -p tcp -j REDIRECT --to-ports "$MITM_PORT"; then
    ip6tables_cmd -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports "$MITM_PORT"
fi

# Kill QUIC over IPv6 to force TLS over TCP through the MITM
if ! ensure_rule -t mangle -C OUTPUT -p udp --dport 443 -j DROP; then
    ip6tables_cmd -t mangle -A OUTPUT -p udp --dport 443 -j DROP
fi

# Block access to the ControlUI from target container
if [ -n "$CONTROL_PORT" ]; then
    if ! ensure_rule -t filter -C OUTPUT -o lo -d ::1 -p tcp --dport "$CONTROL_PORT" -j REJECT --reject-with tcp-reset; then
        ip6tables_cmd -t filter -A OUTPUT -o lo -d ::1 -p tcp --dport "$CONTROL_PORT" -j REJECT --reject-with tcp-reset
    fi
fi
