#!/bin/sh
set -e

MITM_PORT=${1:-18000}
PROXY_MARK=${PROXY_MARK:-0x2000}

iptables_cmd() {
    iptables -w "$@"
}

ensure_rule() {
    if iptables_cmd "$@" 2>/dev/null; then
        return 0
    fi
    return 1
}

if ! ensure_rule -t nat -C OUTPUT -p tcp --dport "$MITM_PORT" -j RETURN; then
    iptables_cmd -t nat -I OUTPUT 1 -p tcp --dport "$MITM_PORT" -j RETURN
fi

if ! ensure_rule -t nat -C OUTPUT -m mark --mark "$PROXY_MARK" -j RETURN; then
    iptables_cmd -t nat -I OUTPUT 2 -m mark --mark "$PROXY_MARK" -j RETURN
fi

if ! ensure_rule -t nat -C OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports "$MITM_PORT"; then
    iptables_cmd -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports "$MITM_PORT"
fi

if ! ensure_rule -t nat -C OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$MITM_PORT"; then
    iptables_cmd -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$MITM_PORT"
fi

if ! ensure_rule -t mangle -C OUTPUT -p udp --dport 443 -j DROP; then
    iptables_cmd -t mangle -A OUTPUT -p udp --dport 443 -j DROP
fi
