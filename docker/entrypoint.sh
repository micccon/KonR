#!/usr/bin/env bash
set -e

# ── CTF mode: connect VPN before anything else ────────────────────────────────
if [ "${CTF_MODE:-0}" = "1" ] && [ -n "${VPN_FILE:-}" ]; then
    VPN_PATH="/vpn/${VPN_FILE}"
    if [ -f "$VPN_PATH" ]; then
        echo "[konr] Starting VPN: $VPN_PATH"
        openvpn --config "$VPN_PATH" --daemon --log /tmp/vpn.log
        # Wait up to 30s for tun0 to appear
        for i in $(seq 1 30); do
            if ip link show tun0 &>/dev/null; then
                echo "[konr] VPN connected (tun0 up)"
                break
            fi
            sleep 1
        done
        if ! ip link show tun0 &>/dev/null; then
            echo "[konr] WARNING: VPN did not come up after 30s — continuing anyway"
        fi
    else
        echo "[konr] WARNING: VPN file not found at $VPN_PATH — skipping"
    fi
fi

# ── Update nuclei templates on first run ──────────────────────────────────────
if [ ! -d "$HOME/.local/nuclei-templates" ] && command -v nuclei &>/dev/null; then
    echo "[konr] Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true
fi

exec "$@"
