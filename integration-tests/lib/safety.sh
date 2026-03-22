#!/usr/bin/env bash
# Safety module: SSH protection + timeout + cleanup
# Source this file, don't execute it.

set -euo pipefail

REMOTE="${REMOTE:-erlkoenig-2__root}"
NFT_DIR="/opt/erlkoenig_nft"
BACKUP_CONFIG="/tmp/erlkoenig_nft_backup.term"
SAFETY_TIMEOUT="${SAFETY_TIMEOUT:-60}"

# ── SSH Safety ──────────────────────────────────────────────────────
# Verify SSH is reachable before and after each test.
# If SSH dies, we have no way to recover remotely.

check_ssh() {
    if ! ssh -o ConnectTimeout=5 "$REMOTE" "true" 2>/dev/null; then
        echo "FATAL: SSH to $REMOTE unreachable!" >&2
        return 1
    fi
}

# ── Backup / Restore ───────────────────────────────────────────────

backup_config() {
    echo "  Backing up current config..."
    ssh "$REMOTE" "cp $NFT_DIR/etc/firewall.term $BACKUP_CONFIG"
}

restore_config() {
    echo "  Restoring original config..."
    ssh "$REMOTE" "cp $BACKUP_CONFIG $NFT_DIR/etc/firewall.term"
    reload_firewall
}

# ── Reload ──────────────────────────────────────────────────────────

reload_firewall() {
    ssh "$REMOTE" "$NFT_DIR/bin/erlkoenig_nft eval 'erlkoenig_nft:reload()'"
}

# ── Emergency Flush ─────────────────────────────────────────────────
# If everything goes wrong, flush all nft rules (SSH survives because
# kernel default policy is accept when no rules exist).

emergency_flush() {
    echo "EMERGENCY: Flushing all nft rules!" >&2
    ssh -o ConnectTimeout=5 "$REMOTE" "nft flush ruleset" 2>/dev/null || true
}

# ── Timeout Wrapper ─────────────────────────────────────────────────
# Run a command with timeout. If it exceeds $SAFETY_TIMEOUT seconds,
# restore the original config.

run_with_timeout() {
    local cmd="$1"
    if ! timeout "$SAFETY_TIMEOUT" bash -c "$cmd"; then
        echo "TIMEOUT: Test exceeded ${SAFETY_TIMEOUT}s, restoring config..." >&2
        restore_config
        return 1
    fi
}

# ── Trap ────────────────────────────────────────────────────────────
# On any exit (error, interrupt, etc.), restore the original config.

setup_trap() {
    trap 'echo ""; echo "Interrupted — restoring config..."; restore_config; exit 130' INT TERM
    trap 'restore_config' EXIT
}
