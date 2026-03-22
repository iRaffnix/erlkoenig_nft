#!/usr/bin/env bash
#
# erlkoenig_nft Integration Test Runner
#
# Runs all integration tests against a remote machine.
# Builds locally, deploys to remote, verifies via nft -j list ruleset.
#
# Usage:
#   ./run_all.sh                    # Run all tests (deploy first)
#   ./run_all.sh --skip-deploy      # Run tests only (use existing install)
#   ./run_all.sh --test 03          # Run single test
#   REMOTE=myhost__root ./run_all.sh   # Override remote host
#
# Safety:
#   - SSH port 22 is open in EVERY test config
#   - Original config is backed up and restored after all tests
#   - Ctrl+C restores the original config
#   - 60s timeout per test (configurable via SAFETY_TIMEOUT)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export REMOTE="${REMOTE:-erlkoenig-2__root}"
export REPO_DIR="${REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
export SAFETY_TIMEOUT="${SAFETY_TIMEOUT:-60}"

source "$SCRIPT_DIR/lib/safety.sh"
source "$SCRIPT_DIR/lib/deploy.sh"
source "$SCRIPT_DIR/lib/verify.sh"

SKIP_DEPLOY=false
SINGLE_TEST=""
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_TESTS=0

# ── Parse Args ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-deploy) SKIP_DEPLOY=true; shift ;;
        --test) SINGLE_TEST="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Pre-flight ──────────────────────────────────────────────────────

echo "╔══════════════════════════════════════════════════════╗"
echo "║  erlkoenig_nft Integration Tests                     ║"
echo "║  Remote: $REMOTE"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

echo "Pre-flight checks..."
check_ssh || { echo "FATAL: Cannot reach $REMOTE"; exit 1; }
echo "  SSH: OK"

# ── Deploy ──────────────────────────────────────────────────────────

if [ "$SKIP_DEPLOY" = false ]; then
    echo ""
    echo "═══ Build & Deploy ═══"
    full_deploy
    echo "  Deploy: OK"
fi

# ── Backup ──────────────────────────────────────────────────────────

echo ""
echo "═══ Backup Original Config ═══"
backup_config
setup_trap
echo "  Backup: OK"

# ── Run Tests ───────────────────────────────────────────────────────

run_single_test() {
    local test_num="$1"
    local config="$SCRIPT_DIR/configs/${test_num}_*.exs"
    local test_script="$SCRIPT_DIR/tests/${test_num}_*.sh"

    # Resolve globs
    config=$(ls $config 2>/dev/null | head -1)
    test_script=$(ls $test_script 2>/dev/null | head -1)

    if [ -z "$config" ] || [ -z "$test_script" ]; then
        echo "  ERROR: Config or test script not found for test $test_num" >&2
        return 1
    fi

    local test_name
    test_name=$(basename "$config" .exs)

    echo ""
    echo "═══ Test: $test_name ═══"

    # Deploy DSL config (compile on remote)
    deploy_dsl_config "$config"

    # Reload firewall
    echo "  Reloading firewall..."
    reload_firewall
    sleep 1

    # Verify SSH is still alive
    if ! check_ssh; then
        echo "  FATAL: Lost SSH after config reload!" >&2
        emergency_flush
        return 1
    fi

    # Run verification
    reset_counters
    source "$test_script"

    TOTAL_PASS=$((TOTAL_PASS + PASS))
    TOTAL_FAIL=$((TOTAL_FAIL + FAIL))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

echo ""
echo "═══ Running Tests ═══"

if [ -n "$SINGLE_TEST" ]; then
    run_single_test "$SINGLE_TEST"
else
    for test_num in 01 02 03 04 05 06 07 08; do
        run_single_test "$test_num"
    done
fi

# ── Restore (trap handles this, but be explicit) ───────────────────

echo ""
echo "═══ Restore Original Config ═══"
# trap will call restore_config on EXIT

# ── Summary ─────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Results: $TOTAL_TESTS tests, $TOTAL_PASS passed, $TOTAL_FAIL failed"
echo "╚══════════════════════════════════════════════════════╝"

if [ "$TOTAL_FAIL" -gt 0 ]; then
    exit 1
fi
