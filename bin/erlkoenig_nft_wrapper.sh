#!/bin/sh
# erlkoenig_nft wrapper — loads cookie, then delegates to the relx release script.
#
# This wrapper ensures that bin/erlkoenig_nft is self-consistent:
# foreground, daemon, eval, rpc, stop, remote_console, pid all work
# without requiring RELX_COOKIE to be set externally.
#
# Cookie resolution order:
#   1. RELX_COOKIE environment variable (explicit, e.g. from systemd)
#   2. Cookie file at $RELEASE_ROOT/cookie (default)
#
# If neither exists, abort with a clear error message.

set -e

# Resolve our own location
SCRIPT=$(readlink -f "$0" 2>/dev/null || echo "$0")
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT")" && pwd -P)"
RELEASE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

# ── Cookie ──────────────────────────────────────────────────────────

if [ -z "$RELX_COOKIE" ]; then
    COOKIE_FILE="$RELEASE_ROOT/cookie"
    if [ -f "$COOKIE_FILE" ] && [ -r "$COOKIE_FILE" ]; then
        RELX_COOKIE="$(cat "$COOKIE_FILE")"
        export RELX_COOKIE
    else
        echo "FATAL: No Erlang cookie found." >&2
        echo "" >&2
        echo "  The cookie is required for all operations (start, stop, eval, rpc)." >&2
        echo "" >&2
        echo "  Option 1: Generate a cookie file:" >&2
        echo "    head -c 32 /dev/urandom | base64 | tr -d '/+=\\n' | head -c 32 > $RELEASE_ROOT/cookie" >&2
        echo "    chmod 440 $RELEASE_ROOT/cookie" >&2
        echo "" >&2
        echo "  Option 2: Set the environment variable:" >&2
        echo "    export RELX_COOKIE=your_secret_cookie_here" >&2
        exit 1
    fi
fi

# ── Delegate to relx release script ────────────────────────────────

exec "$RELEASE_ROOT/bin/_release" "$@"
