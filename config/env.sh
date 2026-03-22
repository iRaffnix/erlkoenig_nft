#!/bin/sh
# env.sh — sourced by relx extended start script before every command
# (daemon, foreground, eval, rpc, stop, remote_console, pid)
#
# Makes the release self-consistent: bin/erlkoenig_nft works without
# external prerequisites. systemd is a clean integration path, but
# not a hidden dependency.

# ── Cookie ──────────────────────────────────────────────────────────
# Priority: RELX_COOKIE env var (systemd) > cookie file (manual)
# Hard abort if neither exists — no silent start with empty cookie.

if [ -z "$RELX_COOKIE" ]; then
    COOKIE_FILE="${RELEASE_ROOT_DIR}/cookie"
    if [ -f "$COOKIE_FILE" ] && [ -r "$COOKIE_FILE" ]; then
        RELX_COOKIE="$(cat "$COOKIE_FILE")"
        export RELX_COOKIE
    fi
fi

if [ -z "$RELX_COOKIE" ]; then
    echo "FATAL: No Erlang cookie found." >&2
    echo "" >&2
    echo "  The cookie is required for all operations (start, stop, eval, rpc)." >&2
    echo "" >&2
    echo "  Option 1: Generate a cookie file:" >&2
    echo "    head -c 32 /dev/urandom | base64 | tr -d '/+=\\n' | head -c 32 > ${RELEASE_ROOT_DIR}/cookie" >&2
    echo "    chmod 440 ${RELEASE_ROOT_DIR}/cookie" >&2
    echo "" >&2
    echo "  Option 2: Set the environment variable:" >&2
    echo "    export RELX_COOKIE=your_secret_cookie_here" >&2
    echo "" >&2
    echo "  If installed via install.sh, the cookie should already exist." >&2
    echo "  Check: ls -la ${RELEASE_ROOT_DIR}/cookie" >&2
    exit 1
fi

# ── API Socket ──────────────────────────────────────────────────────
# Default socket path for CLI communication with daemon.

if [ -z "$ERLKOENIG_SOCKET" ]; then
    export ERLKOENIG_SOCKET="/run/erlkoenig_nft/api.sock"
fi
