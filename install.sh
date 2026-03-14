#!/bin/sh
# erlkoenig_nft installer / updater
# Usage: sudo sh install.sh --version v0.6.0 [--prefix /opt/erlkoenig_nft] [--no-systemd] [--force]
set -eu

REPO="iRaffnix/erlkoenig_nft"
PREFIX="/opt/erlkoenig_nft"
VERSION=""
INSTALL_SYSTEMD=true
FORCE=false

# --- Parse arguments ---

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)      PREFIX="$2"; shift 2 ;;
        --version)     VERSION="$2"; shift 2 ;;
        --no-systemd)  INSTALL_SYSTEMD=false; shift ;;
        --force)       FORCE=true; shift ;;
        -h|--help)
            echo "Usage: install.sh --version vX.Y.Z [--prefix DIR] [--no-systemd] [--force]"
            echo ""
            echo "Options:"
            echo "  --version vX.Y.Z  Version to install (required)"
            echo "  --prefix DIR      Installation directory (default: /opt/erlkoenig_nft)"
            echo "  --no-systemd      Skip systemd unit installation"
            echo "  --force           Force reinstall even if same version"
            echo ""
            echo "Example:"
            echo "  sudo sh install.sh --version v0.6.0"
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# --- Helpers ---

info()  { echo "  [*] $*"; }
warn()  { echo "  [!] $*" >&2; }
err()   { echo "  [E] $*" >&2; }
ok()    { echo "  [+] $*"; }

# --- Detect architecture ---

detect_target() {
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) err "Unsupported architecture: $arch"; exit 1 ;;
    esac

    # Detect musl vs glibc
    libc="glibc"
    if command -v ldd >/dev/null 2>&1; then
        if ldd --version 2>&1 | grep -qi musl; then
            libc="musl"
        fi
    elif [ -f /etc/alpine-release ]; then
        libc="musl"
    fi

    echo "${arch}-${libc}"
}

# --- Read currently installed version ---

installed_version() {
    if [ -f "$PREFIX/releases/start_erl.data" ]; then
        # Format: "ERTS_VSN APP_VSN"
        awk '{print "v" $2}' "$PREFIX/releases/start_erl.data" 2>/dev/null || true
    elif [ -x /usr/local/bin/erlkoenig ]; then
        /usr/local/bin/erlkoenig version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
    fi
}

# --- Check if daemon is running ---

daemon_is_running() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet erlkoenig_nft 2>/dev/null && return 0
    fi
    # Fallback: check if the beam process is running
    pgrep -f "erlkoenig_nft.*beam" >/dev/null 2>&1 && return 0
    return 1
}

# --- Stop daemon gracefully ---

stop_daemon() {
    info "Stopping erlkoenig_nft daemon ..."
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet erlkoenig_nft 2>/dev/null; then
        systemctl stop erlkoenig_nft 2>/dev/null || true
    fi
    # Also kill any orphan beam processes (e.g. started via relx `start`)
    pkill -f "erlkoenig_nft.*beam" 2>/dev/null || true
    # Kill epmd name reservation so the new instance can register
    epmd -names 2>/dev/null | grep -q erlkoenig_nft && epmd -stop erlkoenig_nft 2>/dev/null || true
    # Wait for clean shutdown (up to 10s)
    i=0
    while [ $i -lt 10 ]; do
        if ! daemon_is_running; then
            ok "Daemon stopped"
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    # Force kill if still alive
    pkill -9 -f "erlkoenig_nft.*beam" 2>/dev/null || true
    pkill -9 epmd 2>/dev/null || true
    sleep 1
    ok "Daemon stopped (forced)"
}

# --- Start daemon ---

start_daemon() {
    info "Starting erlkoenig_nft daemon ..."
    # Ensure epmd name is free before starting
    epmd -stop erlkoenig_nft 2>/dev/null || true
    sleep 1
    if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/erlkoenig_nft.service ]; then
        systemctl start erlkoenig_nft
    else
        "$PREFIX/dist/erlkoenig_nft_run" &
    fi
    # Verify it started
    sleep 3
    if daemon_is_running; then
        ok "Daemon started"
    else
        warn "Daemon may not have started — check: journalctl -u erlkoenig_nft -n 20"
    fi
}

# --- Checks ---

if [ "$(id -u)" -ne 0 ]; then
    err "Installer must be run as root (use sudo)"
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    err "curl is required"
    exit 1
fi

# --- Resolve version and target ---

TARGET=$(detect_target)

if [ -z "$VERSION" ]; then
    err "--version is required"
    echo "  Usage: sudo sh install.sh --version vX.Y.Z" >&2
    echo "  Releases: https://github.com/${REPO}/releases" >&2
    exit 1
fi

# --- Check if update is needed ---

CURRENT=$(installed_version)
IS_UPDATE=false

if [ -d "$PREFIX/bin" ]; then
    IS_UPDATE=true
    if [ -n "$CURRENT" ]; then
        # Normalize: strip leading 'v' for comparison
        cur_norm=$(echo "$CURRENT" | sed 's/^v//')
        new_norm=$(echo "$VERSION" | sed 's/^v//')
        if [ "$cur_norm" = "$new_norm" ] && [ "$FORCE" = false ]; then
            ok "Already at version ${VERSION} — nothing to do (use --force to reinstall)"
            exit 0
        fi
    fi
fi

if [ "$IS_UPDATE" = true ]; then
    echo "Updating erlkoenig_nft: ${CURRENT:-unknown} -> ${VERSION} (${TARGET})"
else
    echo "Installing erlkoenig_nft ${VERSION} (${TARGET})"
fi
echo "  prefix:  ${PREFIX}"
echo ""

# --- Stop daemon if running (before update) ---

DAEMON_WAS_RUNNING=false

if [ "$IS_UPDATE" = true ] && daemon_is_running; then
    DAEMON_WAS_RUNNING=true
    stop_daemon
fi

# --- Backup config before update ---

if [ "$IS_UPDATE" = true ] && [ -f "$PREFIX/etc/firewall.term" ]; then
    BACKUP="$PREFIX/etc/firewall.term.bak.$(date +%Y%m%d-%H%M%S)"
    cp "$PREFIX/etc/firewall.term" "$BACKUP"
    ok "Config backed up: $BACKUP"
fi

# --- Download to temp dir, verify, then extract ---

TMPDIR=$(mktemp -d)
ARCHIVE="erlkoenig_nft-${VERSION}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

info "Downloading ${URL} ..."
if ! curl -fsSL "$URL" -o "$TMPDIR/$ARCHIVE"; then
    err "Download failed. Check that ${VERSION} has a ${TARGET} build."
    err "Available at: https://github.com/${REPO}/releases/tag/${VERSION}"
    # Restart daemon with old version if it was running
    if [ "$DAEMON_WAS_RUNNING" = true ]; then
        warn "Restarting daemon with previous version ..."
        start_daemon
    fi
    exit 1
fi

# Verify the archive is valid
if ! tar tzf "$TMPDIR/$ARCHIVE" >/dev/null 2>&1; then
    err "Downloaded archive is corrupt"
    if [ "$DAEMON_WAS_RUNNING" = true ]; then
        warn "Restarting daemon with previous version ..."
        start_daemon
    fi
    exit 1
fi

ok "Download verified"

# --- Extract (preserve config) ---

mkdir -p "$PREFIX"

# Save config files before extracting
if [ "$IS_UPDATE" = true ]; then
    # Save user-modified files
    for f in etc/firewall.term releases/COOKIE; do
        if [ -f "$PREFIX/$f" ]; then
            cp "$PREFIX/$f" "$TMPDIR/$(basename $f).preserve"
        fi
    done
fi

info "Extracting to ${PREFIX} ..."
if ! tar xzf "$TMPDIR/$ARCHIVE" -C "$PREFIX"; then
    err "Extraction failed"
    if [ "$DAEMON_WAS_RUNNING" = true ]; then
        warn "Restarting daemon with previous version ..."
        start_daemon
    fi
    exit 1
fi

# Restore preserved config files
if [ "$IS_UPDATE" = true ]; then
    for f in etc/firewall.term releases/COOKIE; do
        base=$(basename "$f")
        if [ -f "$TMPDIR/${base}.preserve" ]; then
            mkdir -p "$PREFIX/$(dirname $f)"
            cp "$TMPDIR/${base}.preserve" "$PREFIX/$f"
        fi
    done
    ok "Config files preserved"
fi

# --- Create config directory ---

mkdir -p "$PREFIX/etc"

# --- Install CLI to PATH ---

ERTS_DIR=""
if [ -f "$PREFIX/bin/erlkoenig" ]; then
    # Use the newest erts directory (in case old ones linger)
    ERTS_DIR=$(ls -dt "$PREFIX"/erts-* 2>/dev/null | head -1)
    if [ -n "$ERTS_DIR" ]; then
        cat > /usr/local/bin/erlkoenig <<WRAPPER
#!/bin/sh
exec "$ERTS_DIR/bin/escript" "$PREFIX/bin/erlkoenig" "\$@"
WRAPPER
        chmod +x /usr/local/bin/erlkoenig
        ok "CLI: /usr/local/bin/erlkoenig (using bundled ERTS)"
    else
        ln -sf "$PREFIX/bin/erlkoenig" /usr/local/bin/erlkoenig
        ok "CLI: /usr/local/bin/erlkoenig (requires system Erlang)"
    fi
fi

# --- Install systemd unit ---

if [ "$INSTALL_SYSTEMD" = true ] && [ -d /etc/systemd/system ]; then
    sed "s|@@PREFIX@@|${PREFIX}|g" "$PREFIX/dist/erlkoenig_nft.service" \
        > /etc/systemd/system/erlkoenig_nft.service
    systemctl daemon-reload
    ok "Systemd unit: erlkoenig_nft.service"
fi

# --- Install shell completions ---

COMPLETIONS_INSTALLED=false
if [ -d /etc/bash_completion.d ] && [ -x /usr/local/bin/erlkoenig ]; then
    /usr/local/bin/erlkoenig completions bash > /etc/bash_completion.d/erlkoenig 2>/dev/null && \
        COMPLETIONS_INSTALLED=true && ok "Bash completions: /etc/bash_completion.d/erlkoenig"
fi

# --- Generate cookie (first install only) ---

COOKIE_FILE="$PREFIX/releases/COOKIE"
if [ ! -f "$COOKIE_FILE" ]; then
    mkdir -p "$(dirname "$COOKIE_FILE")"
    od -An -tx1 -N16 /dev/urandom | tr -d ' \n' > "$COOKIE_FILE"
    chmod 400 "$COOKIE_FILE"
    ok "Generated Erlang cookie"
fi

# --- Default config (first install only) ---

if [ ! -f "$PREFIX/etc/firewall.term" ]; then
    if [ -f "$PREFIX/bin/erlkoenig" ] && [ -f "$PREFIX/examples/default.exs" ] && [ -n "$ERTS_DIR" ]; then
        info "Compiling default config ..."
        if "$ERTS_DIR/bin/escript" "$PREFIX/bin/erlkoenig" compile \
            "$PREFIX/examples/default.exs" \
            -o "$PREFIX/etc/firewall.term" 2>/dev/null; then
            ok "Default config: $PREFIX/etc/firewall.term"
        else
            warn "Could not compile default config — do it manually: erlkoenig compile"
        fi
    fi
fi

# --- Restart daemon if it was running ---

if [ "$DAEMON_WAS_RUNNING" = true ]; then
    start_daemon
fi

# --- Done ---

echo ""
if [ "$IS_UPDATE" = true ]; then
    echo "Update complete! ${CURRENT:-unknown} -> ${VERSION}"
else
    echo "Installation complete!"
fi
echo ""
echo "  Start:     sudo systemctl start erlkoenig_nft"
echo "  Status:    sudo systemctl status erlkoenig_nft"
echo "  Stop:      sudo systemctl stop erlkoenig_nft"
echo "  Enable:    sudo systemctl enable erlkoenig_nft"
echo "  Verify:    sudo nft list ruleset"
echo ""
echo "  Config:    ${PREFIX}/etc/firewall.term"
echo "  Examples:  erlkoenig examples"
echo "  CLI:       erlkoenig --help"
if [ "$COMPLETIONS_INSTALLED" = true ]; then
    echo ""
    echo "  Completions: /etc/bash_completion.d/erlkoenig"
    echo "  Activate:    source /etc/bash_completion.d/erlkoenig"
fi
if [ "$IS_UPDATE" = false ]; then
    echo ""
    echo "  WARNING: Test in a VM first. See README for safety notes."
fi
