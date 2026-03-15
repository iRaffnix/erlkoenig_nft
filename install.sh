#!/bin/sh
# erlkoenig_nft installer / updater
# Usage: sudo sh install.sh --version v0.6.0 [--prefix /opt/erlkoenig_nft] [--no-systemd] [--force]
set -eu

REPO="iRaffnix/erlkoenig_nft"
PREFIX="/opt/erlkoenig_nft"
VERSION=""
LOCAL_DIR=""
INSTALL_SYSTEMD=true
FORCE=false

# --- Parse arguments ---

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)      PREFIX="$2"; shift 2 ;;
        --version)     VERSION="$2"; shift 2 ;;
        --local)       LOCAL_DIR="$2"; shift 2 ;;
        --no-systemd)  INSTALL_SYSTEMD=false; shift ;;
        --force)       FORCE=true; shift ;;
        -h|--help)
            echo "Usage: install.sh --version vX.Y.Z [--prefix DIR] [--no-systemd] [--force]"
            echo "       install.sh --local DIR [--prefix DIR] [--no-systemd] [--force]"
            echo ""
            echo "Options:"
            echo "  --version vX.Y.Z  Version to install (from GitHub Releases)"
            echo "  --local DIR       Install from local artifacts directory (CI test)"
            echo "  --prefix DIR      Installation directory (default: /opt/erlkoenig_nft)"
            echo "  --no-systemd      Skip systemd unit installation"
            echo "  --force           Force reinstall even if same version"
            echo ""
            echo "Examples:"
            echo "  sudo sh install.sh --version v0.6.0"
            echo "  gh run download <run-id> -D /tmp/artifacts"
            echo "  sudo sh install.sh --local /tmp/artifacts"
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
    pgrep -f "erlkoenig_nft_run" >/dev/null 2>&1 && return 0
    return 1
}

# --- Stop daemon gracefully ---

stop_daemon() {
    info "Stopping erlkoenig_nft daemon ..."

    # Prefer systemd (sends SIGTERM, waits TimeoutStopSec)
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet erlkoenig_nft 2>/dev/null; then
        systemctl stop erlkoenig_nft 2>/dev/null || true
    fi

    # Fallback: find the PID file or beam process and send SIGTERM
    if daemon_is_running; then
        BEAM_PID=$(pgrep -f "erlkoenig_nft_run" 2>/dev/null | head -1 || true)
        if [ -n "$BEAM_PID" ]; then
            kill -TERM "$BEAM_PID" 2>/dev/null || true
        fi
    fi

    # Wait for clean shutdown (up to 15s — matches systemd TimeoutStopSec)
    i=0
    while [ $i -lt 15 ]; do
        if ! daemon_is_running; then
            ok "Daemon stopped"
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done

    # Force kill only the specific beam process (never kill all epmd)
    pgrep -f "erlkoenig_nft_run" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    sleep 1
    ok "Daemon stopped (forced)"
}

# --- Start daemon ---

start_daemon() {
    info "Starting erlkoenig_nft daemon ..."
    if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/erlkoenig_nft.service ]; then
        systemctl start erlkoenig_nft
    else
        "$PREFIX/bin/erlkoenig_nft_run" &
    fi
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

if [ -z "$LOCAL_DIR" ] && ! command -v curl >/dev/null 2>&1; then
    err "curl is required (or use --local)"
    exit 1
fi

# --- Conflict detection ---

if [ -f /opt/erlkoenig/bin/erlkoenig ] && { [ -f /etc/systemd/system/erlkoenig.service ] || systemctl is-active --quiet erlkoenig 2>/dev/null; }; then
    err "erlkoenig is installed and includes erlkoenig_nft as an OTP application."
    echo "" >&2
    echo "  The firewall is already managed by the erlkoenig service." >&2
    echo "  Installing erlkoenig_nft standalone will cause nftables conflicts." >&2
    echo "" >&2
    echo "  If you want to run erlkoenig_nft standalone instead:" >&2
    echo "    sudo systemctl stop erlkoenig" >&2
    echo "    sudo systemctl disable erlkoenig" >&2
    exit 1
fi

# --- Resolve version and target ---

TARGET=$(detect_target)

if [ -z "$VERSION" ] && [ -z "$LOCAL_DIR" ]; then
    err "--version or --local is required"
    echo "  Usage: sudo sh install.sh --version vX.Y.Z" >&2
    echo "         sudo sh install.sh --local /tmp/artifacts" >&2
    exit 1
fi

if [ -n "$LOCAL_DIR" ] && [ ! -d "$LOCAL_DIR" ]; then
    err "Local directory not found: $LOCAL_DIR"
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

# --- Acquire release artifact ---

TMPDIR=$(mktemp -d)
ARTIFACT=""

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

if [ -n "$LOCAL_DIR" ]; then
    # --- Local mode: find tarball in directory ---
    info "Installing from local artifacts: $LOCAL_DIR"
    ARTIFACT=$(find "$LOCAL_DIR" -name 'erlkoenig_nft-*.tar.gz' -print -quit 2>/dev/null || true)
    if [ -z "$ARTIFACT" ]; then
        err "No erlkoenig_nft-*.tar.gz found in $LOCAL_DIR"
        exit 1
    fi
    # Detect version from tarball content if not given
    if [ -z "$VERSION" ]; then
        VERSION=$(tar xzf "$ARTIFACT" -O releases/start_erl.data 2>/dev/null | awk '{print "v"$2}' || true)
    fi
    ok "Found: $(basename "$ARTIFACT")"
else
    # --- Remote mode: download from GitHub Releases ---
    ARCHIVE="erlkoenig_nft-${VERSION}-${TARGET}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"
    ARTIFACT="$TMPDIR/$ARCHIVE"

    info "Downloading ${ARCHIVE} ..."
    if ! curl -fsSL "$URL" -o "$ARTIFACT"; then
        err "Download failed. Check that ${VERSION} has a ${TARGET} build."
        err "Available at: https://github.com/${REPO}/releases/tag/${VERSION}"
        if [ "$DAEMON_WAS_RUNNING" = true ]; then
            warn "Restarting daemon with previous version ..."
            start_daemon
        fi
        exit 1
    fi
fi

# Verify the archive is valid
if ! tar tzf "$ARTIFACT" >/dev/null 2>&1; then
    err "Release archive is corrupt"
    if [ "$DAEMON_WAS_RUNNING" = true ]; then
        warn "Restarting daemon with previous version ..."
        start_daemon
    fi
    exit 1
fi

ok "Artifact verified"

# --- Extract (preserve config) ---

mkdir -p "$PREFIX"

# Save config files before extracting
if [ "$IS_UPDATE" = true ]; then
    # Save user-modified files
    if [ -f "$PREFIX/etc/firewall.term" ]; then
        cp "$PREFIX/etc/firewall.term" "$TMPDIR/firewall.term.preserve"
    fi
fi

info "Extracting to ${PREFIX} ..."
if ! tar xzf "$ARTIFACT" -C "$PREFIX"; then
    err "Extraction failed"
    if [ "$DAEMON_WAS_RUNNING" = true ]; then
        warn "Restarting daemon with previous version ..."
        start_daemon
    fi
    exit 1
fi

# Restore preserved config files
if [ "$IS_UPDATE" = true ]; then
    if [ -f "$TMPDIR/firewall.term.preserve" ]; then
        mkdir -p "$PREFIX/etc"
        cp "$TMPDIR/firewall.term.preserve" "$PREFIX/etc/firewall.term"
    fi
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
        cat > /usr/local/bin/erlkoenig-nft <<WRAPPER
#!/bin/sh
exec "$ERTS_DIR/bin/escript" "$PREFIX/bin/erlkoenig" "\$@"
WRAPPER
        chmod +x /usr/local/bin/erlkoenig-nft
        ok "CLI: /usr/local/bin/erlkoenig-nft (using bundled ERTS)"
    else
        ln -sf "$PREFIX/bin/erlkoenig" /usr/local/bin/erlkoenig-nft
        ok "CLI: /usr/local/bin/erlkoenig-nft (requires system Erlang)"
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
if [ -d /etc/bash_completion.d ] && [ -x /usr/local/bin/erlkoenig-nft ]; then
    /usr/local/bin/erlkoenig-nft completions bash > /etc/bash_completion.d/erlkoenig-nft 2>/dev/null && \
        COMPLETIONS_INSTALLED=true && ok "Bash completions: /etc/bash_completion.d/erlkoenig-nft"
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
echo "  CLI:       erlkoenig-nft --help"
if [ "$COMPLETIONS_INSTALLED" = true ]; then
    echo ""
    echo "  Completions: /etc/bash_completion.d/erlkoenig-nft"
    echo "  Activate:    source /etc/bash_completion.d/erlkoenig-nft"
fi
if [ "$IS_UPDATE" = false ]; then
    echo ""
    echo "  WARNING: Test in a VM first. See README for safety notes."
fi
