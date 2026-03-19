#!/bin/sh
# erlkoenig_nft installer / updater
# ==================================
#
# Usage:
#   sudo sh install.sh --version v0.6.0          # download from GitHub
#   sudo sh install.sh --local /path/to/artifacts # install from local dir
#
# Installs to /opt/erlkoenig_nft. Auto-detects private IP for cluster mode.
# Does NOT pipe curl into sh. Download, review, then run.

set -eu

REPO="iRaffnix/erlkoenig_nft"
PREFIX="/opt/erlkoenig_nft"
SERVICE_USER="erlkoenig"
VERSION=""
LOCAL_DIR=""
INSTALL_SYSTEMD=true
FORCE=false
BIND_IP=""

# ── Helpers ──────────────────────────────────────────────

info()  { echo "  [*] $*"; }
warn()  { echo "  [!] $*" >&2; }
err()   { echo "  [E] $*" >&2; }
ok()    { echo "  [+] $*"; }

# ── Argument parsing ─────────────────────────────────────

usage() {
    echo "Usage: sudo sh install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --version VERSION   Download release from GitHub (e.g., v0.6.0)"
    echo "  --local DIR         Install from local directory (CI artifacts)"
    echo "  --prefix DIR        Installation directory (default: /opt/erlkoenig_nft)"
    echo "  --bind IP           Bind distribution/epmd to this IP (default: auto-detect)"
    echo "                      Auto-detection: first 10.x.x.x on a non-loopback interface"
    echo "                      Falls back to 127.0.0.1 (single-node) if no private IP found"
    echo "  --no-systemd        Skip systemd unit installation"
    echo "  --force             Force reinstall even if same version"
    echo "  --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo sh install.sh --version v0.6.0"
    echo "  sudo sh install.sh --version v0.6.0 --bind 10.0.0.1"
    echo "  sudo sh install.sh --local /tmp/artifacts"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)     VERSION="$2"; shift 2 ;;
        --local)       LOCAL_DIR="$2"; shift 2 ;;
        --prefix)      PREFIX="$2"; shift 2 ;;
        --bind)        BIND_IP="$2"; shift 2 ;;
        --no-systemd)  INSTALL_SYSTEMD=false; shift ;;
        --force)       FORCE=true; shift ;;
        --help|-h)     usage ;;
        *)             err "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Checks ───────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    err "Installer must be run as root (use sudo)"
    exit 1
fi

if [ -z "$VERSION" ] && [ -z "$LOCAL_DIR" ]; then
    err "--version or --local is required"
    echo "  Run: sh install.sh --help" >&2
    exit 1
fi

if [ -z "$LOCAL_DIR" ] && ! command -v curl >/dev/null 2>&1; then
    err "curl is required for remote install (or use --local)"
    exit 1
fi

if [ -n "$LOCAL_DIR" ] && [ ! -d "$LOCAL_DIR" ]; then
    err "Local directory not found: $LOCAL_DIR"
    exit 1
fi

# ── Conflict detection ───────────────────────────────────

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

# ── Hostname check (required for -sname distribution) ───

HOSTNAME=$(hostname -s)
if ! getent hosts "$HOSTNAME" >/dev/null 2>&1; then
    warn "Hostname '$HOSTNAME' not resolvable."
    warn "  Add to /etc/hosts: 127.0.0.1 $HOSTNAME"
    warn "  Distribution will not work without this."
fi

# ── Detect architecture ─────────────────────────────────

detect_target() {
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) err "Unsupported architecture: $arch"; exit 1 ;;
    esac

    libc="linux"
    if command -v ldd >/dev/null 2>&1; then
        if ldd --version 2>&1 | grep -qi musl; then
            libc="musl"
        fi
    elif [ -f /etc/alpine-release ]; then
        libc="musl"
    fi

    echo "${arch}-${libc}"
}

# ── Detect private network IP ────────────────────────────

detect_private_ip() {
    ip -4 -o addr show scope global 2>/dev/null \
        | awk '{print $4}' \
        | sed 's|/.*||' \
        | grep '^10\.' \
        | head -1
}

resolve_bind_ip() {
    if [ -n "$BIND_IP" ]; then
        echo "$BIND_IP"
        return
    fi

    __private_ip=$(detect_private_ip)
    if [ -n "$__private_ip" ]; then
        echo "$__private_ip"
    else
        echo "127.0.0.1"
    fi
}

ip_to_erlang_tuple() {
    echo "$1" | awk -F. '{printf "{%s,%s,%s,%s}", $1, $2, $3, $4}'
}

# ── Read installed version ───────────────────────────────

installed_version() {
    if [ -f "$PREFIX/releases/start_erl.data" ]; then
        awk '{print "v" $2}' "$PREFIX/releases/start_erl.data" 2>/dev/null || true
    fi
}

# ── Daemon management ────────────────────────────────────

daemon_is_running() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet erlkoenig_nft 2>/dev/null && return 0
    fi
    if [ -f "$PREFIX/cookie" ] && [ -x "$PREFIX/bin/erlkoenig_nft" ]; then
        RELX_COOKIE=$(cat "$PREFIX/cookie") "$PREFIX/bin/erlkoenig_nft" ping >/dev/null 2>&1 && return 0
    fi
    return 1
}

stop_daemon() {
    info "Stopping erlkoenig_nft daemon ..."

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet erlkoenig_nft 2>/dev/null; then
        systemctl stop erlkoenig_nft 2>/dev/null || true
    fi

    if daemon_is_running; then
        if [ -f "$PREFIX/cookie" ] && [ -x "$PREFIX/bin/erlkoenig_nft" ]; then
            RELX_COOKIE=$(cat "$PREFIX/cookie") "$PREFIX/bin/erlkoenig_nft" stop >/dev/null 2>&1 || true
        fi
    fi

    i=0
    while [ $i -lt 15 ]; do
        if ! daemon_is_running; then
            ok "Daemon stopped"
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done

    pkill -9 -f "beam.*erlkoenig_nft" 2>/dev/null || true
    sleep 1
    ok "Daemon stopped (forced)"
}

start_daemon() {
    info "Starting erlkoenig_nft daemon ..."
    if command -v systemctl >/dev/null 2>&1 && [ -L /etc/systemd/system/erlkoenig_nft.service ]; then
        systemctl start erlkoenig_nft
    else
        if [ -f "$PREFIX/cookie" ] && [ -x "$PREFIX/bin/erlkoenig_nft" ]; then
            RELX_COOKIE=$(cat "$PREFIX/cookie") "$PREFIX/bin/erlkoenig_nft" daemon
        else
            warn "Could not start daemon manually: Binary or cookie missing."
        fi
    fi
    sleep 2
    if daemon_is_running; then
        ok "Daemon started"
    else
        warn "Daemon may not have started — check: journalctl -u erlkoenig_nft -n 20"
    fi
}

# ── Version check ────────────────────────────────────────

TARGET=$(detect_target)
CURRENT=$(installed_version)
IS_UPDATE=false

if [ -d "$PREFIX/bin" ]; then
    IS_UPDATE=true
    if [ -n "$CURRENT" ] && [ -n "$VERSION" ]; then
        cur_norm=$(echo "$CURRENT" | sed 's/^v//')
        new_norm=$(echo "$VERSION" | sed 's/^v//')
        if [ "$cur_norm" = "$new_norm" ] && [ "$FORCE" = false ]; then
            ok "Already at version ${VERSION} — nothing to do (use --force to reinstall)"
            exit 0
        fi
    fi
fi

if [ "$IS_UPDATE" = true ]; then
    echo "Updating erlkoenig_nft: ${CURRENT:-unknown} -> ${VERSION:-local} (${TARGET})"
else
    echo "Installing erlkoenig_nft ${VERSION:-local} (${TARGET})"
fi
echo "  prefix: ${PREFIX}"
echo ""

# ── Stop daemon if running ───────────────────────────────

DAEMON_WAS_RUNNING=false

if [ "$IS_UPDATE" = true ] && daemon_is_running; then
    DAEMON_WAS_RUNNING=true
    stop_daemon
fi

# ── Acquire artifact ─────────────────────────────────────

TMPDIR=$(mktemp -d)
ARTIFACT=""

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

if [ -n "$LOCAL_DIR" ]; then
    info "Installing from local artifacts: $LOCAL_DIR"
    ARTIFACT=$(find "$LOCAL_DIR" -name 'erlkoenig_nft-*.tar.gz' -print -quit 2>/dev/null || true)
    if [ -z "$ARTIFACT" ]; then
        err "No erlkoenig_nft-*.tar.gz found in $LOCAL_DIR"
        exit 1
    fi
    if [ -z "$VERSION" ]; then
        VERSION=$(tar xzf "$ARTIFACT" -O releases/start_erl.data 2>/dev/null | awk '{print "v"$2}' || true)
    fi
    ok "Found: $(basename "$ARTIFACT")"
else
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

if ! tar tzf "$ARTIFACT" >/dev/null 2>&1; then
    err "Release archive is corrupt"
    if [ "$DAEMON_WAS_RUNNING" = true ]; then
        warn "Restarting daemon with previous version ..."
        start_daemon
    fi
    exit 1
fi

ok "Artifact verified"

# ── Preserve cookie + firewall config before extraction ──

if [ "$IS_UPDATE" = true ]; then
    [ -f "$PREFIX/cookie" ] && cp "$PREFIX/cookie" "$TMPDIR/cookie.preserve"
    [ -f "$PREFIX/etc/firewall.term" ] && cp "$PREFIX/etc/firewall.term" "$TMPDIR/firewall.term.preserve"
fi

# ── Clean extraction (updates) ──────────────────────────

if [ "$IS_UPDATE" = true ]; then
    info "Removing old release files ..."
    rm -rf "${PREFIX:?}/bin" "${PREFIX:?}/erts-"* "${PREFIX:?}/lib" "${PREFIX:?}/releases" "${PREFIX:?}/dist"
fi

# ── Extract ──────────────────────────────────────────────

mkdir -p "$PREFIX"

info "Extracting to ${PREFIX} ..."
if ! tar xzf "$ARTIFACT" -C "$PREFIX"; then
    err "Extraction failed"
    if [ "$DAEMON_WAS_RUNNING" = true ]; then
        warn "Restarting daemon with previous version ..."
        start_daemon
    fi
    exit 1
fi

# Restore preserved files
if [ -f "$TMPDIR/cookie.preserve" ]; then
    cp "$TMPDIR/cookie.preserve" "$PREFIX/cookie"
    ok "Cookie preserved"
fi
if [ -f "$TMPDIR/firewall.term.preserve" ]; then
    mkdir -p "$PREFIX/etc"
    cp "$TMPDIR/firewall.term.preserve" "$PREFIX/etc/firewall.term"
    ok "Firewall config preserved"
fi

# ── Service user ─────────────────────────────────────────

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    ok "Service user '$SERVICE_USER' created"
fi

# ── File permissions ─────────────────────────────────────

chown -R root:"$SERVICE_USER" "$PREFIX"
chmod 750 "$PREFIX"
[ -f "$PREFIX/bin/erlkoenig_nft" ] && chmod 755 "$PREFIX/bin/erlkoenig_nft"
[ -f "$PREFIX/bin/erlkoenig" ] && chmod 755 "$PREFIX/bin/erlkoenig"
[ -f "$PREFIX/dist/erlkoenig_nft.service" ] && chmod 644 "$PREFIX/dist/erlkoenig_nft.service"

# releases dir must be writable — relx generates vm.args from vm.args.src
REL_VSN_DIR=$(ls -d "$PREFIX"/releases/*/start.boot 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true)
if [ -n "$REL_VSN_DIR" ]; then
    chown "$SERVICE_USER":"$SERVICE_USER" "$REL_VSN_DIR"
    chmod 750 "$REL_VSN_DIR"
fi

# etc dir for firewall config
mkdir -p "$PREFIX/etc"
chown "$SERVICE_USER":"$SERVICE_USER" "$PREFIX/etc"

ok "Permissions set"

# ── Fix escript shebang to use bundled ERTS ──────────────

ERTS_BIN=$(ls -d "$PREFIX"/erts-*/bin 2>/dev/null | head -1)
if [ -n "$ERTS_BIN" ] && [ -f "$PREFIX/bin/erlkoenig" ]; then
    sed -i "1s|.*|#!${ERTS_BIN}/escript|" "$PREFIX/bin/erlkoenig"
    ok "CLI shebang: ${ERTS_BIN}/escript"
fi

# ── Symlink CLI into PATH ────────────────────────────────

if [ -f "$PREFIX/bin/erlkoenig" ]; then
    ln -sf "$PREFIX/bin/erlkoenig" /usr/local/bin/erlkoenig-nft
    ok "CLI symlink: /usr/local/bin/erlkoenig-nft"
fi

# ── Configure bind IP (distribution + epmd) ──────────────

RESOLVED_IP=$(resolve_bind_ip)
ERLANG_TUPLE=$(ip_to_erlang_tuple "$RESOLVED_IP")

if [ "$RESOLVED_IP" = "127.0.0.1" ]; then
    info "Bind IP: $RESOLVED_IP (single-node mode)"
else
    ok "Bind IP: $RESOLVED_IP (cluster-ready)"
fi

# Patch sys.config: inet_dist_use_interface
if [ -n "$REL_VSN_DIR" ] && [ -f "$REL_VSN_DIR/sys.config" ]; then
    sed -i "s/{inet_dist_use_interface, {[0-9,]*}}/{inet_dist_use_interface, $ERLANG_TUPLE}/" \
        "$REL_VSN_DIR/sys.config"
    ok "sys.config: inet_dist_use_interface -> $ERLANG_TUPLE"
fi

# Patch systemd unit: ERL_EPMD_ADDRESS
if [ -f "$PREFIX/dist/erlkoenig_nft.service" ]; then
    sed -i "s/ERL_EPMD_ADDRESS=.*/ERL_EPMD_ADDRESS=$RESOLVED_IP/" \
        "$PREFIX/dist/erlkoenig_nft.service"
    ok "systemd unit: ERL_EPMD_ADDRESS -> $RESOLVED_IP"
fi

# ── Disable cloud-init /etc/hosts management ────────────

if [ -d /etc/cloud/cloud.cfg.d ]; then
    if [ ! -f /etc/cloud/cloud.cfg.d/99-keep-hosts.cfg ]; then
        echo "manage_etc_hosts: false" > /etc/cloud/cloud.cfg.d/99-keep-hosts.cfg
        ok "cloud-init: /etc/hosts management disabled"
    fi
fi

# ── Generate cookie (first install only) ─────────────────

if [ ! -f "$PREFIX/cookie" ]; then
    head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c 32 > "$PREFIX/cookie"
    ok "Cookie generated"
fi
chown root:"$SERVICE_USER" "$PREFIX/cookie"
chmod 440 "$PREFIX/cookie"

# ── Systemd ─────────────────────────────────────────────

if [ "$INSTALL_SYSTEMD" = true ] && [ -d /etc/systemd/system ]; then
    ln -sf "$PREFIX/dist/erlkoenig_nft.service" /etc/systemd/system/erlkoenig_nft.service
    systemctl daemon-reload
    ok "Systemd unit: erlkoenig_nft.service (symlinked)"
fi

# ── No default firewall config ───────────────────────────
# The installer does NOT compile a default config automatically.
# A misconfigured firewall (wrong interface, drop policy) can lock
# you out of the server. Create and review your config manually:
#
#   erlkoenig-nft compile examples/default.exs -o /opt/erlkoenig_nft/etc/firewall.term
#   # Review the config, adjust interface names (eth0 vs ens3 etc.)
#   systemctl restart erlkoenig_nft

# ── Shell completions ────────────────────────────────────

if [ -d /etc/bash_completion.d ] && [ -x /usr/local/bin/erlkoenig-nft ]; then
    /usr/local/bin/erlkoenig-nft completions bash > /etc/bash_completion.d/erlkoenig-nft 2>/dev/null && \
        ok "Bash completions installed"
fi

# ── Restart daemon if it was running ─────────────────────

if [ "$DAEMON_WAS_RUNNING" = true ]; then
    start_daemon
fi

# ── Done ─────────────────────────────────────────────────

echo ""
if [ "$IS_UPDATE" = true ]; then
    echo "Update complete! ${CURRENT:-unknown} -> ${VERSION:-local}"
else
    echo "Installation complete!"
fi
echo ""
echo "  Start:     sudo systemctl start erlkoenig_nft"
echo "  Status:    sudo systemctl status erlkoenig_nft"
echo "  Stop:      sudo systemctl stop erlkoenig_nft"
echo "  Enable:    sudo systemctl enable erlkoenig_nft"
echo "  Verify:    sudo nft list ruleset"
echo "  Shell:     sudo RELX_COOKIE=\$(sudo cat $PREFIX/cookie) $PREFIX/bin/erlkoenig_nft remote_console"
echo ""
echo "  Config:    $PREFIX/etc/firewall.term"
echo "  CLI:       erlkoenig-nft --help"
echo "  Bind IP:   $RESOLVED_IP"
echo ""
if [ "$RESOLVED_IP" != "127.0.0.1" ]; then
    echo "  NOTE: Distribution bound to $RESOLVED_IP (cluster-ready, port 9101)."
    echo "        Ensure /etc/hosts maps $(hostname -s) to $RESOLVED_IP"
    echo "        and all cluster nodes share the same cookie."
else
    echo "  NOTE: Running in single-node mode (127.0.0.1)."
    echo "        For cluster: re-run with --bind <private-ip>"
fi
