#!/bin/sh
# erlkoenig_nft installer
# Usage: curl -fsSL https://raw.githubusercontent.com/iRaffnix/erlkoenig_nft/main/install.sh | sudo sh
#    or: sudo sh install.sh [--prefix /opt/erlkoenig_nft] [--version v0.5.0] [--no-systemd]
set -eu

REPO="iRaffnix/erlkoenig_nft"
PREFIX="/opt/erlkoenig_nft"
VERSION=""
INSTALL_SYSTEMD=true

# --- Parse arguments ---

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)    PREFIX="$2"; shift 2 ;;
        --version)   VERSION="$2"; shift 2 ;;
        --no-systemd) INSTALL_SYSTEMD=false; shift ;;
        -h|--help)
            echo "Usage: install.sh [--prefix DIR] [--version vX.Y.Z] [--no-systemd]"
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# --- Detect architecture ---

detect_target() {
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
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

# --- Detect latest version ---

detect_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o /dev/null -w '%{redirect_url}' \
            "https://github.com/${REPO}/releases/latest" 2>/dev/null \
            | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || true
    fi
}

# --- Checks ---

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: installer must be run as root (use sudo)" >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is required" >&2
    exit 1
fi

# --- Resolve version and target ---

TARGET=$(detect_target)

if [ -z "$VERSION" ]; then
    VERSION=$(detect_version)
fi
if [ -z "$VERSION" ]; then
    echo "Error: could not detect latest version. Use --version vX.Y.Z" >&2
    exit 1
fi

ARCHIVE="erlkoenig_nft-${VERSION}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

echo "Installing erlkoenig_nft ${VERSION} (${TARGET})"
echo "  prefix:  ${PREFIX}"
echo "  archive: ${ARCHIVE}"
echo ""

# --- Download and extract ---

mkdir -p "$PREFIX"

echo "Downloading ${URL} ..."
if ! curl -fsSL "$URL" | tar xz -C "$PREFIX"; then
    echo "Error: download failed. Check that ${VERSION} has a ${TARGET} build." >&2
    echo "Available at: https://github.com/${REPO}/releases/tag/${VERSION}" >&2
    exit 1
fi

# --- Create config directory ---

mkdir -p "$PREFIX/etc"

# --- Install CLI to PATH ---

if [ -f "$PREFIX/bin/erlkoenig" ]; then
    # The escript needs the bundled ERTS, not a system Erlang install.
    ERTS_DIR=$(ls -d "$PREFIX"/erts-* 2>/dev/null | head -1)
    if [ -n "$ERTS_DIR" ]; then
        cat > /usr/local/bin/erlkoenig <<WRAPPER
#!/bin/sh
exec "$ERTS_DIR/bin/escript" "$PREFIX/bin/erlkoenig" "\$@"
WRAPPER
        chmod +x /usr/local/bin/erlkoenig
        echo "Installed CLI: /usr/local/bin/erlkoenig (using bundled ERTS)"
    else
        ln -sf "$PREFIX/bin/erlkoenig" /usr/local/bin/erlkoenig
        echo "Installed CLI: /usr/local/bin/erlkoenig (requires system Erlang)"
    fi
fi

# --- Install systemd unit ---

if [ "$INSTALL_SYSTEMD" = true ] && [ -d /etc/systemd/system ]; then
    sed "s|@@PREFIX@@|${PREFIX}|g" "$PREFIX/dist/erlkoenig_nft.service" \
        > /etc/systemd/system/erlkoenig_nft.service
    systemctl daemon-reload
    echo "Installed systemd unit: erlkoenig_nft.service"
    echo "  (not enabled — see README before enabling at boot)"
fi

# --- Generate cookie ---

COOKIE_FILE="$PREFIX/releases/COOKIE"
if [ ! -f "$COOKIE_FILE" ]; then
    od -An -tx1 -N16 /dev/urandom | tr -d ' \n' > "$COOKIE_FILE"
    chmod 400 "$COOKIE_FILE"
    echo "Generated Erlang cookie: $COOKIE_FILE"
fi

# --- Default config ---

if [ ! -f "$PREFIX/etc/firewall.term" ]; then
    if [ -f "$PREFIX/bin/erlkoenig" ] && [ -f "$PREFIX/examples/default.exs" ]; then
        echo "Compiling default config ..."
        "$PREFIX/bin/erlkoenig" compile \
            "$PREFIX/examples/default.exs" \
            -o "$PREFIX/etc/firewall.term" 2>/dev/null && \
            echo "Default config: $PREFIX/etc/firewall.term (accept-all with blocklists)" || \
            echo "  (skipped — compile the config manually with: erlkoenig compile)"
    fi
fi

# --- Done ---

echo ""
echo "Installation complete!"
echo ""
echo "  Start:     sudo ${PREFIX}/bin/erlkoenig_nft start"
echo "  Status:    sudo ${PREFIX}/bin/erlkoenig_nft status"
echo "  Stop:      sudo ${PREFIX}/bin/erlkoenig_nft stop"
echo "  Verify:    sudo nft list ruleset"
echo ""
echo "  Config:    ${PREFIX}/etc/firewall.term"
echo "  Examples:  ${PREFIX}/examples/"
echo "  CLI:       erlkoenig --help"
echo ""
echo "  WARNING: Test in a VM first. See README for safety notes."
