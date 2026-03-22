#!/usr/bin/env bash
# Deploy module: build locally, copy to remote, restart.
# Source this file, don't execute it.

set -euo pipefail

REMOTE="${REMOTE:-erlkoenig-2__root}"
NFT_DIR="/opt/erlkoenig_nft"
REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# ── Build Release ───────────────────────────────────────────────────

build_release() {
    echo "Building erlkoenig_nft release..."
    (cd "$REPO_DIR" && rebar3 as prod tar 2>&1 | tail -1)
}

# ── Build DSL Escript ───────────────────────────────────────────────

build_dsl() {
    echo "Building DSL escript..."
    (cd "$REPO_DIR/dsl" && mix escript.build 2>&1 | tail -1)
}

# ── Deploy Release ──────────────────────────────────────────────────

deploy_release() {
    local tarball
    tarball=$(find "$REPO_DIR/_build/prod/rel" -name '*.tar.gz' | head -1)
    if [ -z "$tarball" ]; then
        echo "ERROR: No release tarball found. Run build_release first." >&2
        return 1
    fi

    echo "Deploying release to $REMOTE..."
    scp -q "$tarball" "$REMOTE:/tmp/erlkoenig_nft_release.tar.gz"
    ssh "$REMOTE" "
        cd $NFT_DIR &&
        tar xzf /tmp/erlkoenig_nft_release.tar.gz &&
        rm /tmp/erlkoenig_nft_release.tar.gz
    "
}

# ── Deploy DSL Escript ──────────────────────────────────────────────

deploy_dsl() {
    echo "Deploying DSL escript to $REMOTE..."
    scp -q "$REPO_DIR/dsl/erlkoenig" "$REMOTE:$NFT_DIR/bin/erlkoenig-dsl"
    ssh "$REMOTE" "chmod +x $NFT_DIR/bin/erlkoenig-dsl"
}

# ── Deploy Config ──────────────────────────────────────────────────

deploy_config() {
    local config_file="$1"
    echo "  Deploying config: $(basename "$config_file")"
    scp -q "$config_file" "$REMOTE:$NFT_DIR/etc/firewall.term"
}

# ── Deploy DSL and Compile on Remote ────────────────────────────────

deploy_dsl_config() {
    local dsl_file="$1"
    echo "  Deploying DSL: $(basename "$dsl_file")"
    scp -q "$dsl_file" "$REMOTE:/tmp/test_firewall.exs"
    ssh "$REMOTE" "
        export PATH=$NFT_DIR/erts-*/bin:\$PATH &&
        $NFT_DIR/bin/erlkoenig-dsl compile /tmp/test_firewall.exs -o $NFT_DIR/etc/firewall.term
    "
}

# ── Restart Service ────────────────────────────────────────────────

restart_service() {
    echo "  Restarting erlkoenig_nft..."
    ssh "$REMOTE" "
        $NFT_DIR/bin/erlkoenig_nft stop 2>/dev/null || true
        sleep 1
        $NFT_DIR/bin/erlkoenig_nft daemon
        sleep 2
    "
}

# ── Full Deploy Cycle ──────────────────────────────────────────────

full_deploy() {
    build_release
    build_dsl
    deploy_release
    deploy_dsl
    restart_service
}
