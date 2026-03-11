#!/bin/sh
# Source this file to add erlkoenig_nft to your PATH:
#   echo 'source /opt/erlkoenig_nft/env.sh' >> ~/.bashrc
#
# Or for the development install:
#   source /path/to/erlkoenig_nft/env.sh

ERLKOENIG_ROOT="$(cd "$(dirname "$0")" && pwd)"
export PATH="$ERLKOENIG_ROOT/bin:$PATH"

# DSL CLI (if built)
if [ -x "$ERLKOENIG_ROOT/dsl/erlkoenig" ]; then
    export PATH="$ERLKOENIG_ROOT/dsl:$PATH"
elif [ -x "$ERLKOENIG_ROOT/erlkoenig" ]; then
    export PATH="$ERLKOENIG_ROOT:$PATH"
fi

export ERLKOENIG_SOCKET="${ERLKOENIG_SOCKET:-/var/run/erlkoenig.sock}"
