#!/bin/sh
# Source this file to add erlkoenig_nft to your PATH:
#   echo 'source /opt/erlkoenig_nft/env.sh' >> ~/.bashrc
#
# Or for the development install:
#   source /path/to/erlkoenig_nft/env.sh

# Resolve the script's directory, whether executed or sourced
if [ -n "$BASH_SOURCE" ]; then
    ERLKOENIG_ROOT="$(cd "$(dirname "$BASH_SOURCE")" && pwd)"
elif [ -n "$ZSH_VERSION" ]; then
    ERLKOENIG_ROOT="$(cd "$(dirname "${(%):-%x}")" && pwd)"
else
    # Fallback for other shells — assume default install path
    ERLKOENIG_ROOT="/opt/erlkoenig_nft"
fi

export PATH="$ERLKOENIG_ROOT/bin:$PATH"
export ERLKOENIG_SOCKET="${ERLKOENIG_SOCKET:-/var/run/erlkoenig.sock}"
