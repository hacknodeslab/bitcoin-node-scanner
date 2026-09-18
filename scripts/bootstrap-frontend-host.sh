#!/usr/bin/env bash
# Backwards-compatible entry point. The bootstrap now covers backend +
# frontend and lives in scripts/bootstrap-host.sh (same defaults on the EC2
# host: ubuntu, /home/ubuntu/bitcoin-node-scanner). See docs/deploy-frodo.md.
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bootstrap-host.sh" "$@"
