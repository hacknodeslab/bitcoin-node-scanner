#!/bin/bash

################################################################################
# Bitcoin Node Security Scanner - Optimized Scan Script
# Thin wrapper around `python -m src.scanner`: loads .env, activates the venv,
# forwards all arguments, and shows the credit-tracker report after a scan.
################################################################################

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_ROOT/venv"

cd "$PROJECT_ROOT"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    cat << EOF
Usage: $0 [SCANNER_OPTIONS]

All arguments are forwarded to: python -m src.scanner

Common options:
    --quick             Quick scan (cache + enrichment limited to 50 nodes)
    --no-cache          Disable the node cache
    --no-enrich         Skip host enrichment (cheapest)
    --max-enrich NUM    Max nodes to enrich (default: 100)
    --check-credits     Show remaining Shodan credits and exit
    --ips FILE          Credit-free host lookups from an IP list
    --api-key KEY       Shodan API key (overrides SHODAN_API_KEY)

Examples:
    $0 --quick
    $0 --no-cache --max-enrich 100
    $0 --check-credits
    $0 --ips data/peers/peers.txt

After a scan, the Shodan credit usage report is shown
(src/credit_tracker.py). See OPTIMIZATIONS_README.md for details.
EOF
    exit 0
fi

# Load .env if present
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$PROJECT_ROOT/.env"
    set +a
fi

# Activate virtualenv if present
if [[ -f "$VENV_DIR/bin/activate" ]]; then
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
fi

CHECK_CREDITS_ONLY="false"
for arg in "$@"; do
    if [[ "$arg" == "--check-credits" ]]; then
        CHECK_CREDITS_ONLY="true"
    fi
done

python -m src.scanner "$@"

# Show credit usage report after a scan (not for --check-credits)
if [[ "$CHECK_CREDITS_ONLY" == "false" ]]; then
    echo ""
    python -m src.credit_tracker --report || true
fi
