#!/bin/bash

################################################################################
# Bitcoin Node Security Scanner - Optimized Scan Script
# Credit-efficient scanning with automatic tracking
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OPTIMIZED_SCANNER="$PROJECT_ROOT/src/optimized_scanner.py"
CREDIT_TRACKER="$PROJECT_ROOT/src/credit_tracker.py"
VENV_DIR="$PROJECT_ROOT/venv"

################################################################################
# Functions
################################################################################

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║      Bitcoin Node Scanner - OPTIMIZED (Credit-Efficient)       ║
║                    HackNodes Lab                               ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Optimization Features:
  ✅ Optimized queries (5 vs 9 - saves 44%)
  ✅ Smart caching (saves 70-80% on re-scans)
  ✅ Selective enrichment (only critical nodes)
  ✅ Automatic credit tracking

Options:
    -h, --help              Show this help
    -q, --quick             Quick scan (cache + 50 enrichments)
    -m, --medium            Medium scan (cache + 75 enrichments)
    -f, --full              Full scan (cache + 100 enrichments)
    -c, --check-credits     Check credits and usage stats
    --no-cache              Disable caching
    --max-enrich NUM        Max enrichments (default: 100)
    -k, --api-key KEY       Shodan API key

Examples:
    $0 --quick              # Fast, efficient scan
    $0 --full               # Comprehensive scan
    $0 --check-credits      # View credits and usage
    $0 --no-cache           # Fresh scan (no cache)

Credit Savings:
    Without optimization:   ~9 query + ~900 scan credits
    With optimization:      ~5 query + ~50-100 scan credits
    Savings:                ~44% query, ~90% scan credits

EOF
}

check_credits() {
    log_info "Checking Shodan credits..."
    
    source "$VENV_DIR/bin/activate"
    python "$OPTIMIZED_SCANNER" --check-credits
}

run_optimized_scan() {
    local scan_mode=$1
    local use_cache=$2
    local max_enrich=$3
    
    log_info "Starting optimized scan..."
    log_info "Mode: $scan_mode"
    log_info "Cache: $use_cache"
    log_info "Max enrichments: $max_enrich"
    echo ""
    
    # Activate venv
    source "$VENV_DIR/bin/activate"
    
    # Build command
    local cmd="python $OPTIMIZED_SCANNER --max-enrich $max_enrich"
    
    if [ "$use_cache" = "false" ]; then
        cmd="$cmd --no-cache"
    fi
    
    if [ "$scan_mode" = "quick" ]; then
        cmd="$cmd --quick"
    fi
    
    if [ -n "$API_KEY_ARG" ]; then
        cmd="$cmd --api-key $API_KEY_ARG"
    fi
    
    # Show credit estimate
    echo -e "${CYAN}Estimated Credit Usage:${NC}"
    if [ "$scan_mode" = "quick" ]; then
        echo "  Query credits:  ~5"
        echo "  Scan credits:   ~50"
    elif [ "$scan_mode" = "medium" ]; then
        echo "  Query credits:  ~5"
        echo "  Scan credits:   ~75"
    else
        echo "  Query credits:  ~5"
        echo "  Scan credits:   ~100"
    fi
    echo ""
    
    # Run scanner
    log_info "Executing: $cmd"
    echo ""
    
    if eval $cmd; then
        echo ""
        log_info "Scan completed successfully ✓"
        
        # Log usage to tracker
        log_info "Logging credit usage..."
        
        # Extract credits from last scan (simplified)
        local query_credits=5
        local scan_credits=$max_enrich
        
        python "$CREDIT_TRACKER" --log \
            --query-credits $query_credits \
            --scan-credits $scan_credits \
            --type $scan_mode \
            --notes "Optimized scan via script"
        
        # Show updated usage report
        echo ""
        python "$CREDIT_TRACKER" --report
        
        show_results
    else
        echo ""
        log_error "Scan failed"
        exit 1
    fi
}

show_results() {
    log_info "Scan results location:"
    echo ""
    
    local output_dir="$PROJECT_ROOT/output"
    
    # Find latest files
    if [ -d "$output_dir/reports" ]; then
        local latest_report=$(ls -t "$output_dir/reports"/report_*.txt 2>/dev/null | head -1)
        if [ -n "$latest_report" ]; then
            echo "  📄 Report: $latest_report"
        fi
        
        local latest_critical=$(ls -t "$output_dir/reports"/critical_nodes_*.json 2>/dev/null | head -1)
        if [ -n "$latest_critical" ]; then
            echo "  ⚠️  Critical Nodes: $latest_critical"
        fi
    fi
    
    echo ""
    
    # Show cache stats
    if [ -f "$PROJECT_ROOT/cache/nodes_cache.json" ]; then
        local cache_size=$(wc -l < "$PROJECT_ROOT/cache/nodes_cache.json" 2>/dev/null || echo "0")
        log_info "Cache: $cache_size cached nodes"
    fi
}

load_env_file() {
    local env_file="$PROJECT_ROOT/.env"
    
    if [ -f "$env_file" ]; then
        log_info "Loading environment from .env file"
        # Load .env file (export each line that doesn't start with # and contains =)
        set -a  # automatically export all variables
        source "$env_file"
        set +a  # disable automatic export
    else
        log_warning "No .env file found at $env_file"
    fi
}

setup_environment() {
    # Load environment variables from .env file
    load_env_file
    
    # Check virtualenv
    if [ ! -d "$VENV_DIR" ]; then
        log_error "Virtual environment not found"
        log_info "Run: ./scripts/setup.sh"
        exit 1
    fi
    
    # Check API key
    if [ -z "$SHODAN_API_KEY" ] && [ -z "$API_KEY_ARG" ]; then
        log_error "SHODAN_API_KEY not set"
        log_info "Set it with: export SHODAN_API_KEY='your_key'"
        log_info "Or add it to .env file: SHODAN_API_KEY=your_key"
        exit 1
    fi
    
    # Create cache directory
    mkdir -p "$PROJECT_ROOT/cache"
}

################################################################################
# Main
################################################################################

# Default values
MODE="medium"
USE_CACHE="true"
MAX_ENRICH=100
CHECK_CREDITS_ONLY="false"
API_KEY_ARG=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        -q|--quick)
            MODE="quick"
            MAX_ENRICH=50
            shift
            ;;
        -m|--medium)
            MODE="medium"
            MAX_ENRICH=75
            shift
            ;;
        -f|--full)
            MODE="full"
            MAX_ENRICH=100
            shift
            ;;
        -c|--check-credits)
            CHECK_CREDITS_ONLY="true"
            shift
            ;;
        --no-cache)
            USE_CACHE="false"
            shift
            ;;
        --max-enrich)
            MAX_ENRICH="$2"
            shift 2
            ;;
        -k|--api-key)
            API_KEY_ARG="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Main execution
print_banner

log_info "Optimized scanner with credit-saving features"
log_info "Working directory: $PROJECT_ROOT"
echo ""

setup_environment

if [ "$CHECK_CREDITS_ONLY" = "true" ]; then
    check_credits
else
    run_optimized_scan "$MODE" "$USE_CACHE" "$MAX_ENRICH"
fi

log_info "Done!"
