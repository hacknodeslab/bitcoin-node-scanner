#!/bin/bash

################################################################################
# Bitcoin Node Security Scanner - Quick Scan Script
# HackNodes Lab
# 
# Description: Automated script to run Bitcoin node security scans
# Usage: ./quick_scan.sh [options]
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SCANNER_SCRIPT="$PROJECT_ROOT/src/scanner.py"
VENV_DIR="$PROJECT_ROOT/venv"
LOG_DIR="$PROJECT_ROOT/output/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

################################################################################
# Functions
################################################################################

print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║         Bitcoin Node Security Scanner - Quick Scan             ║"
    echo "║                    HackNodes Lab                               ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -q, --quick             Quick scan (100 results per query, no enrichment)
    -m, --medium            Medium scan (500 results per query, limited enrichment)
    -f, --full              Full scan (1000 results per query, full enrichment)
    -c, --check-credits     Check Shodan API credits and exit
    -n, --max-results NUM   Custom max results per query
    --no-enrich             Skip host enrichment
    -k, --api-key KEY       Shodan API key (overrides env variable)

Examples:
    $0                      # Default: medium scan
    $0 --quick              # Fast scan for testing
    $0 --full               # Comprehensive scan
    $0 --check-credits      # Check available credits
    $0 -n 2000 --no-enrich  # Custom scan

Environment Variables:
    SHODAN_API_KEY         Shodan API key (required)

EOF
}

check_requirements() {
    log_info "Checking requirements..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check if script exists
    if [ ! -f "$SCANNER_SCRIPT" ]; then
        log_error "Scanner script not found: $SCANNER_SCRIPT"
        exit 1
    fi
    
    # Check API key
    if [ -z "$SHODAN_API_KEY" ] && [ -z "$API_KEY_ARG" ]; then
        log_error "SHODAN_API_KEY environment variable not set"
        log_info "Set it with: export SHODAN_API_KEY='your_key_here'"
        log_info "Or use -k option: $0 -k 'your_key_here'"
        exit 1
    fi
    
    log_info "Requirements check passed ✓"
}

setup_virtualenv() {
    if [ ! -d "$VENV_DIR" ]; then
        log_info "Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
    fi
    
    log_info "Activating virtual environment..."
    source "$VENV_DIR/bin/activate"
    
    # Check if requirements are installed
    if ! python -c "import shodan" 2>/dev/null; then
        log_info "Installing dependencies..."
        pip install -q -r "$PROJECT_ROOT/requirements.txt"
    fi
}

run_scan() {
    local max_results=$1
    local enrich=$2
    
    log_info "Starting scan..."
    log_info "Max results per query: $max_results"
    log_info "Enrichment: $enrich"
    log_info "Timestamp: $TIMESTAMP"
    echo ""
    
    # Build command
    local cmd="python $SCANNER_SCRIPT --max-per-query $max_results"
    
    if [ "$enrich" = "false" ]; then
        cmd="$cmd --no-enrich"
    fi
    
    if [ -n "$API_KEY_ARG" ]; then
        cmd="$cmd --api-key $API_KEY_ARG"
    fi
    
    # Run scanner
    log_info "Executing: $cmd"
    echo ""
    
    if eval $cmd; then
        echo ""
        log_info "Scan completed successfully ✓"
        show_results
    else
        echo ""
        log_error "Scan failed"
        exit 1
    fi
}

check_credits() {
    log_info "Checking Shodan API credits..."
    
    local cmd="python $SCANNER_SCRIPT --check-credits"
    
    if [ -n "$API_KEY_ARG" ]; then
        cmd="$cmd --api-key $API_KEY_ARG"
    fi
    
    eval $cmd
}

show_results() {
    log_info "Scan results location:"
    echo ""
    
    # Find most recent files
    local output_dir="$PROJECT_ROOT/output"
    
    if [ -d "$output_dir/reports" ]; then
        local latest_report=$(ls -t "$output_dir/reports"/report_*.txt 2>/dev/null | head -1)
        if [ -n "$latest_report" ]; then
            echo "  📄 Report: $latest_report"
        fi
        
        local latest_stats=$(ls -t "$output_dir/reports"/statistics_*.json 2>/dev/null | head -1)
        if [ -n "$latest_stats" ]; then
            echo "  📊 Statistics: $latest_stats"
        fi
        
        local latest_critical=$(ls -t "$output_dir/reports"/critical_nodes_*.json 2>/dev/null | head -1)
        if [ -n "$latest_critical" ]; then
            echo "  ⚠️  Critical Nodes: $latest_critical"
        fi
    fi
    
    if [ -d "$output_dir/raw_data" ]; then
        local latest_raw=$(ls -t "$output_dir/raw_data"/nodes_*.json 2>/dev/null | head -1)
        if [ -n "$latest_raw" ]; then
            echo "  💾 Raw Data: $latest_raw"
        fi
    fi
    
    if [ -d "$output_dir/logs" ]; then
        local latest_log=$(ls -t "$output_dir/logs"/scan_*.log 2>/dev/null | head -1)
        if [ -n "$latest_log" ]; then
            echo "  📋 Log File: $latest_log"
        fi
    fi
    
    echo ""
    
    # Show quick summary if report exists
    if [ -n "$latest_report" ] && [ -f "$latest_report" ]; then
        log_info "Quick Summary:"
        echo ""
        grep -A 10 "EXECUTIVE SUMMARY" "$latest_report" | tail -n +2
    fi
}

cleanup() {
    if [ -n "$VENV_DIR" ] && [ -d "$VENV_DIR" ]; then
        deactivate 2>/dev/null || true
    fi
}

################################################################################
# Main Script
################################################################################

# Trap cleanup on exit
trap cleanup EXIT

# Default values
MODE="medium"
MAX_RESULTS=500
ENRICH="true"
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
            MAX_RESULTS=100
            ENRICH="false"
            shift
            ;;
        -m|--medium)
            MODE="medium"
            MAX_RESULTS=500
            ENRICH="true"
            shift
            ;;
        -f|--full)
            MODE="full"
            MAX_RESULTS=1000
            ENRICH="true"
            shift
            ;;
        -c|--check-credits)
            CHECK_CREDITS_ONLY="true"
            shift
            ;;
        -n|--max-results)
            MAX_RESULTS="$2"
            shift 2
            ;;
        --no-enrich)
            ENRICH="false"
            shift
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

log_info "Mode: $MODE"
log_info "Working directory: $PROJECT_ROOT"
echo ""

check_requirements
setup_virtualenv

if [ "$CHECK_CREDITS_ONLY" = "true" ]; then
    check_credits
else
    run_scan "$MAX_RESULTS" "$ENRICH"
fi

log_info "Done!"
