#!/bin/bash

# Bitcoin Node Scanner - Quick Scan Script
# HackNodes Lab

set -e

echo "=========================================="
echo "Bitcoin Node Security Scanner"
echo "Quick Scan Script"
echo "=========================================="
echo ""

# Check if SHODAN_API_KEY is set
if [[ -z "$SHODAN_API_KEY" ]]; then
    echo "ERROR: SHODAN_API_KEY environment variable not set" >&2
    echo "Please set it with: export SHODAN_API_KEY='your_key_here'"
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed" >&2
    exit 1
fi

# Check if dependencies are installed
if ! python3 -c "import shodan" &> /dev/null; then
    echo "Installing dependencies..."
    pip3 install -r requirements.txt
fi

# Run the scanner
echo "Starting scan..."
echo ""

python3 src/scanner.py "$@"

echo ""
echo "=========================================="
echo "Scan completed!"
echo "Check the 'output' directory for results"
echo "=========================================="
