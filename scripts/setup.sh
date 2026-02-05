#!/bin/bash

# Bitcoin Node Scanner - Setup Script
# HackNodes Lab

set -e

echo "=========================================="
echo "Bitcoin Node Security Scanner"
echo "Setup Script"
echo "=========================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python $python_version"

# Check if version is 3.8 or higher
required_version="3.8"
if [[ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]]; then 
    echo "ERROR: Python 3.8 or higher is required"
    exit 1
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo ""
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [[ ! -f .env ]]; then
    echo ""
    echo "Creating .env file from template..."
    cp .env.example .env
    echo ""
    echo "⚠️  IMPORTANT: Edit .env file and add your Shodan API key"
fi

# Create output directories
echo ""
echo "Creating output directories..."
mkdir -p output/{raw_data,reports,logs}

echo ""
echo "=========================================="
echo "Setup completed successfully!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Edit .env file and add your Shodan API key"
echo "2. Activate virtual environment: source venv/bin/activate"
echo "3. Run a scan: python src/scanner.py"
echo ""
