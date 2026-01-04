#!/bin/bash

################################################################################
# Bitcoin Node Security Scanner - Setup Script
# HackNodes Lab
# 
# Description: Automated environment setup and configuration
# Usage: ./setup.sh
################################################################################

set -e  # Exit on error

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
VENV_DIR="$PROJECT_ROOT/venv"
REQUIREMENTS_FILE="$PROJECT_ROOT/requirements.txt"
ENV_FILE="$PROJECT_ROOT/.env"
ENV_EXAMPLE="$PROJECT_ROOT/.env.example"

################################################################################
# Functions
################################################################################

print_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║       Bitcoin Node Security Scanner - Setup                      ║
║                   HackNodes Lab                                  ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[→]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

separator() {
    echo -e "${CYAN}──────────────────────────────────────────────────────────────────${NC}"
}

check_system() {
    log_step "Checking system requirements..."
    
    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="Linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macOS"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        OS="Windows"
    else
        OS="Unknown"
    fi
    
    log_info "Operating System: $OS"
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        log_info "Python3 found: $PYTHON_VERSION"
        
        # Check version is >= 3.8
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
            log_error "Python 3.8 or higher required (found $PYTHON_VERSION)"
            exit 1
        fi
    else
        log_error "Python3 not found. Please install Python 3.8 or higher."
        exit 1
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        log_info "pip3 found"
    else
        log_error "pip3 not found. Please install pip."
        exit 1
    fi
    
    # Check git (optional)
    if command -v git &> /dev/null; then
        log_info "git found"
    else
        log_warning "git not found (optional)"
    fi
    
    echo ""
}

create_virtualenv() {
    separator
    log_step "Setting up Python virtual environment..."
    
    if [ -d "$VENV_DIR" ]; then
        log_warning "Virtual environment already exists at: $VENV_DIR"
        read -p "Do you want to recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_step "Removing existing virtual environment..."
            rm -rf "$VENV_DIR"
        else
            log_info "Using existing virtual environment"
            return
        fi
    fi
    
    log_step "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    log_info "Virtual environment created"
    
    echo ""
}

install_dependencies() {
    separator
    log_step "Installing Python dependencies..."
    
    # Activate venv
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    log_step "Upgrading pip..."
    pip install --quiet --upgrade pip
    
    # Install requirements
    if [ -f "$REQUIREMENTS_FILE" ]; then
        log_step "Installing packages from requirements.txt..."
        pip install --quiet -r "$REQUIREMENTS_FILE"
        log_info "Dependencies installed successfully"
    else
        log_error "requirements.txt not found at: $REQUIREMENTS_FILE"
        exit 1
    fi
    
    # Verify installations
    log_step "Verifying installations..."
    
    if python -c "import shodan" 2>/dev/null; then
        log_info "shodan: OK"
    else
        log_error "shodan installation failed"
    fi
    
    if python -c "import yaml" 2>/dev/null; then
        log_info "pyyaml: OK"
    else
        log_error "pyyaml installation failed"
    fi
    
    if python -c "import requests" 2>/dev/null; then
        log_info "requests: OK"
    else
        log_error "requests installation failed"
    fi
    
    deactivate
    echo ""
}

configure_environment() {
    separator
    log_step "Configuring environment variables..."
    
    if [ -f "$ENV_FILE" ]; then
        log_warning ".env file already exists"
        read -p "Do you want to reconfigure it? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Keeping existing .env file"
            return
        fi
    fi
    
    # Copy example file
    if [ -f "$ENV_EXAMPLE" ]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        log_info "Created .env from template"
    else
        # Create basic .env
        cat > "$ENV_FILE" << 'ENVEOF'
# Shodan API Configuration
SHODAN_API_KEY=your_shodan_api_key_here

# Output Configuration
OUTPUT_DIR=./output
LOG_LEVEL=INFO

# Scan Configuration
MAX_RESULTS_PER_QUERY=1000
ENABLE_HOST_ENRICHMENT=true
MAX_ENRICHMENTS=100

# Rate Limiting
RATE_LIMIT_DELAY=1
QUERY_COOLDOWN=2

# Report Configuration
GENERATE_CSV=true
GENERATE_JSON=true
GENERATE_CHARTS=true
ENVEOF
        log_info "Created basic .env file"
    fi
    
    # Prompt for API key
    echo ""
    log_step "Shodan API Key Configuration"
    echo ""
    echo "You need a Shodan API key to use this scanner."
    echo "Get one at: https://account.shodan.io/"
    echo ""
    
    read -p "Enter your Shodan API key (or press Enter to skip): " API_KEY
    
    if [ -n "$API_KEY" ]; then
        # Update .env file
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' "s/SHODAN_API_KEY=.*/SHODAN_API_KEY=$API_KEY/" "$ENV_FILE"
        else
            # Linux
            sed -i "s/SHODAN_API_KEY=.*/SHODAN_API_KEY=$API_KEY/" "$ENV_FILE"
        fi
        log_info "API key saved to .env"
    else
        log_warning "API key not configured. You'll need to edit .env manually."
    fi
    
    echo ""
}

create_directories() {
    separator
    log_step "Creating output directories..."
    
    mkdir -p "$PROJECT_ROOT/output/raw_data"
    mkdir -p "$PROJECT_ROOT/output/reports"
    mkdir -p "$PROJECT_ROOT/output/logs"
    
    log_info "Created: output/raw_data"
    log_info "Created: output/reports"
    log_info "Created: output/logs"
    
    echo ""
}

test_installation() {
    separator
    log_step "Testing installation..."
    
    source "$VENV_DIR/bin/activate"
    
    # Check if scanner script exists
    if [ -f "$PROJECT_ROOT/src/scanner.py" ]; then
        log_info "Scanner script found"
        
        # Try to run help
        if python "$PROJECT_ROOT/src/scanner.py" --help &> /dev/null; then
            log_info "Scanner script is executable"
        else
            log_warning "Scanner script may have issues"
        fi
    else
        log_warning "Scanner script not found at: $PROJECT_ROOT/src/scanner.py"
        log_warning "You'll need to create it manually"
    fi
    
    deactivate
    echo ""
}

print_next_steps() {
    separator
    echo -e "${GREEN}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                    SETUP COMPLETED!                              ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    echo -e "${CYAN}Next Steps:${NC}"
    echo ""
    echo "1. Configure your API key (if you haven't already):"
    echo -e "   ${YELLOW}nano .env${NC}"
    echo ""
    echo "2. Activate the virtual environment:"
    echo -e "   ${YELLOW}source venv/bin/activate${NC}"
    echo ""
    echo "3. Test the scanner:"
    echo -e "   ${YELLOW}python src/scanner.py --check-credits${NC}"
    echo ""
    echo "4. Run your first scan:"
    echo -e "   ${YELLOW}./scripts/quick_scan.sh --quick${NC}"
    echo ""
    echo "5. For full documentation:"
    echo -e "   ${YELLOW}cat docs/INSTALLATION.md${NC}"
    echo ""
    
    separator
    
    echo -e "${CYAN}Useful Commands:${NC}"
    echo ""
    echo "  Quick scan (testing):     ./scripts/quick_scan.sh --quick"
    echo "  Medium scan (default):    ./scripts/quick_scan.sh --medium"
    echo "  Full scan (comprehensive): ./scripts/quick_scan.sh --full"
    echo "  Check credits:            ./scripts/quick_scan.sh --check-credits"
    echo ""
    
    separator
    
    echo -e "${CYAN}Project Structure:${NC}"
    echo ""
    echo "  bitcoin-node-scanner/"
    echo "  ├── src/              # Source code"
    echo "  ├── config/           # Configuration files"
    echo "  ├── docs/             # Documentation"
    echo "  ├── scripts/          # Helper scripts"
    echo "  ├── output/           # Scan results"
    echo "  │   ├── raw_data/     # Raw JSON/CSV data"
    echo "  │   ├── reports/      # Analysis reports"
    echo "  │   └── logs/         # Log files"
    echo "  └── venv/             # Python virtual environment"
    echo ""
    
    separator
}

################################################################################
# Main Execution
################################################################################

main() {
    print_banner
    
    log_step "Starting setup process..."
    echo ""
    
    check_system
    create_virtualenv
    install_dependencies
    configure_environment
    create_directories
    test_installation
    
    print_next_steps
    
    log_success "Setup completed successfully!"
    echo ""
}

# Run main
main
