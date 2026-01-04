# Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip package manager
- Shodan API key ([Get one here](https://account.shodan.io/))

## Quick Installation

### Linux/macOS
```bash
# Clone repository
git clone https://github.com/hacknodes-lab/bitcoin-node-scanner.git
cd bitcoin-node-scanner

# Run setup script
chmod +x scripts/setup.sh
./scripts/setup.sh

# Configure API key
nano .env
# Add your Shodan API key to SHODAN_API_KEY
```

### Windows
```powershell
# Clone repository
git clone https://github.com/hacknodes-lab/bitcoin-node-scanner.git
cd bitcoin-node-scanner

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure .env
copy .env.example .env
# Edit .env and add your Shodan API key
```

## Manual Installation
```bash
# 1. Clone repository
git clone https://github.com/hacknodes-lab/bitcoin-node-scanner.git
cd bitcoin-node-scanner

# 2. Create virtual environment
python3 -m venv venv

# 3. Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# 4. Install dependencies
pip install -r requirements.txt

# 5. Configure environment
cp .env.example .env
# Edit .env and add your Shodan API key
```

## Verification
```bash
# Check installation
python src/scanner.py --check-credits

# Should output your Shodan account information
```

## Troubleshooting

### "Module not found" error
```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### "API key not found" error
```bash
# Set environment variable directly
export SHODAN_API_KEY="your_key_here"

# Or ensure .env file is properly configured
```

### Permission denied on scripts
```bash
# Make scripts executable
chmod +x scripts/*.sh
```
