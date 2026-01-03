# Bitcoin Node Scanner - Setup Instructions

## What You Have

You've downloaded the base structure of the Bitcoin Node Scanner. Here's what you need to complete:

## Files to Create Manually

### 1. src/scanner.py (Main Script)

The complete scanner.py script is too large for a single file. You have two options:

**Option A**: Copy from the chat conversation above (search for "Bitcoin Node Security Scanner" in the Python code)

**Option B**: I can break it into smaller modules. Create these files:

```
src/
├── __init__.py
├── scanner.py (main entry point)
├── config.py (Config class)
├── analyzer.py (analysis functions)
└── reporter.py (report generation)
```

### 2. Additional Files Needed

```bash
# Create these files in your repository:

# scripts/quick_scan.sh
chmod +x scripts/quick_scan.sh

# scripts/setup.sh  
chmod +x scripts/setup.sh

# docs/INSTALLATION.md
# docs/USAGE.md
# docs/API.md
# docs/METHODOLOGY.md

# config/config.yaml
```

## Quick Setup After Download

```bash
# 1. Extract files
cd your-download-location
tar -xzf bitcoin-node-scanner.tar.gz
cd bitcoin-node-scanner

# 2. Set up Python environment
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API key
cp .env.example .env
nano .env  # Add your SHODAN_API_KEY

# 5. Create the main scanner.py
# Copy the full Python script from the conversation above into src/scanner.py

# 6. Test
python src/scanner.py --check-credits
```

## Next Steps

1. **Get Shodan API Key**: https://account.shodan.io/
2. **Complete the src/scanner.py**: Use the full script from our conversation
3. **Add documentation**: Create the docs/ files
4. **Add scripts**: Create setup.sh and quick_scan.sh
5. **Test locally** before pushing to GitHub
6. **Push to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Initial commit: Bitcoin Node Scanner"
   git remote add origin https://github.com/your-username/bitcoin-node-scanner.git
   git push -u origin main
   ```

## Repository URL

After pushing, your repo will be at:
```
https://github.com/hacknodes-lab/bitcoin-node-scanner
```

## Support

If you need the complete scanner.py file in parts or have questions:
- Check the conversation above for the full code
- Reach out to security@hacknodes.com

---

**HackNodes Lab** - Securing Bitcoin Infrastructure
