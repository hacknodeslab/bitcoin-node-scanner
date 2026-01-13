# Bitcoin Node Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A comprehensive security assessment tool for Bitcoin nodes exposed on the clearnet. This tool leverages Shodan API to identify, analyze, and report on potentially vulnerable Bitcoin Core and Bitcoin Knots nodes.

## Purpose

This scanner helps identify:
- Nodes running vulnerable Bitcoin Core/Knots versions
- Exposed RPC interfaces (critical security risk)
- Development versions running in production
- Nodes with multiple high-risk services exposed
- Geographic distribution of vulnerable nodes
- Infrastructure security posture analysis

## Disclaimer

This tool is for **security research and educational purposes only**. All data collected is from publicly available sources (Shodan). Do not perform active penetration testing without explicit authorization.

## Features

- **Multi-Query Search**: Comprehensive coverage using multiple Shodan queries
- **Vulnerability Detection**: Identifies nodes running known vulnerable versions
- **Risk Assessment**: Categorizes nodes by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- **Host Enrichment**: Deep scan of critical nodes for complete service inventory
- **Statistical Analysis**: Comprehensive statistics and visualizations
- **Multiple Output Formats**: JSON, CSV, and human-readable reports
- **Rate Limiting**: Built-in protections to respect Shodan API limits

## 📋 Prerequisites

- Python 3.8 or higher
- Shodan API key (get one at [shodan.io](https://account.shodan.io/))
- pip package manager

## Quick Start

```bash
# Clone the repository
git clone https://github.com/hacknodeslab/bitcoin-node-scanner.git
cd bitcoin-node-scanner

# Install dependencies
pip install -r requirements.txt

# Configure your API key
export SHODAN_API_KEY="your_api_key_here"

# Run a scan
python src/scanner.py

# Or use the quick scan script
./scripts/quick_scan.sh
```

## Structure Project
```
bitcoin-node-scanner/
├── README.md
├── LICENSE
├── requirements.txt
├── setup.py
├── .env.example
├── .gitignore
├── config/
│   └── config.yaml
├── src/
│   ├── __init__.py
│   ├── scanner.py
│   ├── analyzer.py
│   ├── reporter.py
│   └── utils.py
├── docs/
│   ├── INSTALLATION.md
│   ├── USAGE.md
│   ├── API.md
│   └── METHODOLOGY.md
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   └── test_analyzer.py
└── scripts/
    ├── quick_scan.sh
    └── setup.sh
```

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Guide](docs/USAGE.md)
- [API Reference](docs/API.md)
- [Methodology](docs/METHODOLOGY.md)

## Example Output

```
================================================================================
BITCOIN NODE SECURITY SCAN REPORT
Generated: 2026-01-03 15:30:45
Scan ID: 20260103_153045
================================================================================

EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Total nodes found: 12161
Unique IPs: 11847
Vulnerable nodes: 2341
RPC exposed: 15 (CRITICAL)

RISK DISTRIBUTION
--------------------------------------------------------------------------------
CRITICAL         15 ( 0.12%)
HIGH           2326 (19.13%)
MEDIUM         4820 (39.64%)
LOW            5000 (41.11%)
```

## Sample Findings

Based on recent scans:
- ~19% of exposed nodes run vulnerable versions
- 0.12% have RPC interface publicly exposed (critical)
- Top vulnerable versions: 0.18.x, 0.20.x, 0.21.x
- Geographic concentration: US (28%), Germany (15%), France (9%)

## Configuration

Edit `config/config.yaml` to customize:
- Shodan queries
- Port definitions
- Vulnerable version database
- Output directories
- Risk assessment thresholds

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Ethical Use

- **Responsible Disclosure**: If you discover 0-day vulnerabilities, please report them responsibly to the Bitcoin Core security team
- **No Active Exploitation**: This tool is for passive reconnaissance only
- **Respect Privacy**: Do not publish IP addresses of vulnerable nodes
- **GDPR Compliance**: Handle European data in accordance with regulations

## Credits

Developed by HackNodes Lab

Special thanks to:
- Shodan for providing the API
- Bitcoin Core development team
- OSTIF and Quarkslab for their comprehensive security audit

## Contact

- Website: [hacknodes.com](https://hacknodes.com)
- Email: support@hacknodes.com

## Related Projects

- [Bitcoin Core](https://github.com/bitcoin/bitcoin)
- [Bitcoin Knots](https://github.com/bitcoinknots/bitcoin)
- [Bitnodes](https://bitnodes.io/)

---

**Made with ❤️ for the Bitcoin security community**
