# Bitcoin Node Scanner - Project Structure

## 📁 Complete File Structure

```
bitcoin-node-scanner/
├── README.md                      # Main project documentation
├── LICENSE                        # MIT License
├── requirements.txt               # Python dependencies
├── .env.example                   # Environment variables template
├── .gitignore                     # Git ignore rules
├── SETUP_INSTRUCTIONS.md          # Setup guide
│
├── src/                          # Source code
│   ├── __init__.py               # Package initialization
│   ├── scanner.py                # Main scanner class (690 lines)
│   ├── analyzer.py               # Risk analysis & vulnerability detection (280 lines)
│   ├── reporter.py               # Report generation & data export (320 lines)
│   └── utils.py                  # Helper functions & utilities (430 lines)
│
├── config/                       # Configuration files
│   └── (to be added: config.yaml)
│
├── docs/                         # Documentation
│   ├── API.md                    # API reference (~350 lines)
│   ├── METHODOLOGY.md            # Research methodology (~450 lines)
│   ├── INSTALLATION.md           # (to be created)
│   └── USAGE.md                  # (to be created)
│
├── scripts/                      # Helper scripts
│   ├── quick_scan.sh             # Automated scan script (~300 lines)
│   └── setup.sh                  # Environment setup (~350 lines)
│
├── tests/                        # Unit tests
│   └── (to be added)
│
└── output/                       # Generated outputs (gitignored)
    ├── raw_data/                 # Raw JSON/CSV data
    ├── reports/                  # Analysis reports
    └── logs/                     # Log files
```

---

## 📚 Module Descriptions

### Core Modules (`src/`)

#### `scanner.py` - Main Scanner Class
**Purpose:** Core scanning functionality and Shodan integration

**Key Components:**
- `Config` class: Centralized configuration
- `BitcoinNodeScanner` class: Main scanner orchestration

**Main Methods:**
- `search_bitcoin_nodes()`: Execute Shodan queries
- `parse_node_data()`: Extract node information
- `scan_all_queries()`: Run all configured queries
- `enrich_critical_nodes()`: Deep scan high-risk nodes
- `run_full_scan()`: Complete scan workflow

**Lines of Code:** 690

---

#### `analyzer.py` - Security Analysis
**Purpose:** Vulnerability detection and risk assessment

**Key Components:**
- `SecurityAnalyzer` class: Risk analysis engine

**Main Methods:**
- `is_vulnerable_version()`: Check version vulnerabilities
- `analyze_risk_level()`: Determine CRITICAL/HIGH/MEDIUM/LOW
- `get_risk_reason()`: Explain risk factors
- `generate_statistics()`: Compute scan statistics
- `identify_critical_nodes()`: Filter high-risk nodes
- `get_vulnerability_details()`: CVE information lookup

**Lines of Code:** 280

---

#### `reporter.py` - Report Generation
**Purpose:** Generate reports and export data

**Key Components:**
- `SecurityReporter` class: Report generation engine

**Main Methods:**
- `generate_text_report()`: Human-readable reports
- `save_json_data()`: Export JSON
- `save_csv_data()`: Export CSV
- `save_raw_data()`: Save scan results
- `save_critical_nodes()`: Export critical nodes
- `export_results()`: Export all formats
- `print_summary()`: Console summary

**Lines of Code:** 320

---

#### `utils.py` - Utility Functions
**Purpose:** Helper functions and common operations

**Key Functions:**
- `validate_ip_address()`: IP validation
- `parse_version_number()`: Version parsing
- `compare_versions()`: Version comparison
- `rate_limit()`: Decorator for API rate limiting
- `format_timestamp()`: Timestamp formatting
- `parse_banner_fields()`: Extract banner info
- `retry_on_failure()`: Retry decorator
- `ProgressTracker`: Progress tracking class

**Lines of Code:** 430

---

### Documentation (`docs/`)

#### `API.md`
Complete API reference with:
- Class documentation
- Method signatures
- Data structures
- Usage examples
- Error handling
- Best practices

#### `METHODOLOGY.md`
Research methodology covering:
- Data collection techniques
- Analysis frameworks
- Risk assessment criteria
- Ethical considerations
- Scientific validation
- Statistical methods

---

### Scripts (`scripts/`)

#### `quick_scan.sh`
**Purpose:** Automated scan execution

**Features:**
- 3 preset modes (quick/medium/full)
- Automatic virtualenv management
- Requirements checking
- Results summary
- Error handling

**Usage:**
```bash
./scripts/quick_scan.sh --quick    # Fast scan
./scripts/quick_scan.sh --full     # Comprehensive scan
```

---

#### `setup.sh`
**Purpose:** Initial project setup

**Features:**
- System requirements check
- Virtualenv creation
- Dependency installation
- API key configuration
- Directory structure creation
- Installation verification

**Usage:**
```bash
./scripts/setup.sh
```

---

## 🔧 Configuration

### Environment Variables (`.env`)
```bash
SHODAN_API_KEY=your_api_key_here
OUTPUT_DIR=./output
LOG_LEVEL=INFO
MAX_RESULTS_PER_QUERY=1000
ENABLE_HOST_ENRICHMENT=true
```

### Python Dependencies (`requirements.txt`)
```
shodan>=1.31.0
pyyaml>=6.0
requests>=2.31.0
python-dotenv>=1.0.0
colorama>=0.4.6
tabulate>=0.9.0
matplotlib>=3.8.0
pandas>=2.1.0
```

---

## 📊 Data Flow

```
1. User Input
   ↓
2. BitcoinNodeScanner (scanner.py)
   - Initialize Shodan API
   - Execute queries
   ↓
3. SecurityAnalyzer (analyzer.py)
   - Analyze vulnerabilities
   - Calculate risk levels
   - Generate statistics
   ↓
4. SecurityReporter (reporter.py)
   - Generate reports
   - Export data (JSON/CSV)
   - Print summaries
   ↓
5. Output Files
   - Raw data: output/raw_data/
   - Reports: output/reports/
   - Logs: output/logs/
```

---

## 🎯 Module Usage Examples

### Using Scanner Directly
```python
from src.scanner import BitcoinNodeScanner

scanner = BitcoinNodeScanner(api_key="your_key")
scanner.run_full_scan(max_per_query=500, enrich=True)
```

### Using Analyzer Independently
```python
from src.analyzer import SecurityAnalyzer
from src.scanner import Config

analyzer = SecurityAnalyzer(Config)

# Check vulnerability
is_vuln = analyzer.is_vulnerable_version("Satoshi:0.18.0")

# Analyze risk
risk_level = analyzer.analyze_risk_level(node_data)
```

### Using Reporter
```python
from src.reporter import SecurityReporter
from src.analyzer import SecurityAnalyzer
from src.scanner import Config

analyzer = SecurityAnalyzer(Config)
reporter = SecurityReporter(Config, analyzer)

# Generate report
stats = analyzer.generate_statistics(results)
reporter.save_text_report(stats, results)
```

---

## 🧪 Testing Structure (Planned)

```
tests/
├── __init__.py
├── test_scanner.py          # Scanner tests
├── test_analyzer.py         # Analyzer tests
├── test_reporter.py         # Reporter tests
├── test_utils.py            # Utility tests
└── fixtures/                # Test data
    ├── sample_nodes.json
    └── sample_stats.json
```

---

## 📦 Installation Workflow

1. **Clone Repository**
```bash
git clone https://github.com/hacknodes-lab/bitcoin-node-scanner.git
cd bitcoin-node-scanner
```

2. **Run Setup**
```bash
./scripts/setup.sh
```

3. **Configure API Key**
```bash
nano .env
# Add SHODAN_API_KEY=your_key_here
```

4. **Run First Scan**
```bash
./scripts/quick_scan.sh --quick
```

---

## 🔄 Development Workflow

### Adding New Features

1. **Modify appropriate module:**
   - Scanner logic → `src/scanner.py`
   - Analysis logic → `src/analyzer.py`
   - Report format → `src/reporter.py`
   - Helper functions → `src/utils.py`

2. **Update documentation:**
   - API changes → `docs/API.md`
   - Methodology changes → `docs/METHODOLOGY.md`

3. **Add tests:**
   - Create test in `tests/`

4. **Update version:**
   - Bump version in `src/__init__.py`

---

## 📈 Metrics

### Project Statistics
- **Total Lines of Code:** ~2,000+ lines
- **Python Modules:** 5
- **Bash Scripts:** 2
- **Documentation Files:** 6+
- **Total Files:** 15+

### Code Distribution
- Scanner logic: 35%
- Analysis & reporting: 30%
- Utilities: 20%
- Documentation: 15%

---

## 🚀 Future Enhancements

### Planned Modules
- `src/database.py`: Database integration
- `src/visualization.py`: Data visualization
- `src/api_server.py`: REST API server
- `src/scheduler.py`: Automated scanning

### Planned Features
- Web dashboard
- Real-time monitoring
- Trend analysis
- Export to PDF
- Integration with threat intel feeds

---

## 📞 Support

For questions about project structure:
- GitHub Issues: https://github.com/hacknodes-lab/bitcoin-node-scanner/issues
- Email: security@hacknodes.com

---

**Version:** 1.0.0  
**Last Updated:** 2026-01-04  
**Maintained by:** HackNodes Lab
