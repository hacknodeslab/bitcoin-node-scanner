# Bitcoin Node Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A comprehensive security assessment tool for Bitcoin nodes exposed on the clearnet. This tool leverages Shodan API to identify, analyze, and report on potentially vulnerable Bitcoin Core and Bitcoin Knots nodes.

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=hacknodeslab_bitcoin-node-scanner&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=hacknodeslab_bitcoin-node-scanner)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=hacknodeslab_bitcoin-node-scanner&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=hacknodeslab_bitcoin-node-scanner)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=hacknodeslab_bitcoin-node-scanner&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=hacknodeslab_bitcoin-node-scanner)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=hacknodeslab_bitcoin-node-scanner&metric=bugs)](https://sonarcloud.io/summary/new_code?id=HackNodes-Lab_bitcoin-node-scanner)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=hacknodeslab_bitcoin-node-scanner&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=HackNodes-Lab_bitcoin-node-scanner)
[![CI Pipeline](https://github.com/hacknodeslab/bitcoin-node-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/hacknodeslab/bitcoin-node-scanner/actions/workflows/ci.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hacknodeslab/bitcoin-node-scanner)

## Purpose

This scanner helps identify:
- Nodes running vulnerable Bitcoin versions
- Exposed RPC interfaces (critical security risk)
- Development versions running in production
- Nodes with multiple high-risk services exposed
- Geographic distribution of vulnerable nodes
- Infrastructure security posture analysis

## Features

- **Multi-Query Search**: Comprehensive coverage using multiple Shodan queries
- **Vulnerability Detection**: Identifies nodes running known vulnerable versions
- **Risk Assessment**: Categorizes nodes by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- **Host Enrichment**: Deep scan of critical nodes for complete service inventory
- **Statistical Analysis**: Comprehensive statistics and visualizations
- **Multiple Output Formats**: JSON, CSV, and human-readable reports
- **Rate Limiting**: Built-in protections to respect Shodan API limits
- **Database Support**: Optional PostgreSQL/SQLite persistence for historical analysis
- **Historical Analysis**: Track vulnerability trends and node lifecycle over time

## MaxMind GeoIP Setup

The scanner can enrich node geo data (city, region, coordinates, ASN) using MaxMind's free GeoLite2 databases. This is optional — the scanner works without it, but geo fields will be less complete.

### 1. Get a free MaxMind license key

Create a free account at [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup), then generate a license key in your account portal.

### 2. Download the databases

```bash
export MAXMIND_LICENSE_KEY=your_license_key_here
./scripts/download_geoip_dbs.sh
```

This downloads `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`, and `GeoLite2-Country.mmdb` into `./geoip_dbs/` (configurable via `GEOIP_DB_DIR`). Re-run monthly to keep the databases current.

### 3. Configure the path (optional)

```bash
export GEOIP_DB_DIR=./geoip_dbs   # default — no change needed if you used the script
```

GeoIP enrichment is automatic during scans once the databases are present. If the files are missing, the scanner logs a warning and continues without geo enrichment.

### 4. Enrich existing nodes retroactively

```bash
python -m src.db.cli enrich-geo
```

This fills in missing geo fields (city, region, coordinates, ASN) for all nodes already in the database, processing them in batches of 500.

> **Attribution**: This product includes GeoLite2 data created by MaxMind, available from [maxmind.com](https://www.maxmind.com).

---

## Web Interface

The web interface is a two-process setup:

1. **FastAPI backend** (`src/web/`) — serves the REST API at `/api/v1/*`. Does not serve HTML.
2. **Next.js dashboard** (`frontend/`) — operator dashboard, calls the backend.

`GET /` on the backend 302-redirects to `FRONTEND_ORIGIN` (default `http://localhost:3000`).

In **dev**, the two processes are on different ports (`:8000` + `:3000`) and the frontend calls the backend cross-origin.
In **prod**, nginx serves both on port 80 from a single origin (`/api/` → backend, `/` → Next.js), so there is no cross-origin traffic in the browser. See [`docs/deploy-frontend.md`](docs/deploy-frontend.md) for the deploy pipeline, host bootstrap, and rollback playbook.

### Starting both

Two terminals.

**Backend** (Python / pip):
```bash
export DATABASE_URL="sqlite:///./bitcoin_scanner.db"   # or PostgreSQL URL
export WEB_API_KEY="your-strong-random-secret"
export FRONTEND_ORIGIN="http://localhost:3000"          # CORS allow-list

python -m src.web.main
# or after installing the package:
bitcoin-scanner-web
```

**Frontend** (Node / pnpm):
```bash
cd frontend
pnpm install
# Create frontend/.env.local with the values below, then:
pnpm dev
```

`frontend/.env.local`:
```
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api/v1
NEXT_PUBLIC_WEB_API_KEY=<same value as backend WEB_API_KEY>
```

Open `http://localhost:3000/` to use the dashboard.

### API reference

`/docs` (Swagger UI), `/redoc`, and `/openapi.json` are gated behind `ENABLE_API_DOCS` (set to `1` / `true` / `yes` in local dev; disabled by default to keep the public surface minimal).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/nodes` | List scanned nodes (`risk_level`, `country`, `exposed`, `tor`, `sort_by`, `sort_dir`, `limit`, `offset`) |
| GET | `/api/v1/nodes/countries` | Distinct country names |
| GET | `/api/v1/nodes/{id}/geo` | Geo + ASN detail for a single node |
| GET | `/api/v1/stats` | Aggregate statistics (TOTAL / EXPOSED / STALE / TOR / OK + by_risk_level, by_country) |
| GET | `/api/v1/vulnerabilities` | CVE catalogue |
| POST | `/api/v1/scans` | Trigger a background scan; returns `job_id` |
| GET | `/api/v1/scans/{job_id}` | Job status (`pending`/`running`/`completed`/`failed`) |
| GET | `/api/v1/csrf-token` | Bootstrap the double-submit CSRF token |
| GET | `/api/v1/l402/example` | L402 challenge stub (returns 402 + `WWW-Authenticate: L402 …`) |

All `/api/v1/*` endpoints (except `/csrf-token` and `/l402/example`) require the `X-API-Key` header. Mutating verbs additionally require `X-CSRF-Token`.

### Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WEB_API_KEY` | Yes | — | Secret key sent in `X-API-Key` header |
| `WEB_HOST` | No | `127.0.0.1` | Host the server binds to |
| `WEB_PORT` | No | `8000` | Port the server listens on |
| `DATABASE_URL` | Yes | — | SQLAlchemy database URL (SQLite or PostgreSQL) |
| `FRONTEND_ORIGIN` | No | `http://localhost:3000` | CORS allow-list; comma-separated for multiple |
| `ENABLE_API_DOCS` | No | off | Set to `1`/`true`/`yes` to expose `/docs`, `/redoc`, `/openapi.json` |
| `STALE_THRESHOLD_DAYS` | No | `7` | Age in days before a node is counted as STALE |

> **Security note**: Do not expose the web server on a public interface without a TLS-terminating reverse proxy (e.g., nginx). The API key provides authentication but not encryption.

---

## Prerequisites

- Python 3.8+
- Shodan API key (get one at [shodan.io](https://account.shodan.io/))

## Quick Start

```bash
# Clone the repository
git clone https://github.com/hacknodeslab/bitcoin-node-scanner.git
cd bitcoin-node-scanner

# Install dependencies
pip install -r requirements.txt

# Configure your API key
export SHODAN_API_KEY="your_api_key_here"

# (Optional) Configure database for historical tracking
export DATABASE_URL="postgresql://user:pass@localhost/bitcoin_scanner"
# Or use SQLite: export DATABASE_URL="sqlite:///./bitcoin_scanner.db"

# Run a scan
python src/scanner.py

# Or use the quick scan script
./scripts/quick_scan.sh
```

<details>

<summary>Structure Project</summary>

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
│   ├── test_analyzer.py
│   ├── test_credit_tracker.py
│   ├── test_reporter.py
│   └── test_utils.py
└── scripts/
    ├── quick_scan.sh
    └── setup.sh
```
</details>

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Guide](docs/USAGE.md)
- [API Reference](docs/API.md)
- [Methodology](docs/METHODOLOGY.md)
- [Database Support](docs/DATABASE.md)
- [Frontend Deployment](docs/deploy-frontend.md)

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

## Testing

The project includes comprehensive test coverage for all core modules:

```bash
# Install testing dependencies (already included in requirements.txt)
source venv/bin/activate
pip install -r requirements.txt

# Run all tests
python -m pytest tests/ -v

# Run tests with coverage report
python -m pytest tests/ --cov=src --cov-report=term-missing

# Run tests with HTML coverage report
python -m pytest tests/ --cov=src --cov-report=html

# Run specific test module
python -m pytest tests/test_scanner.py -v
python -m pytest tests/test_utils.py -v
python -m pytest tests/test_analyzer.py -v
python -m pytest tests/test_credit_tracker.py -v
python -m pytest tests/test_reporter.py -v
```

**Test Coverage:**
- **test_scanner.py** (68 tests) - Config, BitcoinNodeScanner, CachedNodeManager, OptimizedBitcoinScanner
- **test_analyzer.py** (24 tests) - Security analysis, vulnerability detection, risk assessment
- **test_credit_tracker.py** (21 tests) - Credit tracking, usage projections, recommendations
- **test_reporter.py** (19 tests) - Report generation, data export, file handling
- **test_utils.py** (27 tests) - Utility functions, validation, data processing

**Total: 159 tests covering 83% of the codebase**

## Configuration

Edit `config/config.yaml` to customize:
- Shodan queries
- Port definitions
- Vulnerable version database
- Output directories
- Risk assessment thresholds

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SHODAN_API_KEY` | Yes | Your Shodan API key |
| `DATABASE_URL` | No | Database connection string for persistence |
| `QUERIES` | No | Comma-separated list of Shodan queries |
| `QUERIES_OPTIMIZED` | No | Optimized query set for credit-efficient scans |

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

Developed by @ifuensan with the HackNodes Lab support.

Special thanks to:
- Shodan for providing the API
- Bitcoin Core development team
- OSTIF and Quarkslab for their comprehensive security audit

## Contact

- Website: [hacknodes.com](https://hacknodes.com)
- Email: support@hacknodes.com

## Disclaimer

This tool is for **security research and educational purposes only**. All data collected is from publicly available sources (Shodan & MaxMind GeoIP). Do not perform active penetration testing without explicit authorization.

---

**Made with ❤️ for the Bitcoin security community**
