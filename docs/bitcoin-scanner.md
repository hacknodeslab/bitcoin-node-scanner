# Bitcoin Node Security Scanner

A security assessment tool for Bitcoin nodes exposed on the clearnet. It leverages
the [Shodan](https://shodan.io) API to identify, analyze, and report on potentially
vulnerable Bitcoin Core and Bitcoin Knots nodes.

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

> **Shodan credit efficiency**: `OptimizedBitcoinScanner` + `CachedNodeManager` exist
> specifically to minimize API credit usage. See [OPTIMIZATIONS_README.md](../OPTIMIZATIONS_README.md).

---

## Usage

```bash
# Configure your API key
export SHODAN_API_KEY="your_api_key_here"

# Run a full scan
python -m src.scanner

# Credit-efficient scan (cache + limited enrichment)
python -m src.scanner --quick

# Check remaining Shodan API credits
python -m src.scanner --check-credits

# Or use the quick scan script
./scripts/quick_scan.sh
```

> **Note**: scanner runs write JSON/CSV to `output/` only — they do **not** persist
> to the database. Load the results with `db-import` (see [Database Support](DATABASE.md)).

```bash
python -m src.db.cli db-import output/raw_data/nodes_<ts>.json
```

See the [Usage Guide](USAGE.md) and [Methodology](METHODOLOGY.md) for the full
workflow, query tuning, and risk-assessment rationale.

---

## MaxMind GeoIP Setup

The scanner can enrich node geo data (city, region, coordinates, ASN) using
MaxMind's free GeoLite2 databases. This is optional — the scanner works without it,
but geo fields will be less complete.

### 1. Get a free MaxMind license key

Create a free account at [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup),
then generate a license key in your account portal.

### 2. Download the databases

```bash
export MAXMIND_LICENSE_KEY=your_license_key_here
./scripts/download_geoip_dbs.sh
```

This downloads `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`, and `GeoLite2-Country.mmdb`
into `./geoip_dbs/` (configurable via `GEOIP_DB_DIR`). Re-run monthly to keep the
databases current.

### 3. Configure the path (optional)

```bash
export GEOIP_DB_DIR=./geoip_dbs   # default — no change needed if you used the script
```

GeoIP enrichment is automatic during scans once the databases are present. If the
files are missing, the scanner logs a warning and continues without geo enrichment.

### 4. Enrich existing nodes retroactively

```bash
python -m src.db.cli enrich-geo
```

This fills in missing geo fields (city, region, coordinates, ASN) for all nodes
already in the database, processing them in batches of 500.

> **Attribution**: This product includes GeoLite2 data created by MaxMind, available
> from [maxmind.com](https://www.maxmind.com).

---

## API

Bitcoin endpoints (under the shared API-key / CSRF auth — see the [API reference](API.md)):

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/nodes` | List scanned nodes (`risk_level`, `country`, `exposed`, `tor`, `is_example`, `sort_by`, `sort_dir`, `limit`, `offset`) |
| GET | `/api/v1/nodes/countries` | Distinct country names |
| GET | `/api/v1/nodes/{id}/geo` | Geo + ASN detail for a single node |
| GET | `/api/v1/stats` | Aggregate statistics (TOTAL / EXPOSED / STALE / TOR / OK + by_risk_level, by_country) |
| GET | `/api/v1/vulnerabilities` | CVE catalogue (from the NVD) |
| POST | `/api/v1/scans` | Trigger a background scan; returns `job_id` |
| GET | `/api/v1/scans/{job_id}` | Job status (`pending`/`running`/`completed`/`failed`) |

---

## Configuration

Edit `config/config.yaml` to customize Shodan queries, port definitions, the
vulnerable-version database, output directories, and risk-assessment thresholds.

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SHODAN_API_KEY` | Yes | Your Shodan API key |
| `DATABASE_URL` | No | Database connection string for persistence |
| `QUERIES` | No | Comma-separated list of Shodan queries |
| `QUERIES_OPTIMIZED` | No | Optimized query set for credit-efficient scans |
| `MAX_RESULTS_NORMAL` | No | Per-query result cap for non-critical queries (default `500`) |
| `MAX_RESULTS_CRITICAL` | No | Cap for critical/RPC queries (default `1000`) |
| `MAX_QUERY_CREDITS_PER_SCAN` | No | Hard ceiling on Shodan search pages per scan run (default `50`) |

> **Risk level enum**: always `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` (defined in
> `analyzer.py`) — never numeric scores.

---

## Example output

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

### Sample findings

Based on recent scans:
- ~19% of exposed nodes run vulnerable versions
- 0.12% have RPC interface publicly exposed (critical)
- Top vulnerable versions: 0.18.x, 0.20.x, 0.21.x
- Geographic concentration: US (28%), Germany (15%), France (9%)
