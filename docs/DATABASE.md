# Database Support

This document describes the database integration for Bitcoin Node Scanner, enabling persistent storage and historical analysis of scan results.

## Overview

The scanner supports optional database persistence using SQLAlchemy with PostgreSQL (recommended for production) or SQLite (for development/testing). When configured, scan results are automatically saved to the database in addition to JSON/CSV files.

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

This includes:
- `sqlalchemy>=2.0.0` - ORM and database abstraction
- `psycopg2-binary>=2.9.0` - PostgreSQL driver
- `alembic>=1.13.0` - Database migrations

### 2. Configure Database

Set the `DATABASE_URL` environment variable:

**PostgreSQL (Recommended for Production):**
```bash
export DATABASE_URL=postgresql://user:password@localhost:5432/bitcoin_scanner
```

**SQLite (Development/Testing):**
```bash
export DATABASE_URL=sqlite:///./bitcoin_scanner.db
```

### 3. Initialize Database

```bash
# Option 1: Using the migration script
python scripts/migrate.py init

# Option 2: Using Alembic directly
alembic upgrade head
```

### 4. Run Scanner with Database

The scanner automatically detects and uses the database when `DATABASE_URL` is set:

```bash
# Standard scan - results saved to both files and database
python -m src.scanner

# Optimized scan
python -m src.scanner --quick
```

## Database Schema

### Tables

#### `nodes`
Stores information about scanned Bitcoin nodes.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| ip | String(45) | IP address (IPv4/IPv6) |
| port | Integer | Port number |
| country_code | String(2) | ISO country code |
| country_name | String(100) | Country name |
| city | String(100) | City name |
| latitude | Float | Geographic latitude |
| longitude | Float | Geographic longitude |
| asn | String(20) | ASN identifier |
| asn_name | String(255) | ASN organization name |
| version | String(100) | Bitcoin Core version |
| user_agent | String(255) | User agent string |
| banner | Text | Raw banner data |
| risk_level | String(20) | CRITICAL/HIGH/MEDIUM/LOW |
| is_vulnerable | Boolean | Has known vulnerabilities |
| has_exposed_rpc | Boolean | RPC port exposed |
| is_dev_version | Boolean | Running dev version |
| first_seen | DateTime | First detection timestamp |
| last_seen | DateTime | Last detection timestamp |

**Indexes:** ip, ip+port (unique), last_seen, country_code, risk_level, is_vulnerable

#### `scans`
Tracks individual scan sessions.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| timestamp | DateTime | Scan start time |
| queries_executed | Text (JSON) | List of Shodan queries |
| total_nodes | Integer | Total nodes found |
| critical_nodes | Integer | CRITICAL risk nodes |
| high_risk_nodes | Integer | HIGH risk nodes |
| vulnerable_nodes | Integer | Vulnerable nodes |
| credits_used | Integer | Shodan credits consumed |
| duration_seconds | Float | Scan duration |
| status | String(20) | running/completed/failed |
| error_message | Text | Error details if failed |

#### `vulnerabilities`
Catalog of known CVEs.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| cve_id | String(20) | CVE identifier (unique) |
| affected_versions | Text (JSON) | List of affected versions |
| severity | String(20) | CRITICAL/HIGH/MEDIUM/LOW |
| cvss_score | Float | CVSS score (0-10) |
| description | Text | Vulnerability description |
| reference_url | String(500) | Reference URL |
| published_date | DateTime | CVE publication date |

#### `node_vulnerabilities`
Links nodes to detected vulnerabilities.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| node_id | Integer | Foreign key to nodes |
| vulnerability_id | Integer | Foreign key to vulnerabilities |
| detected_at | DateTime | Detection timestamp |
| resolved_at | DateTime | Resolution timestamp (null if active) |
| detected_version | String(100) | Version when detected |

## CLI Commands

### Database Statistics
```bash
python -m src.db db-stats
python -m src.db db-stats --days 7
```

### Vulnerability Trends
```bash
python -m src.db db-trends
python -m src.db db-trends --days 30 --granularity week
```

### Export Data
```bash
python -m src.db db-export --output export.json
python -m src.db db-export --days 90
```

### Import Historical Data
```bash
python -m src.db db-import path/to/nodes.json
python scripts/import_json_to_db.py --dir output/raw_data/
python scripts/import_json_to_db.py --all
```

### Node Lifecycle
```bash
python -m src.db db-node 192.168.1.1
```

## Migrations

### Apply Migrations
```bash
alembic upgrade head
```

### Rollback Last Migration
```bash
alembic downgrade -1
```

### Create New Migration
```bash
alembic revision --autogenerate -m "Description of changes"
```

### Check Current Version
```bash
alembic current
```

### View Migration History
```bash
alembic history
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | No | Database connection string |
| `SHODAN_API_KEY` | Yes | Shodan API key |

### Database URL Formats

```bash
# PostgreSQL
DATABASE_URL=postgresql://user:password@host:port/database
DATABASE_URL=postgresql://scanner:secret@localhost:5432/bitcoin_scanner

# SQLite
DATABASE_URL=sqlite:///./local.db
DATABASE_URL=sqlite:////absolute/path/to/database.db
```

## Programmatic Usage

### Using Database-Enabled Scanner

```python
from src.db.scanner_integration import create_db_scanner

# Create scanner with database persistence
scanner = create_db_scanner(use_optimized=True)
scanner.run_optimized_scan()
```

### Direct Repository Access

```python
from src.db.connection import get_db_session
from src.db.repositories import NodeRepository

with get_db_session() as session:
    if session:
        repo = NodeRepository(session)
        vulnerable = repo.find_vulnerable()
        for node in vulnerable:
            print(f"{node.ip}: {node.version}")
```

### Historical Analysis

```python
from datetime import datetime, timedelta
from src.db.analysis import HistoricalAnalyzer

analyzer = HistoricalAnalyzer()
start = datetime.utcnow() - timedelta(days=30)

# Get summary statistics
stats = analyzer.get_summary_statistics(start)
print(f"Total nodes: {stats['total_nodes']}")
print(f"Vulnerable: {stats['vulnerable_nodes']} ({stats['vulnerability_rate']:.1f}%)")

# Get vulnerability trends
trends = analyzer.get_vulnerability_trends(start, granularity="week")

# Get version distribution
versions = analyzer.get_version_distribution()
```

## Useful SQL Queries

### Top 10 Countries by Node Count
```sql
SELECT country_code, COUNT(*) as count
FROM nodes
WHERE last_seen > NOW() - INTERVAL '30 days'
GROUP BY country_code
ORDER BY count DESC
LIMIT 10;
```

### Vulnerable Nodes by Version
```sql
SELECT version, COUNT(*) as count
FROM nodes
WHERE is_vulnerable = true
  AND last_seen > NOW() - INTERVAL '7 days'
GROUP BY version
ORDER BY count DESC;
```

### Nodes with Exposed RPC
```sql
SELECT ip, port, country_code, asn, version, last_seen
FROM nodes
WHERE has_exposed_rpc = true
ORDER BY last_seen DESC
LIMIT 100;
```

### Scan History Summary
```sql
SELECT
    DATE(timestamp) as date,
    COUNT(*) as scans,
    SUM(total_nodes) as total_nodes,
    SUM(vulnerable_nodes) as vulnerable_nodes,
    AVG(duration_seconds) as avg_duration
FROM scans
WHERE status = 'completed'
GROUP BY DATE(timestamp)
ORDER BY date DESC;
```

### Node Churn (New vs Disappeared)
```sql
-- New nodes in last 7 days
SELECT COUNT(*) as new_nodes
FROM nodes
WHERE first_seen > NOW() - INTERVAL '7 days';

-- Nodes not seen in 30 days
SELECT COUNT(*) as stale_nodes
FROM nodes
WHERE last_seen < NOW() - INTERVAL '30 days';
```

## Performance Considerations

1. **Connection Pooling**: PostgreSQL connections use a pool with `pool_pre_ping=True` to handle stale connections.

2. **Bulk Operations**: Use `bulk_upsert()` for inserting many nodes efficiently (batches of 100).

3. **Indexes**: Key columns are indexed for fast queries. Don't add unnecessary indexes.

4. **SQLite Limitations**: SQLite doesn't support concurrent writes well. Use PostgreSQL for production.

## Troubleshooting

### Connection Errors

```
Error: Failed to connect to database
```

Check that:
1. `DATABASE_URL` is correctly formatted
2. Database server is running
3. Credentials are correct
4. Network allows connection

### Migration Errors

```
Error: alembic.util.exc.CommandError
```

Run `alembic current` to check state, then:
```bash
alembic stamp head  # Mark current state
alembic upgrade head  # Apply any pending
```

### Import Errors

```
Error: Database not configured
```

Ensure `DATABASE_URL` is exported before running import:
```bash
export DATABASE_URL=postgresql://...
python scripts/import_json_to_db.py --all
```
