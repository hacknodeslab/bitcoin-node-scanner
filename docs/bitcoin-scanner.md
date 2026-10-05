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

### Scan from a provided IP list (`--ips`)

Instead of discovering nodes via Shodan search queries, you can feed a list of
node IPs — e.g. exported from [b10c's peer-observer](https://github.com/0xB10C/peer-observer)
or `bitcoin-cli getnodeaddresses 0` — and look each one up in Shodan:

```bash
python -m src.scanner --ips data/peers/peers.txt
python -m src.scanner --ips peers.txt --max-ips 500 --rate 1
```

Input is tolerant: peer-observer's `host:port` (IPv4 `1.2.3.4:8333`, IPv6
`[2001:db8::1]:8333`), a plain IP per line, or CSV `ip,port`; blank lines and
`#` comments are ignored and IPs deduped.

- **Cost: none.** Shodan host lookups (`/shodan/host/{ip}`) consume **no query
  credits and no scan credits** — so this works even on the one-time Membership
  tier. The only limit is the API rate (~1 req/s, so ~3.5 h for ~12k IPs).
  `--max-ips` caps a run; `--rate` tunes the pacing.
- **IPs not in Shodan are skipped** (no on-demand scanning) and counted in the
  summary alongside IPs found and IPs with no Bitcoin service.
- Like the query-based scan, this **writes a JSON dump to `output/`** and does
  not persist; load it with `db-import`.

```bash
python -m src.db.cli db-import output/raw_data/nodes_<ts>.json
```

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

## IP reputation enrichment

Passive reputation context for node IPs, stored once per IP in `ip_reputation`
(shared by every `(ip, port)` row) and shown in the dashboard drawer's `host` tab.
Nothing is sent to the nodes themselves.

```bash
python -m src.db.cli db-enrich-ips --dry-run     # offline plan: candidates per risk, quota stop point
python -m src.db.cli db-enrich-ips --limit 500   # highest risk first (CRITICAL → HIGH → MEDIUM → LOW)
python -m src.db.cli db-enrich-ips --source blocklists
```

Staleness is tracked per source (`<source>_checked_at`): an IP is a candidate while any
available source has never checked it or checked it more than `REPUTATION_STALE_DAYS`
ago, and each source is only called for the IPs it still owes — a `--source blocklists`
run never makes IPs look done for AbuseIPDB. Re-running resumes where the last run
stopped. A rejected AbuseIPDB key (401/403) stops that source for the run without
spending the day's quota. Example IPs
(`is_example`) are never enriched.

| Source | What it gives | Limits | Disclosure |
|--------|---------------|--------|------------|
| `abuseipdb` | Abuse confidence score, total reports, last reported | 1,000 lookups/day (free), tracked per UTC day in `enrichment_quota`; HTTP 429 stops the source until the next day | Sends each node IP to AbuseIPDB — opt-in via `ABUSEIPDB_API_KEY` |
| `blocklists` | Which public lists the IP is on | None — lists cached 24h under `BLOCKLIST_CACHE_DIR` | None — matched locally |

Blocklists (select with `BLOCKLISTS`, comma-separated):

| Id | Source | Terms |
|----|--------|-------|
| `firehol_level1` | [FireHOL level1](https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset) | Aggregate of freely redistributable lists (includes bogons) |
| `spamhaus_drop` | [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) + [DROPv6](https://www.spamhaus.org/drop/dropv6.txt) | Free to use; some commercial use needs a Spamhaus agreement — remove it from `BLOCKLISTS` if that applies |
| `feodo` | [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/downloads/ipblocklist.txt) (botnet C2) | CC0 |
| `tor_exit` | [Tor bulk exit list](https://check.torproject.org/torbulkexitlist) | Public |

In the dashboard, filter with `blocklisted=true`, `blocklist=<id>`, `abuse_min=<0-100>` or
`reported=true` in the query bar, or the palette commands `node: filter blocklisted (any list)`,
`node: filter blocklist <id>`, `node: filter abuse score ≥ 25|75 (abuseipdb)` and
`node: filter reported (abuseipdb)`. Paste an IP into the query bar (or `ip=<addr>`) to find a node.

The same run can be started from the API with `POST /api/v1/enrichment/run`
(body `{"limit": 1-1000, "source": "abuseipdb" | "blocklists"}`); progress is read
from `GET /api/v1/scans/{job_id}` (`job_type: "enrichment"`).

---

## API

Bitcoin endpoints (under the shared API-key / CSRF auth — see the [API reference](API.md)):

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/nodes` | List scanned nodes (`risk_level`, `country`, `exposed`, `tor`, `is_example`, `ip`, `blocklisted=true`, `blocklist=<id>`, `abuse_min=<0-100>`, `reported=true`, `sort_by`, `sort_dir`, `limit`, `offset`) |
| GET | `/api/v1/nodes/countries` | Distinct country names |
| GET | `/api/v1/nodes/{id}/geo` | Geo + ASN detail for a single node |
| GET | `/api/v1/stats` | Aggregate statistics (TOTAL / EXPOSED / STALE / TOR / OK + by_risk_level, by_country) |
| GET | `/api/v1/vulnerabilities` | CVE catalogue (from the NVD) |
| POST | `/api/v1/scans` | Trigger a background scan; returns `job_id` |
| GET | `/api/v1/nodes/{id}` | Node detail incl. CVEs and `reputation` (null if never enriched) |
| GET | `/api/v1/scans/{job_id}` | Job status (`pending`/`running`/`completed`/`failed`) and `job_type` (`scan`/`enrichment`) |
| POST | `/api/v1/enrichment/run` | Start a bounded IP-reputation batch (`limit` 1–1000, optional `source`); 409 if one is running |

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
| `ABUSEIPDB_API_KEY` | No | Enables the AbuseIPDB reputation source (skipped when unset) |
| `ABUSEIPDB_DAILY_QUOTA` | No | AbuseIPDB lookups per UTC day (default `1000`) |
| `ABUSEIPDB_MIN_INTERVAL` | No | Seconds between AbuseIPDB requests (default `1`) |
| `REPUTATION_STALE_DAYS` | No | Re-enrich IPs whose reputation is older than this (default `7`) |
| `BLOCKLISTS` | No | Comma-separated blocklist ids (default all: `firehol_level1,spamhaus_drop,feodo,tor_exit`) |
| `BLOCKLIST_CACHE_DIR` | No | Blocklist download cache (default `.blocklist_cache`, refreshed every 24h) |

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
