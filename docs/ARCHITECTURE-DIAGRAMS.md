# Architecture Diagrams

How the pieces of the HackNodes Recon Platform relate. Both diagrams render on
GitHub (Mermaid). Companion to `docs/ARCHITECTURE.md` (system map and
lifecycle walkthroughs) — this file focuses on the data-flow and entity
relations.

## Data flow

All recon is **passive**: data comes from third-party databases and public
lists; the platform never sends traffic to the nodes it tracks.

```mermaid
flowchart LR
    subgraph EXT["Passive sources (no traffic to target nodes)"]
        SHODAN["Shodan API<br/><i>search queries · host lookups</i>"]
        NVD["NVD API<br/><i>CVE catalog</i>"]
        MM[("MaxMind GeoLite2<br/><i>local .mmdb files</i>")]
        ABUSE["AbuseIPDB API<br/><i>1,000 checks/day quota</i>"]
        BL["Public blocklists<br/><i>FireHOL · Spamhaus DROP ·<br/>Feodo · Tor exits</i>"]
        DNS["DNS + CDN CIDR ranges<br/><i>Nostr recon</i>"]
    end

    subgraph INGEST["Ingestion & enrichment (src/)"]
        SCAN["scanner.py<br/><i>BitcoinNodeScanner ·<br/>OptimizedBitcoinScanner<br/>+ CachedNodeManager</i>"]
        NOSTR["nostr/<br/><i>relay CDN-recon</i>"]
        GEO["geoip.py<br/><i>gap-filling:<br/>Shodan wins on conflicts</i>"]
        ENR["enrichers/<br/><i>abuseipdb · blocklists ·<br/>quota · service</i>"]
        NVDS["nvd/<br/><i>client · service · matcher</i>"]
        CT["credit_tracker.py<br/><i>local Shodan usage log</i>"]
    end

    subgraph DB["Persistence (src/db/) — SQLAlchemy · SQLite | PostgreSQL"]
        MODELS["models.py<br/><i>ORM</i>"]
        REPO["repositories/<br/><i>all queries</i>"]
        SHARED["shared logic<br/><i>importer · exporter ·<br/>geo_enrichment · analysis</i>"]
        MIG["migrations/<br/><i>Alembic 001–009</i>"]
    end

    subgraph SURFACE["Surfaces"]
        CLI["db/cli.py<br/><i>stats · db-trends · db-export ·<br/>db-import · enrich-geo · db-enrich-ips</i>"]
        API["web/ · FastAPI /api/v1<br/><i>API key + CSRF ·<br/>background.py job pool</i>"]
        DASH["frontend/ · Next.js<br/><i>explorer · drawer · ⌘K palette<br/>(palette ↔ REST parity)</i>"]
        RPT["reporter.py<br/><i>JSON/CSV/text → output/</i>"]
    end

    SHODAN --> SCAN
    DNS --> NOSTR
    MM --> GEO --> SCAN
    NVD --> NVDS
    ABUSE --> ENR
    BL --> ENR
    SCAN --> CT
    SCAN --> RPT
    SCAN --> SHARED
    NOSTR --> SHARED
    ENR --> SHARED
    NVDS --> SHARED
    SHARED --> REPO --> MODELS
    MIG --> MODELS
    CLI --> SHARED
    API --> REPO
    DASH --> API
```

Key flows:

- **Bitcoin scan** — `scanner.py` queries Shodan (search queries, or `--ips`
  host lookups which cost no credits), enriches with MaxMind geo gaps, writes
  JSON dumps via `reporter.py` and/or persists through
  `db/scanner_integration.py`. Credit usage is tracked locally.
- **Reputation enrichment** — `enrichers/` runs per-IP AbuseIPDB lookups under
  a DB-persisted daily quota, plus local blocklist matching; results land in
  `ip_reputation` (one row per IP, shared by all node rows with that IP).
- **NVD correlation** — `nvd/` refreshes the CVE catalog and rebuilds
  `node_vulnerabilities` links (`db-link-cves`).
- **Serving** — the FastAPI layer (`web/`) exposes the data; long-running work
  (scans, enrichment, geo backfill) runs as `ScanJob`s in
  `web/background.py`'s thread pool, with per-`job_type` single-flight. The
  Next.js dashboard consumes the API; every palette command maps 1:1 to a REST
  endpoint (DESIGN.md D10).
- **CLI** — `src/db/cli.py` shares the same persistence logic
  (`db/importer.py`, `db/exporter.py`, `db/geo_enrichment.py`,
  `db/analysis.py`) as the web layer, so both surfaces behave identically.

## Data model

```mermaid
erDiagram
    SCANS }o--o{ NODES : "scan_nodes (M:N, CASCADE)"
    NODES ||--o{ NODE_VULNERABILITIES : "detected on"
    CVE_ENTRIES ||--o{ NODE_VULNERABILITIES : "linked via cve_id"
    NODES }o..o| IP_REPUTATION : "joined on ip (no FK — one row per IP)"
    NOSTR_SCANS ||--o{ NOSTR_RELAYS : "SET NULL"

    SCANS {
        int id PK
        datetime timestamp
        string status
        int total_nodes
    }
    NODES {
        int id PK
        string ip "idx, unique with port"
        int port
        string risk_level "CRITICAL|HIGH|MEDIUM|LOW"
        bool is_example "RFC 5737 demo IPs"
        string country_code "Shodan"
        string geo_country_code "MaxMind — never overwritten"
    }
    CVE_ENTRIES {
        string cve_id PK
        string severity
        float cvss_score
    }
    NODE_VULNERABILITIES {
        int node_id FK
        string cve_id FK
        datetime detected_at
        datetime resolved_at "null = active"
    }
    IP_REPUTATION {
        string ip PK
        int abuse_confidence_score
        text blocklists "JSON list of matched list ids"
        text sources_json "per-source provenance"
        datetime reputation_enriched_at "drives staleness"
    }
    ENRICHMENT_QUOTA {
        string source
        date day_utc "unique with source"
        int calls
    }
    SCAN_JOBS {
        string id PK
        string job_type "scan | enrichment"
        string status "pending→running→completed|failed"
    }
    NOSTR_RELAYS {
        int id PK
        string url
        string cdn_provider
        int scan_id FK "nullable"
    }
```

Notes:

- `ip_reputation` has **no foreign key** to `nodes` on purpose: reputation
  outlives node-row churn, and the join column (`nodes.ip`) is not unique.
- `enrichment_quota` persists per-source daily call counts so CLI and API runs
  share one budget across restarts.
- `scan_jobs.job_type` lets an enrichment batch run concurrently with a scan,
  but never two jobs of the same type.
- The Nostr domain (`nostr_scans`, `nostr_relays`) is a second recon domain
  sharing the same persistence, API and dashboard.
