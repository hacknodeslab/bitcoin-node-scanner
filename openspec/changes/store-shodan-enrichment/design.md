## Context

The Shodan API returns two tiers of data:

1. **Search result** (`api.search`) — one record per (IP, port) hit. Contains: `ip_str`, `port`, `transport`, `product`, `version`, `data` (banner), `org`, `isp`, `os`, `hostnames`, `domains`, `vulns`, `cpe`, `tags`, `location`, `asn`.
2. **Host scan** (`api.host(ip)`) — full host profile. Contains everything above PLUS `data[]` array with one entry per open port (each with `port`, `transport`, `product`, `version`, `service name`). Costs 1 scan credit.

Currently `parse_node_data` captures `hostnames`, `domains`, `vulns`, `cpe` but they're not in the DB. `enrich_with_host_scan` captures `all_ports`, `all_services`, `os`, `tags`, `vulns` but the enrichment dict is only used in-memory for risk scoring — never written to DB.

## Goals / Non-Goals

**Goals:**
- Persist all available Shodan fields from the base search result (os, hostnames, isp, org, vulns, cpe, tags) — zero extra API calls
- When enrichment runs (critical nodes), persist the full port/service table
- Expose everything via `NodeOut` and the modal

**Non-Goals:**
- Trigger additional Shodan API calls beyond what already happens
- Parse or analyse CVE details (store raw CVE IDs only)
- SSL certificate data (separate concern)

## Decisions

**D1 — Store variable-length lists as JSON text columns**
`open_ports_json`, `vulns_json`, `tags_json`, `cpe_json` stored as `Text` (JSON-serialised). Avoids schema churn for list fields; simple to query in Python. Alternative: separate tables (ports, vulns) — over-engineered for current read-only use case.

**D2 — Base result fields (os, hostnames, isp, org) go in every scan**
`os`, `hostnames` (first hostname only stored as `hostname` string; full list in `hostnames_json`), `isp`, `org` are available in every search result record. No extra credit needed.

**D3 — Enrichment fields overwrite on upsert if enrichment ran**
`open_ports_json` and `tags_json` (full host scan) are only set when `enrichment` key is present in node_data. Base `vulns` from search result goes in `vulns_json` regardless.

**D4 — `isp` and `org` already parsed, just not persisted**
`parse_node_data` already extracts `isp` and `organization`. They just need DB columns and the upsert to include them.

## Risks / Trade-offs

- [Risk] JSON blobs make SQL queries on port data hard → Acceptable; the use case is display only
- [Trade-off] `hostname` stored as first entry only for easy display; full list in `hostnames_json`
- [Trade-off] Existing nodes won't have enrichment data until re-scanned or `db enrich-geo` equivalent is run

## Migration Plan

1. Add migration `006_add_enrichment_fields.py` — nullable columns, no data backfill needed
2. Deploy updated `models.py`, `scanner_integration.py`, `scanner.py`
3. Existing nodes show `null` for new fields until next scan
4. Rollback: revert migration + code
