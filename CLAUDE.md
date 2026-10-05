# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Python-based security reconnaissance tool for discovering and analyzing vulnerable Bitcoin nodes via the Shodan API. It combines a scanning engine, risk analyzer, SQLAlchemy database layer, FastAPI REST API, and a web dashboard.

## Common Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests
python -m pytest tests/ -v

# Run a single test module
python -m pytest tests/test_web_api.py -v

# Run tests with coverage
python -m pytest tests/ --cov=src --cov-report=term-missing

# Start the web API server (http://127.0.0.1:8000)
python -m src.web.main

# Run the scanner
python -m src.scanner
python -m src.scanner --quick            # Cache + limited enrichment
python -m src.scanner --check-credits    # Check Shodan API credits
python -m src.scanner --ips data/peers/peers.txt    # Scan a provided IP list via host lookups (not search)
python -m src.scanner --ips data/peers/peers.txt --max-ips 500 --rate 1
python -m src.scanner --ips data/peers/peers.txt --source-tag peer-observer  # tag added on db-import (default: ip-list)
python -m src.peers.fetch alt-bitnodes  # 8-day union of our alt-bitnodes crawler → data/peers/alt-bitnodes.txt (incremental cache; run daily)
python -m src.scanner --ips data/peers/alt-bitnodes.txt --source-tag alt-bitnodes
# NOTE: scanner runs write JSON/CSV to output/ only — they do NOT persist to
# the database. Load the results with `db-import` (see below).
# --ips mode: looks each IP up with api.host() (host:port / [ipv6]:port / CSV /
# IP-per-line input, e.g. a peer-observer export; `bitcoin-cli getnodeaddresses
# 0` returns JSON and must be converted first — jq recipe in
# docs/bitcoin-scanner.md). Host lookups consume NO query/scan credits (works on
# any tier incl. Membership); bounded by the API rate limit (~1 req/s) and
# --max-ips. IPs not in Shodan are skipped. Always writes a JSON dump (empty if
# nothing matched) → load with db-import, which tags the nodes with --source-tag.

# Run the Nostr relay CDN-recon scanner (phase 0 — measures % of relays behind a CDN)
python -m src.nostr.scanner data/relays.txt           # writes output/nostr_relays_<ts>.json
python -m src.nostr.scanner data/relays.txt --workers 100 --timeout 4
python -m src.nostr.extract_relays data/nw-relays.xlsx data/relays.txt --online --clearnet  # nostr.watch xlsx → host list
# NOTE: like the Bitcoin scanner, the Nostr scanner writes JSON only and does
# NOT persist — load the dump with `db-import-nostr` (see below). No Shodan
# credits used (pure DNS + CDN CIDR matching). Phase 2 (origin unmasking) is
# out of scope.

# Database CLI
python -m src.db.cli stats --days 30
python -m src.db.cli db-trends --days 30 --granularity week
python -m src.db.cli db-export --output output/export.json
python -m src.db.cli db-import output/raw_data/nodes_<ts>.json  # Load a scanner JSON dump into the DB
python -m src.db.cli db-import-nostr output/nostr_relays_<ts>.json  # Load a Nostr CDN-recon dump into the DB
python -m src.db.cli enrich-geo          # Retroactively enrich geo data
python -m src.db.cli db-link-cves        # (Re)build node→CVE links from cve_entries
python -m src.db.cli db-link-cves --scan-id 5  # limit to nodes of one scan
python -m src.db.cli db-mark-examples    # Reconcile is_example flag against canonical IP list
python -m src.db.cli db-seed-examples    # Upsert canonical example nodes (idempotent demo data)
python -m src.db.cli db-seed-examples --purge-extras  # also drop legacy is_example rows at non-canonical ports
python -m src.db.cli db-enrich-ips --dry-run   # IP-reputation plan (offline: candidates per risk, quota stop point)
python -m src.db.cli db-enrich-ips --limit 500 # AbuseIPDB + public blocklists, highest risk first; resumable
python -m src.db.cli db-enrich-ips --source blocklists  # local blocklist match only (no key, no quota)
```

## Required Environment Variables

```bash
SHODAN_API_KEY=       # Shodan API credentials (required for scanning)
WEB_API_KEY=          # Secret key for API authentication
DATABASE_URL=sqlite:///./bitcoin_scanner.db   # or PostgreSQL DSN
```

Optional: `MAXMIND_LICENSE_KEY`, `NVD_API_KEY`, `NVD_AUTO_RELINK` (default `true`; when truthy, refreshing the NVD catalog auto-rebuilds `node_vulnerabilities` for every persisted node — set to `false` if you'd rather run `db-link-cves` manually), `WEB_HOST`, `WEB_PORT`, `FRONTEND_ORIGIN` (origin of the Next.js dashboard at `frontend/`, default `http://localhost:3000`; comma-separated for multiple), `ENABLE_API_DOCS` (turns on `/docs`, `/redoc`, `/openapi.json`; default off), `OUTPUT_DIR` (also the root that `db-import`, `db-import-nostr` and the Nostr scanner's `--json` may read/write — default `output`), `INPUT_DIR` (root that `--ips`, the Nostr relay list and `extract_relays` may read/write — default `data`; see `src/safe_paths.py`), `LOG_LEVEL`, `QUERIES`, `QUERIES_OPTIMIZED`, `MAX_RESULTS_NORMAL` (per-query result cap for non-critical queries, default `500`), `MAX_RESULTS_CRITICAL` (cap for critical/RPC queries, default `1000`), `MAX_QUERY_CREDITS_PER_SCAN` (hard ceiling on Shodan search pages — and thus query credits — a single scan run may consume before it aborts; default `50`), `NOSTR_CDN_CACHE_DIR` (where the Nostr scanner caches CDN IP-range lists, default `.cdn_cache`; refreshed every 7 days), `ABUSEIPDB_API_KEY` (enables the AbuseIPDB reputation source; each lookup discloses the node IP to AbuseIPDB), `ABUSEIPDB_DAILY_QUOTA` (default `1000`, tracked per UTC day in the DB), `ABUSEIPDB_MIN_INTERVAL` (seconds between requests, default `1`), `REPUTATION_STALE_DAYS` (re-enrich after N days, default `7`), `BLOCKLISTS` (comma-separated ids, default `firehol_level1,spamhaus_drop,feodo,tor_exit`), `BLOCKLIST_CACHE_DIR` (default `.blocklist_cache`, refreshed every 24h). Copy `.env.example` to `.env` to start.

## Architecture

### Layer Overview

```
Shodan API ──► scanner.py ──► db/scanner_integration.py ──► SQLAlchemy ORM (db/models.py)
                                                                    │
                                                              db/repositories/
                                                                    │
                                                         web/routers/ (FastAPI · /api/v1)
                                                                    │
                                                       frontend/ (Next.js dashboard)
```

The repo has **two toolchains**: Python (uv/pip) for the backend at `src/` and Node (pnpm) for the dashboard at `frontend/`. They run as two processes — FastAPI on `:8000` exposes `/api/v1/*`, the Next.js app on `:3000` consumes it. `GET /` on the backend 302-redirects to `FRONTEND_ORIGIN`. FastAPI no longer serves any HTML.

- **Dev**: cross-origin (`localhost:3000` → `localhost:8000`). CORS allow-list driven by `FRONTEND_ORIGIN`.
- **Prod**: single-origin via nginx on port 80 (`/api/` → backend, `/` → Next.js). No CORS preflight from browsers. `NEXT_PUBLIC_API_BASE_URL=/api/v1` (relative). Both run as systemd units (`bitcoin-scanner.service` + `bitcoin-scanner-frontend.service`, sources in `scripts/systemd/`). Production is the LXC `pesquisa` (CT 113) on **frodo**, the HackNodes Proxmox on the lab LAN, published as `https://audit.hacknodes.xyz` through a Cloudflare Tunnel (no inbound ports). Provisioned with `scripts/bootstrap-host.sh`, deployed on-host with `scripts/deploy.sh` because CI cannot reach the LAN; see `docs/deploy-frodo.md`. The former AWS EC2 + CloudFront setup was decommissioned in September 2026; there is no CI deploy workflow any more. Gondor is the Librería de Satoshi Proxmox — not for this project.

### Key Modules (`src/`)

- **scanner.py** — Core orchestration; `BitcoinNodeScanner` runs full scans; `OptimizedBitcoinScanner` reduces Shodan credit usage with caching via `CachedNodeManager`.
- **analyzer.py** — `SecurityAnalyzer` assigns risk levels (CRITICAL/HIGH/MEDIUM/LOW) based on Bitcoin version, exposed RPC, and dev-version flags.
- **reporter.py** — Multi-format output (JSON, CSV, text reports).
- **geoip.py** — MaxMind GeoIP enrichment (separate from Shodan geo fields).
- **credit_tracker.py** — Monitors Shodan API credit consumption.
- **enrichers/** — Passive IP-reputation enrichment behind an `Enricher` protocol + `REGISTRY` (a new source = one module + one registry entry + its `<name>_checked_at` column): `abuseipdb.py` (per-IP `check` API, opt-in), `blocklists.py` (FireHOL level1 / Spamhaus DROP / Feodo / Tor exits, downloaded + cached + CIDR-matched locally), `quota.py` (DB-persisted per-source daily quota, atomic increments; 429 exhausts the day, 401/403 only disables the source for the run), `service.py` (candidate selection CRITICAL→LOW with per-source staleness — each source is only called for IPs it still owes —, example-IP exclusion, per-source failure isolation). Never sends traffic to the nodes. GreyNoise (50 lookups/week) and ipinfo (redundant ASN source) were evaluated and rejected.
- **peers/** — Peer-list sources that write `--ips`-ready files under `INPUT_DIR`. `alt_bitnodes.py` pulls snapshots from our alt-bitnodes crawler (`ALT_BITNODES_URL`, default https://pesquisa.hacknodes.xyz), unions the last `ALT_BITNODES_WINDOW_DAYS` (8) with a per-snapshot cache under `data/peers/alt-bitnodes/cache/`, and brackets IPv6 — its keys are unbracketed `ip:port`, which the generic `--ips` reader would misread. Skips onion/I2P/CJDNS/non-global. CLI: `python -m src.peers.fetch alt-bitnodes`. Uses `requests` with an explicit UA (CloudFront 403s `Python-urllib`).
- **nostr/** — Nostr relay CDN-recon (phase 0): `classifier.py` (normalize → resolve A/AAAA → CDN CIDR match → verdict), `cdn_ranges.py` (cached Cloudflare/CloudFront/Fastly ranges + hardcoded Cloudflare fallback), `scanner.py` (runnable; writes a JSON dump to `output/`), `extract_relays.py` (nostr.watch xlsx → host list). No Shodan credits; pure DNS. Loaded into the DB via `db-import-nostr`. Phase 2 (origin unmasking) is out of scope.

### Database Layer (`src/db/`)

Uses **SQLAlchemy 2.0** with SQLite (default) or PostgreSQL. Key models in `models.py`:
- `Node` — Bitcoin node with risk/geo/version data; indexes on `ip`, `(ip, port)`, `last_seen`, `risk_level`, `is_vulnerable`, `is_example`. The `is_example` flag is set automatically at write time for IPs in `src/example_ips.py`; backfill via `db-mark-examples`.
- `Scan` — Session metadata (queries, node count, credits used, status).
- `CVEEntry` — Vulnerability catalog from NVD with CVSS scores.
- `NodeVulnerability` — Many-to-many junction (node ↔ CVE) with detection timestamps.
- `ScanJob` — Background async job tracking (pending → running → completed/failed). `job_type` is `scan` or `enrichment`; single-flight is per type.
- `IpReputation` — One row per IP (unique `ip`, no FK to `nodes`; joined on `nodes.ip`): `abuse_*` columns, `blocklists_json`, `sources_json` (per-source status/payload), `<source>_checked_at` per source (drives candidate selection), `reputation_enriched_at` (last success of any source; display only). `EnrichmentQuota` — per-source per-UTC-day call counts. Kept off the `nodes` table on purpose (its `asn`/`org` columns are Shodan/MaxMind data).
- `NostrScan` / `NostrRelay` — Nostr relay CDN-recon (dedicated tables, independent of `Node`/`Scan`). `NostrRelay` is keyed by `host` (unique), stores `verdict`/`providers`/`ips`; indexes on `host`, `verdict`, `last_seen`. Re-importing upserts in place (one row per host). The list/stats queries scope to the latest `NostrScan`.

Repository pattern in `db/repositories/` abstracts all queries. `db/scanner_integration.py` bridges the scanner output into the database.

### Web API (`src/web/`)

FastAPI app mounted at `src/web/main.py`. Authentication via API key + CSRF (`auth.py`). Routers:
- `GET /api/v1/nodes` — Paginated, filterable node list (filters: `risk_level`, `country`, `exposed`, `tor`, `is_example`, `port`, `ip`, `blocklisted=true`, `blocklist=<id>`, `abuse_min=<0-100>`, `reported=true`; the reputation ones join `ip_reputation` and are mirrored as query-bar keys and palette commands. In the query bar a bare IP is shorthand for `ip=`). Each node payload includes `is_example: bool`.
- `GET /api/v1/stats` — Aggregate statistics
- `POST /api/v1/scans`, `GET /api/v1/scans/{job_id}` — Background scan jobs
- `GET /api/v1/vulnerabilities` — CVE lookups
- `GET /api/v1/nodes/{id}` includes `reputation` (null if never enriched; raw source payloads are not exposed). `POST /api/v1/enrichment/run` (API key + CSRF, body `{limit: 1-1000, source?}`) starts a background enrichment job; status via `GET /api/v1/scans/{job_id}`.
- `GET /api/v1/nostr/relays` — Paginated Nostr relay list from the latest scan (filters: `verdict`, `provider`, `behind_cdn`); `GET /api/v1/nostr/stats` — per-verdict counts, % behind CDN. Surfaced in the dashboard `/nostr` panel.
- `GET /api/v1/csrf-token` — CSRF token endpoint

Background scans run via `web/background.py` (async task executor) so they don't block the HTTP API. Swagger UI at `/docs`, ReDoc at `/redoc`, and `/openapi.json` are gated behind `ENABLE_API_DOCS` (set to `1`/`true`/`yes` in local dev; disabled by default to keep the public surface minimal).

### NVD Integration (`src/nvd/`)

Fetches CVE data from the National Vulnerability Database. `client.py` handles HTTP, `service.py` adds caching and database persistence, `models.py` defines the CVE schema.

### Frontend theming (`frontend/`)

Tokens are sourced from `/DESIGN.md`'s YAML front matter. The `themes:` map defines two colour palettes — `dark` (default) and `light` — both with the same 21 token names: the original 18 (`primary`, `bg`, `surface`, `surface-2`, `border`, `border-dim`, `text`, `text-dim`, `muted`, `dim`, `ok`, `warn`, `alert`, `on-primary`, `alert-bg`, `warn-bg`, `ok-bg`, `l402-bg`) plus the `accent` triplet (`accent`, `accent-bg`, `accent-border`) added by `mark-example-ips`. The accent triplet drives both the `EXAMPLE` pill and the selected-row tint — both palettes MUST keep them in sync. `pnpm tokens:gen` regenerates `frontend/lib/design-tokens.ts` (typed `themes` + `colors` exports) and the `:root` + `[data-theme="light"]` blocks inside `frontend/app/globals.css`. Tailwind utilities reference CSS custom properties, so the active theme swaps at runtime when `<html>` carries `data-theme="light"`.

The active mode (`dark` / `light` / `system`) lives in `localStorage['bns:theme']`. An inline pre-hydration script in `app/layout.tsx` (`THEME_INIT_SCRIPT` from `lib/theme.ts`) reads it before React mounts to avoid a flash of wrong theme. `ThemeProvider` (`components/providers/ThemeProvider.tsx`) owns the runtime state and tracks `prefers-color-scheme` only while in `system` mode.

## Important Conventions

- **CLI file paths are confined**: any file path taken from a command line goes through `src/safe_paths.py` (`safe_input_file` / `safe_output_file` / `*_write`), which resolves it and requires it under `INPUT_DIR` (default `data/`) or `OUTPUT_DIR` (default `output/`). This blocks `../`, absolute paths and symlink escapes when a command is driven by an automated agent. New CLI commands that open a user-named file must use it too.

- **Shodan credit efficiency**: The `OptimizedBitcoinScanner` and `CachedNodeManager` exist specifically to minimize API credit usage — avoid adding code paths that bypass this.
- **Dual geo sources**: Nodes have both Shodan-provided geo fields (`country_code`, `city`) and MaxMind fields (`geo_country_code`, `geo_subdivision`, `asn`). Don't conflate them.
- **Risk level enum**: Always use `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` strings (defined in `analyzer.py`) — not numeric scores.
- **Database portability**: Session management in `db/connection.py` handles SQLite foreign key pragmas automatically; PostgreSQL and SQLite behave differently for some queries.

## Registro en el segundo cerebro (Logseq)

Este repo es el código del proyecto **HackNodes Pesquisa**. Al terminar una sesión
con cambios relevantes, registra el trabajo en el grafo Logseq que está en:

  /Users/ifuensan/Work/hacknodes/myprojects/research/logseq-claude-brain

Reglas:
- La página del proyecto YA existe: `pages/HackNodes Pesquisa.md`. No crees una nueva.
- Respeta la sintaxis de bloques de Logseq (ver el `CLAUDE.md` de ese grafo): cada
  línea es un bloque `- `, propiedades `clave:: valor` en el primer bloque, NADA de
  frontmatter YAML.
- Bajo `## Log` añade un bloque (append-only, nunca borres los antiguos):
    - DONE [qué se hizo, en pasado]
      date:: [[Jun 18th, 2026]]   ← formato Logseq: MMM do, yyyy
- Si hubo una decisión, regístrala bajo `## Decisiones` con `por-que::` y `date::`.
- Añade una línea resumen en el journal del día `journals/YYYY_MM_DD.md`,
  enlazando al proyecto: `- Trabajé en [[HackNodes Pesquisa]]: <resumen>.`
- area:: de este proyecto es [[HackNodes]].
- Datos sensibles (claves, tokens Shodan/`.env`, IPs concretas de nodos vulnerables):
  NO los persistas en el grafo; resume sin exponer el dato crudo.
- Pídeme confirmación antes de escribir si tienes dudas.
