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

# Database CLI
python -m src.db.cli db-stats --days 30
python -m src.db.cli db-trends --days 30 --granularity week
python -m src.db.cli db-export --output export.json
python -m src.db.cli enrich-geo          # Retroactively enrich geo data
```

## Required Environment Variables

```bash
SHODAN_API_KEY=       # Shodan API credentials (required for scanning)
WEB_API_KEY=          # Secret key for API authentication
DATABASE_URL=sqlite:///./bitcoin_scanner.db   # or PostgreSQL DSN
```

Optional: `MAXMIND_LICENSE_KEY`, `NVD_API_KEY`, `WEB_HOST`, `WEB_PORT`, `FRONTEND_ORIGIN` (origin of the Next.js dashboard at `frontend/`, default `http://localhost:3000`; comma-separated for multiple), `ENABLE_API_DOCS` (turns on `/docs`, `/redoc`, `/openapi.json`; default off), `OUTPUT_DIR`, `LOG_LEVEL`, `QUERIES`, `QUERIES_OPTIMIZED`.

## Architecture

### Layer Overview

```
Shodan API ──► scanner.py ──► db/scanner_integration.py ──► SQLAlchemy ORM (db/models.py)
                                                                    │
                                                              db/repositories/
                                                                    │
                                                         web/routers/ (FastAPI)
                                                                    │
                                                          web/static/ (Dashboard)
```

### Key Modules (`src/`)

- **scanner.py** — Core orchestration; `BitcoinNodeScanner` runs full scans; `OptimizedBitcoinScanner` reduces Shodan credit usage with caching via `CachedNodeManager`.
- **analyzer.py** — `SecurityAnalyzer` assigns risk levels (CRITICAL/HIGH/MEDIUM/LOW) based on Bitcoin version, exposed RPC, and dev-version flags.
- **reporter.py** — Multi-format output (JSON, CSV, text reports).
- **geoip.py** — MaxMind GeoIP enrichment (separate from Shodan geo fields).
- **credit_tracker.py** — Monitors Shodan API credit consumption.

### Database Layer (`src/db/`)

Uses **SQLAlchemy 2.0** with SQLite (default) or PostgreSQL. Key models in `models.py`:
- `Node` — Bitcoin node with risk/geo/version data; indexes on `ip`, `(ip, port)`, `last_seen`, `risk_level`, `is_vulnerable`.
- `Scan` — Session metadata (queries, node count, credits used, status).
- `CVEEntry` — Vulnerability catalog from NVD with CVSS scores.
- `NodeVulnerability` — Many-to-many junction (node ↔ CVE) with detection timestamps.
- `ScanJob` — Background async job tracking (pending → running → completed/failed).

Repository pattern in `db/repositories/` abstracts all queries. `db/scanner_integration.py` bridges the scanner output into the database.

### Web API (`src/web/`)

FastAPI app mounted at `src/web/main.py`. Authentication via API key + CSRF (`auth.py`). Routers:
- `GET /api/v1/nodes` — Paginated, filterable node list
- `GET /api/v1/stats` — Aggregate statistics
- `POST /api/v1/scans`, `GET /api/v1/scans/{job_id}` — Background scan jobs
- `GET /api/v1/vulnerabilities` — CVE lookups
- `GET /api/v1/csrf-token` — CSRF token endpoint

Background scans run via `web/background.py` (async task executor) so they don't block the HTTP API. Swagger UI at `/docs`, ReDoc at `/redoc`, and `/openapi.json` are gated behind `ENABLE_API_DOCS` (set to `1`/`true`/`yes` in local dev; disabled by default to keep the public surface minimal).

### NVD Integration (`src/nvd/`)

Fetches CVE data from the National Vulnerability Database. `client.py` handles HTTP, `service.py` adds caching and database persistence, `models.py` defines the CVE schema.

### Frontend theming (`frontend/`)

Tokens are sourced from `/DESIGN.md`'s YAML front matter. The `themes:` map defines two colour palettes — `dark` (default) and `light` — both with the same 18 token names. `pnpm tokens:gen` regenerates `frontend/lib/design-tokens.ts` (typed `themes` + `colors` exports) and the `:root` + `[data-theme="light"]` blocks inside `frontend/app/globals.css`. Tailwind utilities reference CSS custom properties, so the active theme swaps at runtime when `<html>` carries `data-theme="light"`.

The active mode (`dark` / `light` / `system`) lives in `localStorage['bns:theme']`. An inline pre-hydration script in `app/layout.tsx` (`THEME_INIT_SCRIPT` from `lib/theme.ts`) reads it before React mounts to avoid a flash of wrong theme. `ThemeProvider` (`components/providers/ThemeProvider.tsx`) owns the runtime state and tracks `prefers-color-scheme` only while in `system` mode.

## Important Conventions

- **Shodan credit efficiency**: The `OptimizedBitcoinScanner` and `CachedNodeManager` exist specifically to minimize API credit usage — avoid adding code paths that bypass this.
- **Dual geo sources**: Nodes have both Shodan-provided geo fields (`country_code`, `city`) and MaxMind fields (`geo_country_code`, `geo_subdivision`, `asn`). Don't conflate them.
- **Risk level enum**: Always use `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` strings (defined in `analyzer.py`) — not numeric scores.
- **Database portability**: Session management in `db/connection.py` handles SQLite foreign key pragmas automatically; PostgreSQL and SQLite behave differently for some queries.
