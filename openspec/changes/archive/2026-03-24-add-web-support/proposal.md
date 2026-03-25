## Why

The Bitcoin Node Security Scanner currently operates exclusively as a CLI tool, requiring users to run Python scripts and parse text/JSON output manually. Adding a web interface would make scan results accessible to non-technical stakeholders, enable real-time monitoring dashboards, and provide a REST API for integration with other security tooling.

## What Changes

- Add a FastAPI-based REST API server exposing scan triggers, node data, and statistics
- Add a web dashboard (HTML/JS) for browsing scan results, risk breakdowns, and historical trends
- Expose the existing database layer (PostgreSQL/SQLite) through API endpoints
- Add background task support so scans can be triggered and monitored asynchronously via the web
- Add authentication (API key) to protect the web interface and API

## Capabilities

### New Capabilities

- `web-api`: REST API server (FastAPI) exposing endpoints for scan management, node queries, and statistics retrieval
- `web-dashboard`: Browser-based dashboard for visualizing scan results, risk levels, and geographic distribution
- `background-scan`: Asynchronous scan execution with status tracking, triggered via API or dashboard

### Modified Capabilities

<!-- No existing spec-level requirements are changing; this is purely additive -->

## Impact

- **New dependencies**: `fastapi`, `uvicorn`, `python-multipart`, `python-jose` (JWT/API key auth)
- **Existing code**: `src/db/` repositories will be consumed by new API layer; `src/scanner.py` will be wrapped in a background task runner
- **Database schema**: May require a new `scan_jobs` table to track async scan state
- **Deployment**: New entry point `src/web/main.py`; Docker/docker-compose updates recommended
- **No breaking changes** to existing CLI interface
