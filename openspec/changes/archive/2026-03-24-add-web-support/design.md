## Context

The Bitcoin Node Security Scanner is a Python CLI tool that uses the Shodan API to discover and assess vulnerable Bitcoin nodes. It has an optional database layer (PostgreSQL/SQLite via SQLAlchemy/Alembic) and produces JSON/CSV/text reports. The existing `src/db/` package provides repository classes for persisting scan results.

Adding web support means layering a FastAPI server on top of the existing code without touching CLI behavior. The server will read from the database, trigger scans as background tasks, and serve a lightweight dashboard.

## Goals / Non-Goals

**Goals:**
- REST API (FastAPI) for querying nodes, statistics, and managing scans
- Minimal web dashboard (server-rendered or single HTML file with vanilla JS) for non-CLI users
- Asynchronous scan execution so HTTP requests return immediately
- API key authentication to prevent unauthorized access
- Zero breaking changes to the CLI

**Non-Goals:**
- Real-time WebSocket streaming (can be added later)
- Full SPA framework (React/Vue) — keep frontend simple
- Multi-user auth / RBAC — single API key is sufficient for now
- Replacing the CLI — web is additive only

## Decisions

### 1. FastAPI over Flask/Django
FastAPI provides async support (needed for background tasks), automatic OpenAPI docs, and Pydantic validation with minimal boilerplate. Flask would require manual async handling; Django is too heavy for this use case.

### 2. Background tasks via FastAPI `BackgroundTasks` + asyncio, not Celery
Scans are long-running (~minutes) but infrequent. Celery adds Redis/RabbitMQ operational overhead not justified here. FastAPI's built-in `BackgroundTasks` + a `scan_jobs` table in the existing DB gives enough visibility without extra infrastructure.

**Alternative considered**: `concurrent.futures.ProcessPoolExecutor` directly — rejected because it doesn't integrate cleanly with FastAPI's lifecycle and lacks job status tracking.

### 3. Single HTML file dashboard, no build step
A single `src/web/static/index.html` with vanilla JS (fetch API) keeps the repo free of Node.js tooling. The dashboard reads from the REST API. This is sufficient for an internal security tool.

**Alternative considered**: React SPA — rejected; overkill for a research/internal tool.

### 4. API key auth via `X-API-Key` header
Simple, stateless, easy to rotate. Key stored in environment variable `WEB_API_KEY`. FastAPI dependency injection enforces it on every protected endpoint.

**Alternative considered**: JWT tokens — rejected; no need for per-user identity in a single-operator tool.

### 5. New `scan_jobs` table via Alembic migration
Tracks `id`, `status` (pending/running/completed/failed), `started_at`, `finished_at`, `result_summary`. This gives the API a way to report scan progress without polling the scanner process directly.

## Risks / Trade-offs

- **Long-running scans block the event loop** → Mitigation: run scanner in a `ThreadPoolExecutor` via `asyncio.get_event_loop().run_in_executor()` since existing scanner code is synchronous.
- **Single API key is a weak auth model** → Mitigation: document that the server should not be exposed publicly; recommend reverse proxy (nginx) with TLS.
- **Dashboard has no live updates** → Mitigation: auto-refresh every 30s via `setInterval`; WebSocket can be added later.
- **SQLite concurrency** → Mitigation: for production use, recommend PostgreSQL (already supported); SQLite is fine for single-user local use.

## Migration Plan

1. Add `fastapi`, `uvicorn[standard]`, `python-multipart` to `requirements.txt`
2. Create Alembic migration for `scan_jobs` table
3. Implement `src/web/` package: `main.py`, `routers/`, `auth.py`, `static/index.html`
4. Add `WEB_API_KEY` and `WEB_HOST`/`WEB_PORT` to `.env.example`
5. Add `web` entrypoint to `pyproject.toml` (`uvicorn src.web.main:app`)
6. Update README with web server usage instructions

**Rollback**: The web layer is entirely additive. Removing it means deleting `src/web/` and the Alembic migration; no other code changes needed.

## Open Questions

- Should the dashboard auto-trigger a new scan, or only show historical data from the DB? (Assumed: both — view history + trigger new scan)
- Rate-limit scan triggers to prevent accidental API abuse? (Assumed: yes, one concurrent scan at a time)
