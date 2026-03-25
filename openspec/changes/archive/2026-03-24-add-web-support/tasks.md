## 1. Dependencies and Configuration

- [x] 1.1 Add `fastapi`, `uvicorn[standard]`, and `python-multipart` to `requirements.txt`
- [x] 1.2 Add `WEB_API_KEY`, `WEB_HOST`, and `WEB_PORT` variables to `.env.example`
- [x] 1.3 Add `web` console script entry point to `pyproject.toml` pointing to `src.web.main:app`

## 2. Database Migration

- [x] 2.1 Create Alembic migration adding `scan_jobs` table with columns: `id` (UUID PK), `status`, `started_at`, `finished_at`, `result_summary` (JSON)
- [x] 2.2 Add `ScanJob` SQLAlchemy model in `src/db/models.py`
- [x] 2.3 Add `ScanJobRepository` class in `src/db/repositories.py` with methods: `create`, `get_by_id`, `update_status`, `get_active_job`

## 3. API Auth Middleware

- [x] 3.1 Create `src/web/auth.py` with FastAPI dependency `require_api_key` that reads `WEB_API_KEY` from env and validates `X-API-Key` header (returns 401 on mismatch or missing key)
- [x] 3.2 Add startup validation in `src/web/main.py` that raises `RuntimeError` if `WEB_API_KEY` is not set

## 4. REST API Routers

- [x] 4.1 Create `src/web/routers/nodes.py` implementing `GET /api/v1/nodes` with `risk_level` filter and `limit`/`offset` pagination
- [x] 4.2 Create `src/web/routers/stats.py` implementing `GET /api/v1/stats` returning aggregate counts from `NodeRepository`
- [x] 4.3 Create `src/web/routers/scans.py` implementing `POST /api/v1/scans` (trigger scan, enforce single-concurrent constraint) and `GET /api/v1/scans/{job_id}`
- [x] 4.4 Register all routers in `src/web/main.py` with `/api/v1` prefix and `require_api_key` dependency

## 5. Background Scan Executor

- [x] 5.1 Create `src/web/background.py` with `run_scan_job(job_id, db_session)` function that: updates job to `running`, calls existing scanner, persists nodes via `NodeRepository`, updates job to `completed` or `failed`
- [x] 5.2 Wire `run_scan_job` into FastAPI `BackgroundTasks` in the `POST /api/v1/scans` handler using `asyncio.get_event_loop().run_in_executor()` for thread isolation

## 6. Web Dashboard

- [x] 6.1 Create `src/web/static/index.html` — single-file dashboard with: stats summary cards, risk-level filter dropdown, node data table, "Start Scan" button with status indicator
- [x] 6.2 Implement JS in `index.html` to: fetch stats on load and every 30s, fetch nodes on load and on filter change, POST scan trigger and poll job status every 10s, disable scan button while job is active
- [x] 6.3 Mount `src/web/static/` as StaticFiles in `src/web/main.py` and serve `index.html` at `GET /`

## 7. Tests

- [x] 7.1 Write unit tests for `require_api_key` dependency (valid key, missing key, wrong key)
- [x] 7.2 Write integration tests for `GET /api/v1/nodes` and `GET /api/v1/stats` using FastAPI `TestClient` with a test SQLite DB
- [x] 7.3 Write integration tests for `POST /api/v1/scans` covering: success (202), concurrent conflict (409), and job status retrieval

## 8. Documentation

- [x] 8.1 Add "Web Interface" section to `README.md` with startup instructions, environment variables, and API key setup
- [x] 8.2 Verify FastAPI auto-generated docs are accessible at `/docs` and `/redoc` in development mode
