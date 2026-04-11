## 1. Database Migration

- [x] 1.1 Create SQLAlchemy model `CVEEntry` in `src/db/models.py` with columns: `cve_id`, `published`, `last_modified`, `severity`, `cvss_score`, `description`, `affected_versions`, `fetched_at`
- [x] 1.2 Generate Alembic migration to create the `cve_entries` table
- [x] 1.3 Run migration and verify table creation in `bitcoin_scanner.db`

## 2. NVD API Client

- [x] 2.1 Create `src/nvd/` package with `__init__.py`
- [x] 2.2 Define `CVEEntry` dataclass and `NVDAPIError` exception in `src/nvd/models.py`
- [x] 2.3 Implement `NVDClient` in `src/nvd/client.py` with paginated fetch, API key support, and rate-limit delay
- [x] 2.4 Implement response mapping from NVD JSON to `CVEEntry` (CVSS v3/v2 priority, fallback to UNKNOWN)
- [x] 2.5 Add `NVD_API_KEY` and `NVD_CACHE_TTL_HOURS` to `env.example`

## 3. Vulnerability Service (Cache Logic)

- [x] 3.1 Implement `NVDService` in `src/nvd/service.py` with `get_vulnerabilities()` method
- [x] 3.2 Implement TTL check: return cached records if `fetched_at` is within TTL
- [x] 3.3 Implement upsert logic: insert or update `cve_entries` records on refresh
- [x] 3.4 Return entries sorted by `cvss_score` DESC, NULLs last

## 4. Web API Endpoint

- [x] 4.1 Create `src/web/routers/vulnerabilities.py` with `GET /api/v1/vulnerabilities` route
- [x] 4.2 Wire up `NVDService` inside the route; return 503 if NVD is unreachable and cache is empty
- [x] 4.3 Register the vulnerabilities router in `src/web/main.py`

## 5. Web Dashboard

- [x] 5.1 Add "Vulnerabilities" tab/section to the dashboard HTML template
- [x] 5.2 Implement JavaScript fetch from `/api/v1/vulnerabilities` on tab activation
- [x] 5.3 Render CVE table with columns: CVE ID, Severity (color badge), CVSS Score, Published Date, Description (truncated)
- [x] 5.4 Add loading indicator and error state message to the vulnerabilities section
- [x] 5.5 Display "Last updated: <relative time>" subtitle using `fetched_at` from response

## 6. Tests

- [x] 6.1 Unit test `NVDClient` with mocked HTTP responses (paginated success, 403 error, timeout)
- [x] 6.2 Unit test `NVDService` cache logic (fresh cache, stale cache, empty cache)
- [x] 6.3 Integration test `GET /api/v1/vulnerabilities` (200 with data, 503 on unavailable NVD with empty cache)
