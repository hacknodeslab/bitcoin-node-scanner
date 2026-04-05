## Context

The Bitcoin Node Scanner already stores scanned node data in SQLite (via SQLAlchemy) and exposes a FastAPI web API with an HTML dashboard. The project needs to surface known CVE data for Bitcoin software so operators can correlate node versions against published vulnerabilities.

The NVD REST API v2 (`services.nvd.nist.gov/rest/json/cves/2.0`) is the authoritative public source for CVE data. Without an API key, it enforces a rate limit of 5 requests per 30 seconds; with a key, the limit is 50 requests per 30 seconds.

## Goals / Non-Goals

**Goals:**
- Fetch CVE entries related to Bitcoin (`keywordSearch=bitcoin` and/or CPE `cpe:2.3:a:bitcoin:bitcoin:*`) from NVD API v2
- Cache results in a new `cve_entries` database table to avoid repeat fetching
- Expose a `GET /api/v1/vulnerabilities` endpoint returning cached CVE data
- Render a vulnerabilities table in the web dashboard

**Non-Goals:**
- Automatic correlation between scanned node versions and affected CVE version ranges (future work)
- Alerting or notifications when new CVEs are discovered
- Support for non-Bitcoin CPEs or generic vulnerability scanning

## Decisions

### 1. NVD API v2 with keyword + CPE filter
**Decision**: Query `keywordSearch=bitcoin` with optional `cpeName=cpe:2.3:a:bitcoin:bitcoin:*` narrowing.
**Rationale**: The keyword search is broad enough to catch Bitcoin Core CVEs and related entries. CPE filtering alone can miss entries not yet assigned a CPE. Combining both gives the best recall.
**Alternatives considered**: Only CPE filter — misses entries in review state; only keyword — may include false positives which are acceptable at this scope.

### 2. On-demand fetch with DB cache (TTL-based)
**Decision**: Fetch from NVD on first request or when cache is older than a configurable TTL (default 24h). Store results in `cve_entries` table.
**Rationale**: Avoids hammering the NVD API on every dashboard load while keeping data reasonably fresh. Simpler than a background scheduler for an initial implementation.
**Alternatives considered**: Background scheduled job — more complex wiring, overkill for a research tool; no cache (always live) — rate limit violations with multiple users.

### 3. New `src/nvd/` module
**Decision**: Encapsulate all NVD interaction in `src/nvd/client.py` (HTTP calls + pagination) and `src/nvd/service.py` (cache logic, DB writes).
**Rationale**: Keeps web API routes thin; matches existing module pattern (`src/db/`, `src/web/`).

### 4. SQLite table `cve_entries`
**Decision**: New SQLAlchemy model with columns: `cve_id` (PK), `published`, `last_modified`, `severity`, `cvss_score`, `description`, `affected_versions` (JSON text), `fetched_at`.
**Rationale**: Aligns with existing SQLAlchemy/Alembic migration pattern already in place.

### 5. Optional NVD API key via environment variable
**Decision**: Read `NVD_API_KEY` from environment; if absent, proceed without key at lower rate limits with an appropriate delay between paginated requests.
**Rationale**: Makes the feature usable without registration while rewarding users who obtain a free API key.

## Risks / Trade-offs

- **NVD API unavailability** → The endpoint returns cached data if available, or a `503` with a clear message if the cache is empty and the upstream is unreachable.
- **Rate limiting without API key** → The client adds a `0.6s` sleep between paginated requests to stay within the 5/30s limit. With many CVE pages this fetch can be slow (~10s). Acceptable for an on-demand research tool.
- **SQLite JSON storage for `affected_versions`** → Stored as JSON text; no indexed querying. Sufficient for display purposes in v1.
- **False-positive CVEs** → Keyword search may return tangentially related results. Operators are expected to review descriptions themselves.

## Migration Plan

1. Add Alembic migration to create `cve_entries` table
2. Add `NVD_API_KEY` to `env.example` (optional)
3. New module `src/nvd/` — no changes to existing modules
4. Extend `src/web/main.py` with new router; extend dashboard HTML with new tab

Rollback: Remove the migration and the `src/nvd/` module. No existing functionality is altered.

## Open Questions

- Should `affected_versions` parsing attempt to match against scanned node versions for a risk badge? (Deferred to follow-on change.)
- Should there be a manual "Refresh CVEs" button in the dashboard, or only TTL-driven refresh?
