# State Machines

Every explicit and implicit state machine in the scanner, its states, invariants,
transition tables, and the invalid states/transitions the code can actually reach
(including via retries and concurrency). Bugs that were confirmed in code are
listed with evidence and linked to the issue that fixed them.

Status legend: **[FIXED]** = fixed with regression tests; **[CONFIRMED]** =
reachable in the current code, documented, intentionally not changed; **[BY DESIGN]**
= looks invalid but is intended.

---

## 1. ScanJob (background job) — `scan_jobs` table

Explicit. States: `pending`, `running`, `completed`, `failed`
(`src/db/models.py:301`). `job_type` is `scan` or `enrichment`; single-flight is
per type, enforced in the DB by the partial unique index
`uq_scan_jobs_active_per_type` (`src/db/models.py:311-315`, also created for
pre-existing DBs in `src/db/connection.py:218-221`).

### Transition table

| From      | Event                                   | To        | Code |
|-----------|-----------------------------------------|-----------|------|
| —         | `POST /api/v1/scans` (or enrichment)    | `pending` | `src/web/routers/scans.py:49`, `src/db/repositories/scan_job_repository.py:21` |
| `pending` | background task starts                  | `running` | `src/web/background.py:70` |
| `running` | work returns                            | `completed` | `src/web/background.py:87` |
| `running` | work raises                             | `failed`  | `src/web/background.py:84-85` |

### Invariants

- I1: at most one job per `job_type` in (`pending`, `running`) — DB-enforced.
- I2: `started_at` set exactly once, on the `pending → running` transition.
- I3: `finished_at` set exactly once, on entry to a terminal state.
- I4: terminal states (`completed`, `failed`) are final — no transition out.

### Invalid states reachable (before fixes)

1. **Stuck `pending` / `running` → permanent single-flight deadlock [FIXED — Issue 1].**
   - `src/web/background.py:64-67`: if `get_session_factory()` is None the task
     returns without touching the job — the row stays `pending` forever.
   - `src/web/background.py:70`: the `running` mark is *outside* the `try`, so any
     exception there (DB locked, reaped job) leaves the row `pending` forever.
   - Process crash/restart between `POST` and background-task execution leaves
     `pending` (or `running`) rows behind. Because I1 is enforced in the database,
     every subsequent `POST` then gets 409 forever
     (`src/web/routers/scans.py:41-46`, `src/web/routers/enrichment.py:57-62`).
   - No reaper, timeout, or recovery path existed anywhere.
2. **Terminal-state overwrite [FIXED — Issue 1].** `update_status` accepted any
   status string and reset `started_at`/`finished_at`
   (`src/db/repositories/scan_job_repository.py:37-51` before the fix), so
   re-invoking `_run_job` for the same `job_id` (duplicate background task,
   manual retry) drove `completed → running → completed`, violating I2/I3/I4.

---

## 2. Scan (scan session) — `scans` table

Explicit. States: `running`, `completed`, `failed`
(`src/db/models.py:146`). A separate lifecycle from `ScanJob`: one `ScanJob`
drives one `Scan`, but the CLI (`python -m src.scanner`) and
`scripts/full_db_scan.py` create `Scan` rows without any job.

### Transition table

| From      | Event                                   | To        | Code |
|-----------|-----------------------------------------|-----------|------|
| —         | scan session starts                     | `running` | `src/db/scanner_integration.py:182-185` |
| `running` | scan finishes, stats saved              | `completed` | `src/db/repository/scan_repository.py:72` (`complete`) |
| `running` | scan raises                             | `failed`  | `src/db/repositories/scan_repository.py:134` (`fail`), invoked from `src/db/scanner_integration.py:348-357` |
| —         | JSON import (CLI or REST)               | `completed` (created directly) | `src/db/repositories/scan_repository.py:109-121` (`record_import`) |

### Invariants

- I1: a `running` scan always terminates `completed` or `failed` — the wrapper
  catches all exceptions (`src/db/scanner_integration.py:335-357`).
- I2: `error_message` is non-NULL iff status is `failed`.
- I3: import rows are always born `completed` and carry the
  `json-import:<source>` provenance marker (`src/db/importer.py:198-209`).
- I4: stats columns (`total_nodes`, …) are only meaningful when `completed`.

### Invalid states reachable

1. **Stuck `running` [CONFIRMED, low impact].** If the process is killed after
   `_start_scan_session` but before `_complete_scan_session`, the row stays
   `running` forever. Unlike `ScanJob` there is no unique-index deadlock (nothing
   blocks new scans), but `count_by_status` and dashboards show a phantom active
   scan, and `get_statistics` silently drops it (it only aggregates
   `status="completed"`). Not fixed: recovery would need a reaper policy for the
   CLI-driven lifecycle too; scans routinely run for hours.
2. **`duration_seconds` NULL on a `completed` row [BY DESIGN]** — set from
   `self._scan_start_time`, which is None if timing data is missing.

---

## 3. NodeVulnerability link — `node_vulnerabilities` table

Implicit lifecycle per (node, CVE) pair. A row is **active** when
`resolved_at IS NULL`, **resolved** otherwise. Re-detection after resolution
creates a *new* row (history is kept by design).

### Transition table

| From              | Event                                   | To                | Code |
|-------------------|-----------------------------------------|-------------------|------|
| —                 | node's version starts matching a CVE    | active (insert)   | `VulnerabilityRepository.sync_node_links` / `link_to_node` |
| active            | node's version no longer matches        | resolved (`resolved_at` set) | `sync_node_links`, `resolve_for_node`, `resolve_all_for_node` |
| resolved          | version matches again                   | new active row    | `sync_node_links` |

### Invariants

- I1: at most one *active* row per (node_id, cve_id) — **not DB-enforced
  before Issue 2**.
- I2: `resolved_at` set at most once per row (no row is resurrected).
- I3: `node.is_vulnerable` mirrors "has ≥1 active link" (kept in sync by
  `src/nvd/service.py:125-150` and `src/db/scanner_integration.py`).

### Invalid states reachable (before fixes)

1. **Duplicate active rows per (node, CVE) [FIXED — Issue 2].** Neither
   `link_to_node` nor `sync_node_links` is atomic: both read the active set and
   insert afterwards (`src/db/repositories/vulnerability_repository.py:62-80,
   109-154`), and there was no unique constraint — only non-unique indexes
   (`src/db/models.py:208-213`). Two concurrent relinks can both observe "no
   active link" and both insert. Reachable in practice: a scan's NVD refresh
   with `NVD_AUTO_RELINK` (`src/db/scanner_integration.py:196-200`) runs in the
   scanner thread while `GET /api/v1/vulnerabilities` can refresh in a request
   thread (`src/web/routers/vulnerabilities.py:57-68`) — separate sessions, same
   node set. On PostgreSQL this is a genuine lost-update race; on SQLite the
   writer lock usually degrades it to "database is locked". Impact: inflated
   affected-node counts on CVEs and the dashboard.
2. **`is_vulnerable` disagreeing with links [CONFIRMED, self-healing].** A crash
   between the link sync and the flag update leaves them inconsistent until the
   next relink (`NVD_AUTO_RELINK` on refresh, or `db-link-cves`).

---

## 4. NVD cache — `cve_entries` table

Implicit TTL state machine. States: **empty** (no rows), **fresh**
(`max(fetched_at)` within `NVD_CACHE_TTL_HOURS`, default 24 h), **stale**.

| From    | Event                     | To     | Code |
|---------|---------------------------|--------|------|
| empty/stale | `get_vulnerabilities()` called | fresh (fetch + upsert + optional relink) | `src/nvd/service.py:41-45, 69-123` |

Invariants: every read of a stale/empty cache triggers exactly one refresh;
a refresh upserts by `cve_id` (idempotent, no duplicates); when
`NVD_AUTO_RELINK` is truthy a changed catalog rebuilds all node links.

### Invalid states / bugs

1. **Refresh SQL not portable to PostgreSQL [FIXED — Issue 3].** `_refresh`
   used `sqlalchemy.dialects.sqlite.insert(...).on_conflict_do_update(...)`
   (`src/nvd/service.py:9, 94-116` before the fix) — SQLite-only syntax that
   fails on the PostgreSQL deployments the schema and engine setup otherwise
   support (`src/db/connection.py:76-86`, `postgresql_where` in models). On PG,
   every TTL refresh raised; `/api/v1/vulnerabilities` only catches `NVDAPIError`
   so a stale cache + PG = unhandled 500.
2. **Two concurrent refreshes [CONFIRMED, benign].** Both fetch from NVD and
   upsert the same `cve_id`s; upsert makes the second a no-op. Wasteful (two
   upstream calls) but not incorrect.

---

## 5. IP reputation per-source lifecycle — `ip_reputation` table

Implicit, per (IP, source) pair. Persisted state lives in
`sources_json` (`status: ok | partial | error`) and the typed
`<source>_checked_at` columns (`src/db/models.py:349-350`,
`src/db/repositories/reputation_repository.py:84-95`).

| State | Meaning | Transition |
|-------|---------|------------|
| pending | row absent, or `<source>_checked_at` NULL | → checked on successful enrich |
| checked | `<source>_checked_at` set within `REPUTATION_STALE_DAYS` (default 7) | → due when older than cutoff |
| due | checked_at NULL or stale — candidate for re-enrichment | → checked/partial/error |
| partial | data saved but incomplete; source stays due (`src/enrichers/service.py:104-113`) | → checked on clean retry |
| error | source failed for this IP; stays due (`src/enrichers/service.py:115-117`) | → checked on later success |

Invariants: `calls` in `enrichment_quota` never exceeds the daily limit even
with concurrent runs (atomic conditional UPDATE,
`src/enrichers/quota.py:89-109`); a quota-bound source is never re-spent on IPs
it already covers (`due` map, `src/enrichers/service.py:76-82`); example IPs are
never enriched (`src/enrichers/service.py:67`).

### Invalid states reachable

1. **`exhausted` flag vs `calls` [BY DESIGN].** `remaining()` returns 0 when
   `exhausted` even if `calls < limit` (429-driven), and `sync_remaining` may
   raise `calls` above the nominal limit to match the server — deliberate, the
   server is the source of truth.
2. **Retry quota burn [CONFIRMED, accepted].** `AbuseIPDBEnricher._lookup`
   consumes quota *before* each HTTP attempt and retries up to 3 times
   (`src/enrichers/abuseipdb.py:126-159`), so transient network failures spend
   2–3× quota per IP. Each retry is a real upstream call, so the count is
   honest; not changed.
3. **Auth rejection disables the source for the run only [BY DESIGN]**
   (`_disabled` flag, `src/enrichers/abuseipdb.py:117-123`): the next run retries
   with the same key, on the theory a revoked key gets fixed.

---

## 6. EnrichmentQuota — `enrichment_quota` table

Implicit daily budget. One row per (source, UTC day). `calls` monotonically
increases; `exhausted` is a one-way latch set by HTTP 429 or quota exhaustion.

Invariants: I1 `calls <= limit` while not exhausted (conditional UPDATE with
`calls < limit` predicate, `src/enrichers/quota.py:100-105`); I2 at most one
row per (source, day) (unique index, `src/db/models.py:379`); I3 concurrent
`consume()` calls can't both win the last slot (atomic UPDATE rowcount check).

No invalid states found. `_ensure_row` converts a concurrent-insert
`IntegrityError` into a rollback by design (`src/enrichers/quota.py:56-66`),
relying on the enrichment service committing reputation writes per chunk before
quota calls — the comment's assumption holds because `run_enrichment` runs
sources sequentially within a chunk (`src/enrichers/service.py:76-121`).

---

## 7. Geo enrichment batch — node table scan

Implicit batch cursor. `enrich_nodes_geo` walks all nodes in batches of 500,
gap-filling Shodan-NULL fields with MaxMind data
(`src/db/geo_enrichment.py`).

### Invalid transitions

1. **Unstable cursor [FIXED — Issue 4].** Pagination was
   `OFFSET n LIMIT 500` with **no ORDER BY** (`src/db/geo_enrichment.py:44-45`
   before the fix). Without a keyset: (a) row order is undefined, so batches can
   overlap or skip within a single run on engines that don't guarantee stable
   offsets; (b) any concurrent insert shifts offsets and silently skips rows —
   reachable because the web job (`POST /api/v1/enrich-geo`) and a scan/import
   can write nodes while a long CLI `enrich-geo` is running. Fixed with
   keyset pagination on `Node.id`.

---

## 8. Scan credit budget — in-memory, per scanner instance

Implicit. `pages_fetched` counts Shodan search calls; once
`pages_fetched >= MAX_QUERY_CREDITS_PER_SCAN` (default 50, env-overridable),
`budget_exhausted` latches and all remaining query loops break
(`src/scanner.py:118-122, 175-186, 308-311`).

Invariants: `budget_exhausted` is one-way per run; `pages_fetched` only counts
successful `api.search()` calls (incremented after the call returns,
`src/scanner.py:189-195`).

No invalid states. Note the budget is per-process: the CLI and a concurrently
running web scan each keep their own count — by design, since the ceiling
guards a single run, not the account.

---

## 9. CachedNodeManager — `cache/nodes_cache.json`

Implicit TTL: per-IP entries are **fresh** for `CACHE_MAX_AGE_DAYS` (7) after
`timestamp`, else **stale** (`src/scanner.py:836-918`). Corrupt JSON loads as
empty (fail-open). No multi-process lock on the cache file: two concurrent
scanner processes can interleave `update_cache` writes and lose entries —
[CONFIRMED, low impact] CLI-only concern (the web path never uses the cache).

---

## 10. NostrScan — `nostr_scans` table

Explicit but degenerate. States in schema: `completed`, `failed`
(`src/db/models.py:239`). Only `create_scan(status="completed")` is ever called
(`src/db/repositories/nostr_repository.py:41-58`,
`src/db/cli.py:213-218`) — the `failed` state is **unreachable dead schema**
[CONFIRMED]. Not fixed: importing a malformed dump fails before the session
opens, so there is currently no failure point after scan creation; the state is
kept for future use.

---

## Issue index

| Issue | Title | Severity | Fix |
|-------|-------|----------|-----|
| 1 | ScanJob: stuck `pending`/`running` deadlock + unenforced transition table | High | `ScanJobRepository.get_active_job` reaps orphaned jobs to `failed` first (staleness cutoffs env-tunable via `SCAN_JOB_STALE_PENDING_MINUTES`/`SCAN_JOB_STALE_RUNNING_MINUTES`, defaults 30 min/12 h); `update_status` enforces the transition table and raises on terminal-state overwrite; `_run_job` contains failures of both the `running` mark and the terminal mark so a job always reaches a terminal state |
| 2 | NodeVulnerability: duplicate active links under concurrent relink | High | Partial unique index `uq_node_vuln_active` (`src/db/models.py`, additively created for existing DBs by `_migrate_schema`) plus conflict-tolerant `ON CONFLICT DO NOTHING` inserts in `sync_node_links`/`link_to_node` — the losing side of the race becomes a no-op |
| 3 | NVD refresh emits SQLite-only upsert SQL — breaks PostgreSQL | Medium | Dialect-agnostic `session.merge()` upsert in `NVDService._refresh` |
| 4 | Geo enrichment `OFFSET` cursor can skip/duplicate rows | Medium | Keyset pagination on `Node.id` in `enrich_nodes_geo` |

All fixes are guarded by `tests/test_state_machine_regressions.py`; the full suite
(836 tests) passes.
