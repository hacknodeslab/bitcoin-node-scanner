## 1. Database

- [x] 1.1 Add `IpReputation` and `EnrichmentQuota` models and `ScanJob.job_type` (default `'scan'`) to `src/db/models.py`
- [x] 1.2 Write migration `migrations/versions/009_add_ip_reputation.py` (two tables + indexes, `scan_jobs.job_type` with server default; downgrade drops them)
- [x] 1.3 Add `src/db/repositories/reputation_repository.py`: `upsert(ip, result)`, `get_by_ip(ip)`, `ips_needing_enrichment(limit, stale_days)` with risk ordering and example exclusion; export it from `repositories/__init__.py`
- [x] 1.4 Extend `ScanJobRepository` so `create` takes a `job_type` and `get_active_job` filters by type
- [x] 1.5 Tests: migration up/down on SQLite, upsert-in-place, one row per IP shared by two ports, candidate ordering (CRITICAL → HIGH → MEDIUM → LOW → unrated), staleness cut-off, example IPs excluded

## 2. Enricher core

- [x] 2.1 Create `src/enrichers/__init__.py` with the `Enricher` protocol, the `SourceResult` type, and the registry
- [x] 2.2 Implement `src/enrichers/quota.py`: DB-backed daily counter per source (UTC day), `remaining()`, `consume()` in a transaction, min-interval throttle, `mark_exhausted()`
- [x] 2.3 Implement `src/enrichers/service.py`: select candidates, re-check `is_example_ip()`, run available enrichers, isolate failures, merge into `sources_json`, set `reputation_enriched_at` only when ≥1 source succeeded, return run stats
- [x] 2.4 Tests: unavailable enricher skipped with a single log line; one source fails while the other persists; all fail leaves `reputation_enriched_at` unchanged; quota mid-run cut (998 + 10 → 2 calls); quota survives a new session; next-UTC-day reset

## 3. Sources

- [x] 3.1 Implement `src/enrichers/abuseipdb.py` (v2 `check`, `Key` header, timeout, retry/backoff on 5xx and connection errors, project User-Agent, defensive parsing, 429 → stop + `mark_exhausted`, honor `X-RateLimit-Remaining`)
- [x] 3.2 Implement `src/enrichers/blocklists.py` (list registry with id/URL/parser/validator, 24h validated cache with atomic writes under `BLOCKLIST_CACHE_DIR`, stale cache used when refresh fails, `BLOCKLISTS` env override, IPv4/IPv6 bisect matching)
- [x] 3.3 Add `.blocklist_cache/` to `.gitignore`
- [x] 3.4 Tests with mocked HTTP (`tests/test_nvd_client.py` style): AbuseIPDB field mapping, no key → unavailable, 429 behaviour, retry on 503; blocklist parsing per format, CIDR hit/miss for v4 and v6, clean IP → `[]`, one list failing, stale-cache fallback

## 4. CLI backfill

- [x] 4.1 Add `db-enrich-ips` to `src/db/cli.py` with `--limit`, `--source`, `--dry-run`, reading `REPUTATION_STALE_DAYS` (default 7)
- [x] 4.2 Implement the offline `--dry-run` plan output (candidates per risk level, available sources, AbuseIPDB calls that fit today's quota, stop point) with no HTTP calls and no writes
- [x] 4.3 Tests: `--limit 1` picks the CRITICAL IP; `--source blocklists` makes no AbuseIPDB request; dry run makes no HTTP request and no DB/cache writes; no keys → exit 0 and `enricher unavailable: abuseipdb` logged; DB with example nodes → zero example rows touched

## 5. Web API

- [x] 5.1 Add `ReputationOut` and `NodeDetailOut.reputation` in `src/web/routers/nodes.py` (looked up by `node.ip`, with the `stale` flag computed, raw payloads not exposed)
- [x] 5.2 Add `job_type` to `ScanJobOut`; make `POST /api/v1/scans` single-flight per type
- [x] 5.3 Add `src/web/routers/enrichment.py` with `POST /api/v1/enrichment/run` (API key + CSRF, body validation: `limit` 1–1000 default 100, `source` must be registered, 202 / 409) and mount it in `src/web/main.py`
- [x] 5.4 Add an enrichment runner to `src/web/background.py` reusing the thread-pool and status helpers; the result summary carries IPs processed, per-source ok/error counts, and quota remaining
- [x] 5.5 Tests in `tests/test_web_api.py`: `reputation` null vs populated; list endpoint unchanged; enrichment endpoint 403 without CSRF, 409 when active, 422 for `limit=5000` and an unknown source; a running enrichment does not block a scan

## 6. Frontend

- [x] 6.1 Add `Reputation` type and `reputation` to the node detail type in `frontend/lib/api/types.ts`
- [x] 6.2 Add `ABUSE` (score-based colour) and `BLOCKLIST` kinds to `frontend/components/ui/Pill.tsx`
- [x] 6.3 Render the `REPUTATION` card in the `host` tab of `NodeDetailDrawer.tsx` below `host metadata`, hidden when `reputation` is null
- [x] 6.4 Tests in `NodeDetailDrawer.test.tsx`: alert/warn/ok score pills, blocklist pills, blocklist-only enrichment, stale hint, card absent when null
- [x] 6.5 Run the app locally and check the card in dark and light themes

## 7. Docs

- [x] 7.0 `git mv env.example .env.example` at the repo root: `docs/INSTALLATION.md:42,64`, `scripts/setup.sh:48` and `Makefile:47` already expect `.env.example`, so `setup.sh` currently fails; check no other reference to the undotted name remains
- [x] 7.1 Add `ABUSEIPDB_API_KEY`, `ABUSEIPDB_DAILY_QUOTA`, `ABUSEIPDB_MIN_INTERVAL`, `REPUTATION_STALE_DAYS`, `BLOCKLISTS`, `BLOCKLIST_CACHE_DIR` to the root `.env.example` and the `README.md` env section (README defers domain vars to per-domain docs, so they are named there and tabulated in `docs/bitcoin-scanner.md`)
- [x] 7.2 Document `db-enrich-ips` and the enrichment endpoint in `CLAUDE.md` and `docs/bitcoin-scanner.md`, including the list ids, URLs and terms of each blocklist
- [x] 7.3 Add an ethical-use note that AbuseIPDB lookups disclose node IPs to AbuseIPDB, while blocklists are matched locally
- [x] 7.4 Run `python -m pytest tests/ -v` offline and the frontend tests; compare any failures against the known pre-existing ones

## 8. Blocklist filters (added after review)

- [x] 8.1 `GET /api/v1/nodes`: `blocklisted=true` and `blocklist=<id>` (validated id, 422 unknown, 400 for `blocklisted=false`), applied to `X-Total-Count`
- [x] 8.2 Query-bar grammar keys `blocklisted` / `blocklist` (alert-coloured values) and `BLOCKLIST_IDS` in `frontend/lib/blocklists.ts`
- [x] 8.3 Palette commands `node: filter blocklisted (any list)` and `node: filter blocklist <id>` per list
- [x] 8.4 Tests: API filters (incl. two ports per IP, combination with `port`), grammar, palette commands
