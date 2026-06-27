## 1. Backend — nostr recon module

- [x] 1.1 Create `src/nostr/__init__.py` and `src/nostr/cdn_ranges.py` porting the CDN-range fetch/cache from `check_cf.py` (Cloudflare v4/v6, CloudFront from AWS ip-ranges, Fastly), with the 7-day `.cdn_cache/` TTL and the hardcoded Cloudflare fallback on fetch failure
- [x] 1.2 Create `src/nostr/classifier.py` with `normalize(line)`, parallel `resolve(host)`, and `classify(host)` returning `{host, verdict, ips, providers, error}` (verdicts: provider name / `+`-joined combo / `direct` / `dns_error` / `skipped` for `.onion`/`.i2p`)
- [x] 1.3 Create `src/nostr/scanner.py` as `python -m src.nostr.scanner <relays.txt>` that classifies hosts via `ThreadPoolExecutor`, computes `{counts, total, resolved, behind_any_cdn}`, and writes a JSON dump to `output/`
- [x] 1.4 Add `src/nostr/extract_relays.py` helper (port from PoC) to derive a host list from a nostr.watch xlsx export
- [x] 1.5 Add unit tests: normalization (URL forms, comments, dedup), verdict assignment against fixture CIDR ranges, `skipped`/`dns_error` paths, and aggregate-count consistency (`resolved`, `behind_any_cdn`)

## 2. Database — dedicated Nostr tables

- [x] 2.1 Add `NostrRelay` model to `src/db/models.py` (host unique, verdict, providers JSON, ips JSON, first_seen, last_seen; indexes on `host`, `verdict`, `last_seen`)
- [x] 2.2 Add `NostrScan` model (source list ref, total, resolved, behind_any_cdn, started_at, status)
- [x] 2.3 Create `src/db/repositories/nostr_repository.py` with: upsert-relay-by-host, create-scan, latest-scan lookup, paginated relay query (filter by verdict/provider/behind_cdn), and a `GROUP BY` stats aggregate for the latest scan
- [x] 2.4 Add `db-import-nostr <dump.json>` to `src/db/cli.py`: create a `NostrScan` and upsert one `NostrRelay` per result (update on existing host, bump `last_seen`)
- [x] 2.5 Add tests: import a dump creates a scan + relays; re-import updates (no duplicate); repository filters and stats aggregate return correct values

## 3. Web API — /api/v1/nostr/*

- [x] 3.1 Add Pydantic response models for relay items and stats in the nostr router/schemas
- [x] 3.2 Create `src/web/routers/nostr.py` with `GET /api/v1/nostr/relays` (paginated; `verdict`/`provider`/`behind_cdn` filters) and `GET /api/v1/nostr/stats` (per-verdict counts, total, resolved, behind_any_cdn, behind-CDN %), reusing the existing API-key/CSRF auth
- [x] 3.3 Mount the router in `src/web/main.py`
- [x] 3.4 Add API tests: paginated list, provider filter, `behind_cdn=true` exclusion, 401 without key, stats shape, and zeroed stats when no scan exists

## 4. Frontend — API client + types

- [x] 4.1 Add Nostr relay + stats types to `frontend/lib/api/types.ts`
- [x] 4.2 Add `getNostrRelays(params)` and `getNostrStats()` to `frontend/lib/api/endpoints.ts`
- [x] 4.3 Run `pnpm typecheck` in `frontend/`

## 5. Frontend — Nostr panel page

- [x] 5.1 Create `frontend/app/nostr/page.tsx` with summary cards (% behind CDN, per-provider breakdown, total/resolved) using DESIGN.md tokens and dark/light theme
- [x] 5.2 Render a sortable, paginated relay table (host, verdict as `Pill`, providers, IPs) reusing the `NodeTable` table/pagination patterns; add a CDN-verdict variant to `Pill`
- [x] 5.3 Add verdict/provider and "behind CDN" filters wired to the relay endpoint
- [x] 5.4 Add an empty state for when no scan has been imported
- [x] 5.5 Add `nostr` to `NAV_LINKS` in `frontend/components/explorer/TopNav.tsx` and extend the `current` union type to include `"nostr"`

## 6. Verification & docs

- [x] 6.1 Add a frontend test for the panel (renders summary + rows, filters by provider, paginates) with mocked API
- [x] 6.2 Run `python -m pytest tests/ -v` and `pnpm typecheck && pnpm test` in `frontend/`; confirm no new failures
- [x] 6.3 Manually verify end-to-end: run `src.nostr.scanner` on a sample list → `db-import-nostr` → panel shows stats, filters, and pagination
- [x] 6.4 Update `CLAUDE.md` with the Nostr scan flow and the `db-import-nostr` command
