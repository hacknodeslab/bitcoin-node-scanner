## 1. Bounded pagination

- [x] 1.1 In `search_bitcoin_nodes()`, compute `max_pages = ceil(min(max_results, total) / 100)` and stop paginating once `page > max_pages`
- [x] 1.2 Break the pagination loop immediately when a fetched page returns an empty `matches` list
- [x] 1.3 Verify normal completion still paginates exactly `ceil(total / 100)` times for a query smaller than `max_results` — covered by test 5.1

## 2. Per-scan query-credit budget guard

- [x] 2.1 Add `MAX_QUERY_CREDITS_PER_SCAN` env var to `OptimizedConfig` (and base `Config` if used by the full scanner) with a conservative static default — added to base `Config` (default 50); `OptimizedConfig` inherits
- [x] 2.2 Add a run-level `pages_fetched` counter incremented on every `api.search()` call (page 1 included) — `self.pages_fetched` on `BitcoinNodeScanner`
- [x] 2.3 Before each `api.search()` call, abort remaining queries with a WARNING if `pages_fetched >= MAX_QUERY_CREDITS_PER_SCAN`, then fall through to persistence/reporting — guard in `search_bitcoin_nodes`; `budget_exhausted` flag checked by both query loops
- [x] 2.4 Log the active ceiling and its source (env vs default) at scan start — `_log_credit_ceiling()` called by `scan_all_queries` and `scan_optimized_queries`

## 3. Accurate credit reporting

- [x] 3.1 Set `credit_usage['query_credits_used']` from the `pages_fetched` total instead of `+= 1` per `smart_search()` call
- [x] 3.2 Confirm the end-of-run CREDIT USAGE SUMMARY reflects real page count — summary prints `credit_usage['query_credits_used']`, now sourced from `pages_fetched`

## 4. Documentation

- [x] 4.1 Add a note to `CLAUDE.md` that `python -m src.scanner` / `--quick` writes JSON/CSV only and requires a follow-up `db-import` — note added under "Run the scanner"; `db-import` also added to the Database CLI list
- [x] 4.2 Document the `MAX_QUERY_CREDITS_PER_SCAN` env var in `CLAUDE.md` alongside `MAX_RESULTS_NORMAL` / `MAX_RESULTS_CRITICAL` — all three documented in the Optional env vars line

## 5. Verification

- [x] 5.1 Add/extend a test that simulates Shodan `total` overestimating retrievable results and asserts the loop stops at `ceil(total/100)` pages — `test_pagination_caps_at_ceil_of_target` + `test_pagination_stops_on_empty_page`
- [x] 5.2 Add a test asserting the scan aborts when `pages_fetched` reaches the ceiling — `test_scan_aborts_when_credit_ceiling_reached`
- [x] 5.3 Run the full test suite (`python -m pytest tests/ -v`) and confirm green — change is clean: `538 passed / 8 failed`, the +3 new tests pass; the 8 failures are the same pre-existing order-dependent pollution documented in the db-import-scan-provenance change (verified unchanged)
