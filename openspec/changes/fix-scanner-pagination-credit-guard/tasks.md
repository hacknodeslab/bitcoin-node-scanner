## 1. Bounded pagination

- [ ] 1.1 In `search_bitcoin_nodes()`, compute `max_pages = ceil(min(max_results, total) / 100)` and stop paginating once `page > max_pages`
- [ ] 1.2 Break the pagination loop immediately when a fetched page returns an empty `matches` list
- [ ] 1.3 Verify normal completion still paginates exactly `ceil(total / 100)` times for a query smaller than `max_results`

## 2. Per-scan query-credit budget guard

- [ ] 2.1 Add `MAX_QUERY_CREDITS_PER_SCAN` env var to `OptimizedConfig` (and base `Config` if used by the full scanner) with a conservative static default
- [ ] 2.2 Add a run-level `pages_fetched` counter incremented on every `api.search()` call (page 1 included)
- [ ] 2.3 Before each `api.search()` call, abort remaining queries with a WARNING if `pages_fetched >= MAX_QUERY_CREDITS_PER_SCAN`, then fall through to persistence/reporting
- [ ] 2.4 Log the active ceiling and its source (env vs default) at scan start

## 3. Accurate credit reporting

- [ ] 3.1 Set `credit_usage['query_credits_used']` from the `pages_fetched` total instead of `+= 1` per `smart_search()` call
- [ ] 3.2 Confirm the end-of-run CREDIT USAGE SUMMARY reflects real page count

## 4. Documentation

- [ ] 4.1 Add a note to `CLAUDE.md` that `python -m src.scanner` / `--quick` writes JSON/CSV only and requires a follow-up `db-import`
- [ ] 4.2 Document the `MAX_QUERY_CREDITS_PER_SCAN` env var in `CLAUDE.md` alongside `MAX_RESULTS_NORMAL` / `MAX_RESULTS_CRITICAL`

## 5. Verification

- [ ] 5.1 Add/extend a test that simulates Shodan `total` overestimating retrievable results and asserts the loop stops at `ceil(total/100)` pages
- [ ] 5.2 Add a test asserting the scan aborts when `pages_fetched` reaches the ceiling
- [ ] 5.3 Run the full test suite (`python -m pytest tests/ -v`) and confirm green
