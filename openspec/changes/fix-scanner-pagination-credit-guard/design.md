## Context

`BitcoinNodeScanner.search_bitcoin_nodes()` in `src/scanner.py` paginates Shodan search results with:

```python
total = search_results['total']
while collected < min(max_results, total):
    if page > 1:
        search_results = self.api.search(query, page=page)
    for result in search_results['matches']:
        ...
        collected += 1
    page += 1
    time.sleep(1)
```

Each `api.search()` call costs one Shodan query credit. Shodan's `total` is an **estimate** and can exceed the number of results actually retrievable. When pages start returning fewer (or zero) matches, `collected` plateaus below `min(max_results, total)`, so the `while` condition stays true and the loop keeps requesting pages — burning one credit per call — until credits run out or the API raises an "upgrade your API plan" error.

Observed in production: query `port:8332` (`total=649`) ran 1.5 hours and drained all 89 remaining monthly credits. The internal `query_credits_used` counter is incremented once per `smart_search()` call, so it reported `2` for a run that actually consumed ~89 credits — the operator had no signal anything was wrong.

`MAX_RESULTS_NORMAL` / `MAX_RESULTS_CRITICAL` are already env-overridable (recent change). There is no per-scan credit ceiling.

## Goals / Non-Goals

**Goals:**
- A single scan run can never exceed a configurable query-credit ceiling.
- The pagination loop always terminates within `ceil(total / 100)` page requests, and stops early on an empty page.
- The end-of-run summary reports the real credit consumption.
- `--quick`'s lack of DB persistence is documented.

**Non-Goals:**
- Auto-wiring `--quick` to persist directly to the DB (left as an optional follow-up; `db-import` remains the supported path).
- Changing the caching layer (`CachedNodeManager`) or the optimized query set.
- Retroactively refunding or recovering the credits already spent.

## Decisions

**1. Loop bound: track `pages_fetched` and cap at `ceil(total / 100)`; break on empty page.**
Replace the sole `while collected < min(max_results, total)` condition with an explicit page cap plus an empty-page break. `max_pages = ceil(min(max_results, total) / 100)`. Break immediately if `search_results['matches']` is empty. Rationale: the page count is the thing that costs credits, so bounding pages — not `collected` — is what actually caps spend. Alternative considered: trusting `collected` to catch up to `total`; rejected because Shodan's `total` overestimate is exactly the failure mode.

**2. Credit guard: a per-run counter checked before each `api.search()` call against `MAX_QUERY_CREDITS_PER_SCAN`.**
Increment a run-level `pages_fetched` counter on every `api.search()` call (page 1 included). Before each call, if `pages_fetched >= ceiling`, abort the remaining queries with a WARNING and fall through to persistence/reporting. Default ceiling when the env var is unset: a conservative value (e.g. 50) — generous enough for a normal optimized scan, small enough to never drain a fresh 100-credit month in one run. Alternative considered: calling `api.info()` before each search to read live remaining credits; rejected — `api.info()` itself adds latency and the run-local counter is sufficient and deterministic.

**3. Credit accounting: report `pages_fetched` as credits used.**
The existing `credit_usage['query_credits_used']` becomes the `pages_fetched` total instead of a `+= 1` per `smart_search()`. This is an approximation (Shodan's exact billing has edge cases) but is accurate to within rounding and is vastly better than the current meaningless count.

**4. Documentation-only fix for DB persistence.**
Add a note to `CLAUDE.md` under the scanner commands that `--quick` / plain scans write JSON/CSV only and require a follow-up `db-import`. Keeps scope tight; wiring direct persistence is a separate change if wanted.

## Risks / Trade-offs

- **[Default ceiling too low surprises users mid-scan]** → Log the ceiling and its source (env vs default) at scan start so the abort is never a surprise; document the env var in `CLAUDE.md`.
- **[`pages_fetched` is an approximation of real billing]** → Acceptable: it is an upper-bound-ish estimate and the guard errs on the side of stopping early. Exact reconciliation can still be done via `--check-credits`.
- **[Empty-page break could stop a valid scan early if Shodan transiently returns an empty page]** → Low risk; Shodan pagination does not interleave empty pages within a valid result set. If it proves flaky, a single retry on empty page can be added later.

## Migration Plan

Pure behavior change in `src/scanner.py` plus a `CLAUDE.md` note. No DB, schema, or API changes; no migration step. Rollback is reverting the commit. The already-applied (uncommitted) `MAX_RESULTS_*` env-var change should be folded into this change's commit.

## Open Questions

- What default value for `MAX_QUERY_CREDITS_PER_SCAN` — 50, or derived from live remaining credits at scan start? Leaning toward a static conservative default for determinism.
