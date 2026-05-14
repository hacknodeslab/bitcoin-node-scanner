## Why

A single scan of the query `port:8332` (Shodan reported `total=649`, ~7 pages expected) ran for 1.5 hours and silently consumed all 89 remaining monthly Shodan query credits, leaving zero budget for the rest of the scan. The pagination loop in `search_bitcoin_nodes()` has no upper bound on page count and no credit budget ceiling, so a single query can exhaust the entire monthly allowance — directly defeating the credit-efficiency goal that `OptimizedBitcoinScanner` exists to serve.

## What Changes

- Bound the pagination loop in `search_bitcoin_nodes()`:
  - Stop when a page returns zero matches (Shodan's `total` is an estimate and can exceed actually-retrievable results).
  - Cap the page count at `ceil(total / 100)` so the loop can never request more pages than results exist.
- Add a per-scan **query-credit budget guard**: before each `api.search()` call, check remaining credits against a configurable ceiling and abort the scan cleanly (with a warning) rather than draining the monthly limit.
- Fix credit accounting: the internal `query_credits_used` counter increments once per query (reported a meaningless `2` for a scan that actually burned 89 credits). Track and report the real number of pages fetched / credits consumed.
- Document (or optionally wire) DB persistence: `python -m src.scanner --quick` writes only JSON/CSV and does **not** persist to the database — users must run `db-import` manually. At minimum this gets documented; optionally an opt-in flag persists directly.

## Capabilities

### New Capabilities
- `scanner-credit-safety`: Bounded pagination and query-credit budget enforcement for the Shodan scanner — guarantees a scan cannot exceed a configured credit ceiling and cannot loop past the available result set.

### Modified Capabilities
<!-- No existing spec covers scanner pagination/credit behavior. -->

## Impact

- **Code**: `src/scanner.py` — `search_bitcoin_nodes()`, `smart_search()`, the optimized scan loop, and credit-usage reporting in the scan summary.
- **Config**: new optional env var for the per-scan credit ceiling (e.g. `MAX_QUERY_CREDITS_PER_SCAN`); builds on the already-externalized `MAX_RESULTS_NORMAL` / `MAX_RESULTS_CRITICAL`.
- **Docs**: `CLAUDE.md` — note that `--quick` does not persist to the DB and requires a follow-up `db-import`.
- **No DB schema or API changes.** Behavior change only: scans now abort early instead of exhausting credits.
