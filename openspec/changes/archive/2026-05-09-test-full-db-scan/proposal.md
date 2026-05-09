## Why

`scripts/full_db_scan.py` is an untested production script that drives full-catalog Bitcoin node scans via Shodan `search_cursor`-style pagination and bulk-upserts into the database. It touches credits, pagination, rate-limit retries, batching, scan lifecycle, and DB persistence — a high-risk data path with zero automated coverage today. Adding a test suite catches regressions when Shodan/DB behavior evolves and makes the script safe to refactor.

## What Changes

- **New test file** `tests/test_full_db_scan.py` covering the helper functions (`extract_version`, `map_match`, `bulk_save`) and the `main()` CLI entry point.
- Tests mock the `shodan.Shodan` client (no network) and use the shared in-memory SQLite fixture from `tests/conftest.py` so they run offline and in isolation.
- Cover happy path, `--dry-run`, `--limit`, rate-limit retry, "no more pages" termination, empty-matches break, missing `DATABASE_URL`, and the scan-record lifecycle (create running → complete).
- Target ≥80% line coverage for `scripts/full_db_scan.py` via `pytest-cov`.

## Capabilities

### New Capabilities

- `full-db-scan-tests`: Full pytest suite for the Shodan-driven full DB scan script, covering helper functions, CLI argument handling, pagination/retry behavior, and scan lifecycle persistence.

### Modified Capabilities

<!-- none -->

## Impact

- New file: `tests/test_full_db_scan.py`.
- No changes to production code in `scripts/full_db_scan.py` or `src/`.
- CI runs the new tests alongside existing ones; the coverage report will include the script.
- Test runtime impact is negligible (all I/O and sleeps are mocked).
