## 1. Scaffolding

- [x] 1.1 Create `tests/test_full_db_scan.py` with a module docstring referencing this change
- [x] 1.2 Add `sys.path` bootstrap (repo root) matching the approach used by `tests/test_import_json_to_db.py`
- [x] 1.3 Import `scripts.full_db_scan as full_db_scan` and the shared `db_engine` / `db_session` fixtures from `tests/conftest.py`
- [x] 1.4 Add a module-level `autouse` fixture that patches `scripts.full_db_scan.time.sleep` to a no-op for every test

## 2. Helper function tests (`extract_version`, `map_match`)

- [x] 2.1 Test `extract_version` with a Satoshi-containing banner → returns `"Satoshi:X.Y.Z"`
- [x] 2.2 Test `extract_version` when only `match["version"]` is set → falls back to it
- [x] 2.3 Test `extract_version` with malformed Satoshi banner (no trailing `/`) → falls back safely
- [x] 2.4 Test `extract_version` with empty match → returns `None`
- [x] 2.5 Test `map_match` with a full Shodan-shape dict and a stub scanner; assert every field (ip, port, country_code, city, latitude, asn, banner length ≤ 500, version)
- [x] 2.6 Test `map_match` with `port=8332` → `has_exposed_rpc is True`
- [x] 2.7 Test `map_match` with a version containing `.99.` → `is_dev_version is True`
- [x] 2.8 Test `map_match` with no `port` key → defaults to 8333 and `has_exposed_rpc is False`
- [x] 2.9 Test `map_match` delegation — stub scanner returns sentinel risk/vulnerable values and the returned dict mirrors them

## 3. `bulk_save` tests (real in-memory SQLite)

- [x] 3.1 Fixture that calls `init_db()` bound to the in-memory engine and creates a `Scan` row, yielding `scan_id`
- [x] 3.2 Patch `scripts.full_db_scan.get_db_session` to yield a session backed by the in-memory engine
- [x] 3.3 Test a batch of 3 mapped nodes → all 3 are present in `Node` and associated with the `Scan`
- [x] 3.4 Test empty batch → no rows written, no exception
- [x] 3.5 Test non-existent `scan_id` → nodes still upserted, no exception, no scan association

## 4. `main()` CLI argument tests

- [x] 4.1 Test missing `DATABASE_URL` (patch `is_database_configured` to return `False`) → `SystemExit`, nothing written, no Shodan call
- [x] 4.2 Test `--dry-run` → credit summary printed, no `Scan` row created, no `bulk_save` call
- [x] 4.3 Test `--limit 50` with 10,000 reported results and 1,000 credits → target is 50, fake client's `search` called ≤ 1 time (1 page of 100 is enough to cap at 50)
- [x] 4.4 Test target clamped by credits — credits=1 (→ max 100 nodes) with 10,000 reported → target is 100

## 5. `main()` pagination loop tests

- [x] 5.1 Build a fake Shodan client helper that returns paginated `matches` lists keyed by `page` number
- [x] 5.2 Happy path: 3 pages × 100 matches → 300 nodes saved, scan completed with `total_nodes=300`
- [x] 5.3 Rate-limit retry: page 2 raises `APIError("Rate limit reached")` on first call, succeeds on second → total nodes includes page 2, `time.sleep` called with `RETRY_WAIT`
- [x] 5.4 Pagination end via `APIError("No information available for that page")` → loop exits cleanly, scan completed
- [x] 5.5 Empty matches list on a page → loop exits, scan completed with nodes saved so far
- [x] 5.6 Unknown `APIError` (e.g. `"Server error"`) raised mid-loop → caught by outer handler, scan still finalized in `finally`

## 6. Scan lifecycle assertions

- [x] 6.1 After a successful `main()` run, inspect the in-memory DB and assert the `Scan` row has `status="completed"`, `total_nodes == saved`, `duration_seconds >= 0`
- [x] 6.2 Assert `queries_executed == ["product:Satoshi"]` on the created scan

## 7. Coverage & CI

- [x] 7.1 Run `python -m pytest tests/test_full_db_scan.py -v` locally — all tests pass (23/23 pass)
- [x] 7.2 Run `python -m pytest tests/test_full_db_scan.py --cov=full_db_scan --cov-report=term-missing` — reports **95%** line coverage (used the registered module name `full_db_scan` since `scripts/` has no `__init__.py`; see design.md)
- [x] 7.3 Run the full suite `python -m pytest tests/ -v` — no new test regressed; 7 pre-existing failures in `test_scanner.py` / `test_web_api.py` are unrelated to this change (reproduce identically when excluding the new file)
- [x] 7.4 Coverage is 95% (≥ 80%); the 6 uncovered lines are unreachable: the defensive `except Exception: pass` in `extract_version` (38-39), the `session is None` guard in `bulk_save` (71), the documented duplicate `except shodan.APIError` block (183-184), and the `if __name__ == "__main__"` entry (202) — all called out in design.md Risks

## 8. Wrap-up

- [ ] 8.1 Add a one-paragraph note to the PR description flagging the duplicate `except shodan.APIError` block (lines 183-184) and the hardcoded Shodan API key fallback as follow-up concerns _(deferred to when the PR is opened)_
- [x] 8.2 Run `openspec validate test-full-db-scan --strict` and fix any issues — passes: "Change 'test-full-db-scan' is valid"
