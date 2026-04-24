## Context

`scripts/full_db_scan.py` is a ~200-line command-line script that drives a full Shodan catalog scan of Bitcoin nodes into the project database. It:

1. Loads a Shodan API client and queries `product:Satoshi`.
2. Computes a fetch target from `credits * 100`, clamped by `--limit`.
3. Creates a `Scan` row (`status="running"`) and then iterates pages of `api.search`, mapping each match and bulk-upserting batches via `NodeRepository.bulk_upsert`.
4. Catches Shodan rate-limit errors to retry, and "no-more-pages"/"page" errors to terminate cleanly.
5. Finalizes the `Scan` row in a `finally` block (completes with total nodes and duration).

Today the script has **zero tests**. The existing test suite (`tests/`) uses an in-memory SQLite fixture from `tests/conftest.py` (`db_engine`, `db_session`), mocks Shodan via `unittest.mock`, and a closely analogous script (`scripts/import_json_to_db.py`) already has a companion test (`tests/test_import_json_to_db.py`) we can use as a pattern.

The script imports `shodan` at module level, constructs `shodan.Shodan(API_KEY)` inside `main()`, calls `init_db()` / `get_db_session()` from `src.db.connection`, and uses `NodeRepository` / `ScanRepository`. This is the surface we need to mock.

## Goals / Non-Goals

**Goals:**

- Add `tests/test_full_db_scan.py` covering the pure helpers (`extract_version`, `map_match`, `bulk_save`) and the `main()` entry point.
- Exercise the critical control-flow branches: `--dry-run`, `--limit`, missing `DATABASE_URL`, rate-limit retry, "no more pages" exit, empty-matches exit, unknown `APIError` fallthrough, and the `finally`-block scan completion.
- Run fully offline — no real Shodan calls, no real sleeps, no real file I/O beyond the in-memory SQLite DB.
- Achieve ≥ 80% line coverage for `scripts/full_db_scan.py`.

**Non-Goals:**

- Refactoring the script to be more testable (e.g., injecting the Shodan client). If seams are needed, we use `monkeypatch` / `unittest.mock.patch`, not production-code changes. One exception: if duplicate `except shodan.APIError` blocks or similarly dead code materially blocks reaching 80%, note it in Open Questions — do not silently rewrite logic.
- End-to-end validation against the real Shodan API.
- Adding new CLI flags or changing script behavior.
- Testing `src/scanner.BitcoinNodeScanner` internals — those are already covered by `tests/test_scanner.py`.

## Decisions

### 1. Use `unittest.mock.patch` at the `scripts.full_db_scan` module namespace

Patch `scripts.full_db_scan.shodan.Shodan`, `scripts.full_db_scan.time.sleep`, `scripts.full_db_scan.is_database_configured`, `scripts.full_db_scan.init_db`, `scripts.full_db_scan.get_db_session`, and `scripts.full_db_scan.BitcoinNodeScanner` where appropriate.

**Why here, not at the source module:** the script does `from src.db.connection import ...` and `from src.scanner import BitcoinNodeScanner`, so those names are bound into `scripts.full_db_scan`'s namespace. Patching the import site is the canonical pattern and keeps the rest of the test suite unaffected.

**Alternative considered:** monkeypatching `src.db.connection.get_db_session` directly. Rejected — it leaks into other tests that share the same fixture.

### 2. Reuse the in-memory SQLite fixture for `bulk_save` tests

`bulk_save` uses `get_db_session()` internally. For those targeted unit tests we patch `scripts.full_db_scan.get_db_session` to yield a session bound to the `db_engine` fixture (in-memory SQLite). This exercises the real repository logic without a real file.

**Why:** higher fidelity than mocking the repositories, and consistent with the existing `test_import_json_to_db.py` approach. Alternative (mocking `NodeRepository` / `ScanRepository`) would leave the actual DB code path unverified.

### 3. Mock Shodan `api.search` / `api.info` via a fake client object

Build a `MagicMock` whose `.info()` returns `{"query_credits": N}` and whose `.search()` returns either a fixed dict or a side-effect callable that yields different pages / raises `shodan.APIError` for specific pages.

**Why:** `search_cursor` is not used by the script — only `search(..., page=..., limit=...)` — so a stateful `search` side-effect covering pages 1..N plus a terminating condition is enough.

### 4. Patch `time.sleep` to zero

Every test that traverses the pagination loop patches `scripts.full_db_scan.time.sleep` so the `PAGE_DELAY` (2s) and `RETRY_WAIT` (30s) don't slow the suite. We also assert `time.sleep` was called with `RETRY_WAIT` when exercising the rate-limit branch, to confirm the retry path executed.

### 5. Test `main()` via `argparse` argv injection

Use `monkeypatch.setattr(sys, "argv", ["full_db_scan.py", "--limit", "50"])` inside each `main()` test. For the missing-DB-URL case, assert `SystemExit` via `pytest.raises(SystemExit)`.

### 6. Coverage measurement

Invoke pytest with `--cov=scripts.full_db_scan --cov-report=term-missing`. Because `scripts/` has no `__init__.py` today, the test file will add the repo root to `sys.path` (mirroring what the script does) so coverage can import it as `scripts.full_db_scan`. If coverage accounting fails without a package, fall back to `--cov=scripts/full_db_scan.py`.

## Risks / Trade-offs

- **Duplicate `except shodan.APIError` block (lines 183-184)**: the second `except` is unreachable (the first catches it). Tests cannot cover it. → Accept the dead line; 80% threshold is still reachable. Surface this in Open Questions as a follow-up cleanup rather than fixing it in this change (which is test-only).
- **Hardcoded fallback API key in `API_KEY = os.getenv("SHODAN_API_KEY", "9Tk6l4k6...")`**: constants are module-level and evaluated at import. → Tests never exercise the real network, so the literal never matters, but the secret-looking string should be flagged to the user as a separate concern (not part of this change).
- **Module-level side effect risk**: `API_KEY` and `QUERY` are module globals read inside `main()`. Tests that need to override them use `monkeypatch.setattr(full_db_scan, "QUERY", "...")` rather than re-importing.
- **Pagination-loop complexity**: the retry/terminate branches are the most fragile test area. → Use explicit page-numbered side-effect functions (not `side_effect=[...]` lists) so each test clearly documents which page raises which error.

## Migration Plan

Not applicable — this change only adds a new test file. No production code moves. Rollback = delete `tests/test_full_db_scan.py`.

## Open Questions

- Should the duplicate `except shodan.APIError` block (lines 183-184) be removed in a follow-up? Flag it in the PR description; do not touch production code in this change.
- Should we add `scripts/__init__.py` to make `scripts` a proper package for coverage? Probably yes, but keep it out of this PR unless required for the coverage gate to report correctly.
