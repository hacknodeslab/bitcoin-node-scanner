## Why

`scripts/import_json_to_db.py` is an untested ETL script that handles historical data ingestion and deduplication into the database — a critical data path with zero test coverage today. Adding a comprehensive test suite brings it up to ≥80% coverage and prevents regressions when the import logic or DB schema evolves.

## What Changes

- **New test file** `tests/test_import_json_to_db.py` covering `ProgressBar`, `JSONImporter`, and `main()` entry point.
- Tests use an in-memory SQLite database (via the existing `get_db_session` / `init_db` infrastructure) so they run without external dependencies.
- Coverage gate enforced at ≥80% for `scripts/import_json_to_db.py` via `pytest-cov`.

## Capabilities

### New Capabilities

- `import-json-to-db-tests`: Full pytest suite for the JSON→DB import script, covering happy paths, edge cases, error handling, and CLI argument parsing.

### Modified Capabilities

<!-- none -->

## Impact

- New file: `tests/test_import_json_to_db.py`
- No changes to production code.
- CI pipeline will run the new tests alongside existing ones; coverage report will include the script.
