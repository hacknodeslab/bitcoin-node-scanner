## Context

`scripts/import_json_to_db.py` is a standalone ETL utility that reads JSON files produced by the scanner and loads them into the SQLAlchemy-backed database. It has no tests today. The rest of the test suite already uses in-memory SQLite via `DATABASE_URL=sqlite:///:memory:` and the shared `init_db` / `get_db_session` helpers, so the same pattern applies here.

## Goals / Non-Goals

**Goals:**
- Write `tests/test_import_json_to_db.py` achieving ≥80% line coverage on `scripts/import_json_to_db.py`.
- Cover all major code paths: `ProgressBar`, `JSONImporter.import_file`, `JSONImporter._import_node`, `JSONImporter._analyze_risk_level`, `JSONImporter._is_vulnerable_version`, `JSONImporter._extract_timestamp`, `JSONImporter.import_directory`, and `main()`.
- Use `pytest`, `unittest.mock`, and in-memory SQLite — no external services required.

**Non-Goals:**
- Modifying production code.
- 100% branch coverage (some branches are defensive guards; 80% line coverage is the target).
- Integration tests against a real PostgreSQL instance for this script.

## Decisions

**In-memory SQLite for all DB tests**
Same approach used by `tests/test_db_integration.py`. Avoids filesystem side-effects and keeps tests fast. `DATABASE_URL=sqlite:///:memory:` is set via `monkeypatch.setenv`.

**Mock `get_db_session` for isolation of non-DB paths**
For tests that exercise error branches (e.g., JSON parse error, missing file, empty nodes), mocking the session avoids needing a real DB just to test early-exit logic.

**`tmp_path` fixture for file-based tests**
`import_file` and `import_directory` accept path strings; `pytest`'s `tmp_path` fixture provides a clean temp directory for writing fixture JSON files during tests.

**Test `main()` via `subprocess`-free approach**
Use `unittest.mock.patch` on `argparse.ArgumentParser.parse_args` (or `sys.argv`) combined with mocking `is_database_configured` and `init_db` to test the CLI entry point without actually initialising a DB each time.

## Risks / Trade-offs

- `sys.path.insert` at module top may conflict if `scripts/` is imported differently in CI → Mitigation: tests import via `importlib` with explicit path manipulation, matching how the script itself resolves imports.
- `ProgressBar.update` writes to stdout — tests that capture stdout must use `capsys` to avoid cluttering output → Mitigation: use `capsys` or redirect stdout to `StringIO`.

## Migration Plan

No migration needed — new test file only. Existing CI job `pytest tests/` picks it up automatically. Add `--cov=scripts` to coverage config if not already included.
