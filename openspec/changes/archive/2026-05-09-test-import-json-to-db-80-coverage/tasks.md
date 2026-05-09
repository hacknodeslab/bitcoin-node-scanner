## 1. Setup & Fixtures

- [x] 1.1 Create `tests/test_import_json_to_db.py` with imports: `importlib`, `sys`, `json`, `pytest`, `unittest.mock`, `datetime`, `pathlib.Path`
- [x] 1.2 Add a `script` module-level fixture that imports `scripts/import_json_to_db.py` via `importlib` (adjusting `sys.path` as needed)
- [x] 1.3 Add a `db_session` fixture that sets `DATABASE_URL=sqlite:///:memory:`, calls `init_db()`, and yields a session via `get_db_session()`
- [x] 1.4 Add helper `make_node_dict(ip, port=8333, version="/Satoshi:30.0.0/", ...)` factory used across multiple tests

## 2. ProgressBar Tests

- [x] 2.1 Test `update()` with no arg increments `current` by 1
- [x] 2.2 Test `update(current=5)` sets `current` to 5
- [x] 2.3 Test `update()` with `total=0` does not raise `ZeroDivisionError`
- [x] 2.4 Test `finish()` prints a newline (use `capsys`)

## 3. JSONImporter — File Parsing Tests

- [x] 3.1 Test `import_file` with a list-format JSON (3 nodes): verify `imported == 3`, `errors == 0`
- [x] 3.2 Test `import_file` called twice: second call yields `updated == 3`, `imported == 0`
- [x] 3.3 Test `import_file` with `{"nodes": [...]}` dict envelope (2 nodes)
- [x] 3.4 Test `import_file` with single-node dict (has `"ip"` key)
- [x] 3.5 Test `import_file` with arbitrary-key dict envelope
- [x] 3.6 Test `import_file` with non-existent path returns all-zero stats
- [x] 3.7 Test `import_file` with invalid JSON returns `errors == 1`
- [x] 3.8 Test `import_file` with empty list `[]` returns all-zero stats

## 4. JSONImporter — Node Logic Tests

- [x] 4.1 Test `_import_node` skips dict missing `"ip"` key (returns `"skipped"`)
- [x] 4.2 Test `_import_node` with `port=8332` sets `has_exposed_rpc=True` and `risk_level="CRITICAL"`
- [x] 4.3 Test `_analyze_risk_level` returns `"CRITICAL"` for port 8332
- [x] 4.4 Test `_analyze_risk_level` returns `"MEDIUM"` for vulnerable version only
- [x] 4.5 Test `_analyze_risk_level` returns `"HIGH"` for vulnerable version + `.99.` dev flag
- [x] 4.6 Test `_analyze_risk_level` returns `"LOW"` for safe node

## 5. JSONImporter — Version Detection Tests

- [x] 5.1 Test `_is_vulnerable_version("/Satoshi:0.18.1/")` returns `True`
- [x] 5.2 Test `_is_vulnerable_version("/Satoshi:30.0.0/")` returns `False`
- [x] 5.3 Test `_is_vulnerable_version("garbage")` returns `False` without raising

## 6. JSONImporter — Timestamp Extraction Tests

- [x] 6.1 Test `_extract_timestamp("nodes_20240115_120000.json")` returns `datetime(2024, 1, 15, 12, 0, 0)`
- [x] 6.2 Test `_extract_timestamp("nodes_20240115.json")` returns date 2024-01-15
- [x] 6.3 Test `_extract_timestamp("nodes.json")` returns a datetime near `utcnow()` (within 5 seconds)

## 7. JSONImporter — Directory Import Tests

- [x] 7.1 Test `import_directory` with 2 JSON files (3 nodes each): `files_processed == 2`, `nodes_imported == 6`
- [x] 7.2 Test `import_directory` with non-existent path: `files_processed == 0`

## 8. main() CLI Tests

- [x] 8.1 Test `main()` with no argv raises `SystemExit(1)`
- [x] 8.2 Test `main()` when `is_database_configured()` returns `False` raises `SystemExit(1)`
- [x] 8.3 Test `main()` when `init_db()` returns `False` raises `SystemExit(1)`
- [x] 8.4 Test `main(["--all"])` calls `JSONImporter.import_directory("output/raw_data")`
- [x] 8.5 Test `main(["--dir", "/tmp/foo"])` calls `JSONImporter.import_directory("/tmp/foo")`
- [x] 8.6 Test `main(["/tmp/nodes.json"])` calls `JSONImporter.import_file("/tmp/nodes.json")`

## 9. Coverage Verification

- [x] 9.1 Run `pytest tests/test_import_json_to_db.py --cov=scripts --cov-report=term-missing` and confirm coverage ≥ 80%
- [x] 9.2 If below 80%, identify uncovered lines from the report and add targeted tests
