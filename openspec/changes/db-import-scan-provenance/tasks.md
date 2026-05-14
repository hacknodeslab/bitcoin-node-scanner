## 1. Record a Scan row on import

- [x] 1.1 In `scripts/import_json_to_db.py` `import_file()`, after the node loop succeeds and within the same session, create a `Scan` row: `status='completed'`, `credits_used=0`, `timestamp=datetime.utcnow()`, `total_nodes=imported+updated`, `queries_executed=f"json-import:{os.path.basename(file_path)}"`
- [x] 1.2 Populate `critical_nodes` / `high_risk_nodes` / `vulnerable_nodes` from the per-node risk levels the loop already computes (or leave at default 0 if not readily available)
- [x] 1.3 Ensure the `Scan` row is committed in the same transaction as the nodes, so a failed import leaves no `completed` row
- [x] 1.4 Add/confirm a `ScanRepository` helper for creating a completed scan record if one does not already exist

## 2. Keep import scans distinguishable

- [x] 2.1 Grep consumers of the `scans` table (`HistoricalAnalyzer`, `db-trends` in `src/db/cli.py`, `scan_repository.py`) and confirm whether they need to exclude `queries_executed LIKE 'json-import:%'`
- [x] 2.2 Adjust any aggregate that would misreport zero-credit import scans as Shodan scans — **no-op**: `db-stats`/`db-trends` aggregate the `Node` table (grouped by `last_seen`), not `scans`; `get_latest()` intentionally wants imports; `db-export` is a raw dump; `ScanRepository.get_statistics()` has no caller. No aggregate misreports; the `json-import:` marker stays available for future filtering.

## 3. Backfill the prior import

- [x] 3.1 Write a one-off backfill (small script or documented SQL) that inserts the missing `Scan` row for the ~7700-node import, using the filename-derived timestamp (`_extract_timestamp` logic, e.g. `nodes_20260513_213234.json`)
- [x] 3.2 Run the backfill on the local DB; verify `GET /api/v1/stats` returns the new `last_scan_at` — inserted Scan id=9 (2026-05-13 21:32:34, 7713 nodes, 640 critical); `get_latest()` confirmed to return it
- [x] 3.3 Back up the production DB, run the backfill on production over SSH (`/home/ubuntu/bitcoin-node-scanner/bitcoin_scanner.db`), verify via the prod stats endpoint — prod DB backed up; idempotent `INSERT` applied; `scans` id=9 confirmed as the latest row by timestamp. HTTP `/api/v1/stats` is API-key protected so verified at the DB level (`get_latest()` orders by `timestamp DESC`).

## 4. Verification

- [x] 4.1 Add a test asserting `db-import` of a fixture JSON creates a `Scan` row with `status='completed'`, `credits_used=0`, and a `json-import:` marker — `TestImportRecordsScan::test_successful_import_creates_completed_scan_row`
- [x] 4.2 Add a test asserting a failed import does not leave a `completed` `Scan` row — `TestImportRecordsScan::test_failed_import_leaves_no_completed_scan_row`
- [x] 4.3 Run the full test suite (`python -m pytest tests/ -v`) and confirm green — change is clean: baseline `533 passed / 8 failed` → with change `535 passed / 8 failed` (+2 new tests pass, nothing broken). The 8 failures (`test_parse_node_data_missing_fields`, `TestStatsEndpoint`, `TestScansEndpoint`) are **pre-existing order-dependent test pollution** confirmed via `git stash` — out of scope for this change.
