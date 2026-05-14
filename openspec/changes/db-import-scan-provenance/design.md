## Context

`db-import` (`src/db/cli.py:cmd_import`) shells out to `scripts/import_json_to_db.py`. That script already imports `ScanRepository`, opens a session via `get_db_session()`, and tracks per-file stats (`imported`, `updated`, `skipped`, `errors`). It does not create a `Scan` row.

The dashboard's "last scan" reads the latest `scans` row: `StatsStrip.tsx` → `GET /api/v1/stats` → `stats.py` → `scan_repo.get_latest()` (`SELECT * FROM scans ORDER BY timestamp DESC LIMIT 1`). With no `scans` row from imports, the date is whatever the last real Shodan scan was (currently 24 March), regardless of how many nodes were imported since.

The `Scan` model (`src/db/models.py:116`) already has every field needed: `timestamp`, `queries_executed` (Text), `total_nodes`, `critical_nodes`, `high_risk_nodes`, `vulnerable_nodes`, `credits_used`, `duration_seconds`, `status`, `error_message`. No migration is required.

## Goals / Non-Goals

**Goals:**
- A successful import writes one `Scan` row so the dashboard date advances.
- Import scans are distinguishable from credit-consuming Shodan scans.
- The already-completed import is backfilled in local + production DBs.

**Non-Goals:**
- No new column on `scans` — the `json-import:` marker in `queries_executed` is sufficient.
- No change to `stats.py` or the frontend — they already read the latest scan correctly.
- Not linking imported nodes to the `Scan` via the `ScanNode` association — out of scope; the row is a provenance marker, not a full scan session. Can be a follow-up if node↔scan linkage is wanted.
- Not auditing/altering every `db-trends` aggregate — this change provides the marker; adjusting specific aggregates is verification work, not new behavior.

## Decisions

**1. Marker via `queries_executed` prefix `json-import:<filename>`, not a new boolean column.**
`queries_executed` is free-text (Text, JSON list of queries for real scans). A recognizable prefix makes import scans filterable with a `LIKE 'json-import:%'` predicate and needs no migration. Alternative considered: a `kind` / `is_import` column — cleaner typing but requires a migration and touching the model; rejected as overkill for a single boolean distinction the prefix already encodes.

**2. Create the row inside the existing import session, after the node loop succeeds.**
`import_file()` already holds a session and the final stats. Add the `Scan` insert at the end of the successful path, in the same transaction, so a failed import leaves no `completed` row. `total_nodes = imported + updated`; `credits_used = 0`; `status = 'completed'`; `timestamp = datetime.utcnow()`. Risk fields (`critical_nodes` etc.) can be populated if the loop already computes risk levels (it calls `_analyze_risk_level`), otherwise left at default 0.

**3. Backfill as a small standalone script / documented SQL, run once per DB.**
The prior import has no recoverable exact timestamp from a `scans` row, but `scripts/import_json_to_db.py` has `_extract_timestamp()` which parses the timestamp from the JSON filename (`nodes_20260513_213234.json` → that datetime). Use that as the backfill `timestamp`. Apply to local first, verify `GET /api/v1/stats`, then to production over SSH. Alternative: re-run the whole import — rejected, it would re-touch 7700 rows unnecessarily; a single INSERT is safer.

## Risks / Trade-offs

- **[`db-trends` / `HistoricalAnalyzer` silently count import scans as real scans]** → Verification task: grep consumers of the `scans` table and confirm they either tolerate `credits_used=0` rows or filter `json-import:%`. Adjust the ones that misreport.
- **[Free-text marker is weaker than a typed column]** → Accepted: the prefix is unambiguous and greppable; if import-provenance grows more structured later, a typed column can supersede it.
- **[Backfill timestamp is filename-derived, not the actual import wall-clock]** → Acceptable: the filename timestamp is when the scan data was produced, which is arguably the more meaningful "scan" date anyway.

## Migration Plan

No schema migration. Deploy order: (1) merge the code change so future imports self-record; (2) run the backfill on local, verify `/api/v1/stats`; (3) run the backfill on production over SSH against `/home/ubuntu/bitcoin-node-scanner/bitcoin_scanner.db` (back up the remote DB first, as with any prod DB write). Rollback: delete the import `Scan` row(s) — identifiable by the `json-import:` marker.

## Open Questions

- Should the import `Scan` row also populate `critical_nodes` / `vulnerable_nodes` counts, or leave them 0? Leaning toward populating them if the import loop already has the risk level per node, since it makes the dashboard's per-scan stats meaningful.
