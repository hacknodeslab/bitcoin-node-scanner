## Why

`python -m src.db.cli db-import <file>` inserts and updates nodes but never writes a row to the `scans` table. The dashboard's "last scan" value is derived from the most recent `scans` row (`StatsStrip.tsx` → `GET /api/v1/stats` → `stats.py` → `scan_repo.get_latest()`), so after importing 7700+ fresh nodes the dashboard still shows a stale date (24 March). An import is a real data-provenance event and should be recorded as one.

## What Changes

- The JSON import flow (`db-import` → `scripts/import_json_to_db.py`) SHALL create a `Scan` row on successful completion, with: `status='completed'`, `queries_executed` set to a recognizable import marker (e.g. `json-import:<filename>`), `total_nodes` = number of nodes imported/updated, `credits_used=0`, `timestamp` = now.
- Import-provenance scans SHALL be distinguishable from real Shodan scans so historical analysis and `db-trends` are not polluted by zero-credit "scans". The marker is a recognizable `queries_executed` prefix (`json-import:`) — no schema change required.
- The dashboard's "last scan" continues to read the latest `scans` row; after this change a fresh import correctly advances that date.
- A one-off backfill SHALL insert the missing `Scan` row for the import already performed today, applied to both the local DB and the production DB.

## Capabilities

### New Capabilities
- `import-scan-provenance`: Recording JSON imports as `Scan` rows so the dashboard and history reflect import events, with a marker that keeps them distinguishable from credit-consuming Shodan scans.

### Modified Capabilities
<!-- No existing spec covers the db-import runtime behavior (only import-json-to-db-tests, a test capability). -->

## Impact

- **Code**: `scripts/import_json_to_db.py` (import flow — already imports `ScanRepository`), `src/db/repositories/scan_repository.py` (a create/record helper if not already present). No change to `src/db/models.py` (`Scan` model already has every needed field). `src/web/routers/stats.py` is unchanged — it already reads the latest scan.
- **Data**: one-off backfill row inserted into local + production `bitcoin_scanner.db`.
- **Consumers of scan history**: `db-trends` / `HistoricalAnalyzer` should treat `json-import:` scans as non-credit events; verify aggregates that assume `credits_used > 0` or count "scans" do not misreport.
- **No API or frontend changes.** Behavior change only.
