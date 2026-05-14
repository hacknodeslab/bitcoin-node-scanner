# import-scan-provenance Specification

## Purpose

Records every `db-import` run as a `Scan` row so that imported nodes have the same provenance and history coverage as Shodan-scanned nodes, and the dashboard's last-scan date reflects imports. Import scans are tagged via a `queries_executed` marker so history consumers can distinguish them from real Shodan scans without a schema change.

## Requirements

### Requirement: Import records a Scan row

A successful `db-import` run SHALL create exactly one `Scan` row recording the import. The row MUST have `status='completed'`, `credits_used=0`, `timestamp` set to the time the import completed, `total_nodes` set to the count of nodes imported plus updated, and `queries_executed` set to a marker of the form `json-import:<filename>`.

#### Scenario: Successful import creates a Scan row

- **WHEN** `db-import <file>` completes without error
- **THEN** a new `scans` row exists with `status='completed'`, `credits_used=0`, `queries_executed` starting with `json-import:`, and `total_nodes` equal to imported + updated count

#### Scenario: Failed import does not create a completed Scan row

- **WHEN** an import aborts with an error before finishing
- **THEN** no `scans` row with `status='completed'` is created for that run

#### Scenario: Dashboard last-scan date reflects the import

- **WHEN** an import completes and the dashboard requests `GET /api/v1/stats`
- **THEN** `last_scan_at` equals the timestamp of the import's `Scan` row

### Requirement: Import scans are distinguishable from Shodan scans

An import-provenance `Scan` row SHALL be identifiable as such by its `queries_executed` marker (`json-import:` prefix) without requiring a schema change. Consumers of scan history that aggregate credit usage or count Shodan scans SHALL be able to exclude import scans by this marker.

#### Scenario: History consumer filters import scans

- **WHEN** scan history is aggregated for credit-usage or scan-frequency metrics
- **THEN** rows whose `queries_executed` begins with `json-import:` can be excluded so zero-credit imports do not distort the metrics

### Requirement: Backfill for prior import

A one-off backfill SHALL insert the missing `Scan` row for the import already performed (the ~7700-node import) into both the local and production databases, so the dashboard stops showing the stale date.

#### Scenario: Backfill corrects the stale dashboard date

- **WHEN** the backfill row is inserted into a database whose latest real scan predates the import
- **THEN** `GET /api/v1/stats` returns `last_scan_at` equal to the backfilled import timestamp
