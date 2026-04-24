## ADDED Requirements

### Requirement: Version extraction from Shodan match data

The test suite SHALL verify that `extract_version` returns the correct Bitcoin version string across all supported input shapes of a Shodan match.

#### Scenario: Banner contains a Satoshi token

- **WHEN** the match `data` field contains `"/Satoshi:25.0.0/"`
- **THEN** `extract_version` returns `"Satoshi:25.0.0"`

#### Scenario: Banner is missing Satoshi token but match has a version field

- **WHEN** the match `data` field lacks `/Satoshi:` but `match["version"]` is set to `"24.1"`
- **THEN** `extract_version` returns `"24.1"`

#### Scenario: Banner is malformed around the Satoshi token

- **WHEN** the match `data` contains `"/Satoshi:"` but no trailing `/` delimiter
- **THEN** `extract_version` falls back to `match["version"]` (or `None` when absent) without raising

#### Scenario: Neither banner nor version field present

- **WHEN** the match has no `data` and no `version` field
- **THEN** `extract_version` returns `None`

### Requirement: Shodan match → DB node dict mapping

The test suite SHALL verify that `map_match` produces a node dictionary whose fields align with the database schema and the risk/vulnerability analysis produced by `BitcoinNodeScanner`.

#### Scenario: Full match with location and ASN

- **WHEN** a match with `ip_str`, `port`, `location`, `asn`, `org`, and a Satoshi banner is mapped
- **THEN** the returned dict contains matching `ip`, `port`, `country_code`, `country_name`, `city`, `latitude`, `longitude`, `asn`, `asn_name`, `version`, and a `banner` truncated to 500 chars

#### Scenario: Port 8332 is flagged as exposed RPC

- **WHEN** the match `port` is `8332`
- **THEN** `has_exposed_rpc` is `True` in the mapped dict

#### Scenario: Dev version banner

- **WHEN** the version string contains `".99."` (e.g. `"Satoshi:24.99.0"`)
- **THEN** `is_dev_version` is `True`

#### Scenario: Missing port defaults to 8333

- **WHEN** the match has no `port` key
- **THEN** `port` defaults to `8333` and `has_exposed_rpc` is `False`

#### Scenario: Risk and vulnerability are delegated to the scanner

- **WHEN** `map_match` is called with a stub scanner whose `analyze_risk_level` and `is_vulnerable_version` return sentinel values
- **THEN** the mapped dict's `risk_level` and `is_vulnerable` equal those sentinel values, confirming delegation

### Requirement: Bulk save associates nodes with the current scan

The test suite SHALL verify that `bulk_save` upserts the supplied nodes and links them to the scan record supplied by `scan_id`.

#### Scenario: Batch of nodes is persisted and linked to scan

- **WHEN** `bulk_save` is called with a list of mapped nodes and an existing `scan_id`
- **THEN** the nodes are present in the database and associated with that scan

#### Scenario: Empty batch is a no-op

- **WHEN** `bulk_save` is called with an empty list
- **THEN** no nodes are written and no exception is raised

#### Scenario: Missing scan_id does not crash

- **WHEN** `bulk_save` is called with a `scan_id` that does not exist in the DB
- **THEN** nodes are still upserted and the call returns without raising

### Requirement: CLI entry point respects arguments and environment

The test suite SHALL verify that `main()` honors `--dry-run`, `--limit`, and the `DATABASE_URL` requirement.

#### Scenario: Missing DATABASE_URL exits with error

- **WHEN** `is_database_configured()` returns `False`
- **THEN** `main()` prints an error and exits with a non-zero status without calling Shodan

#### Scenario: Dry-run skips writes

- **WHEN** `main()` is invoked with `--dry-run`
- **THEN** it prints the credit/target summary and returns without creating a scan record or calling `bulk_save`

#### Scenario: Limit caps the number of fetched nodes

- **WHEN** `main()` is invoked with `--limit 50` and Shodan reports 10,000 available nodes
- **THEN** the target is `min(50, available, credits*100)` and no more than 50 nodes are saved

#### Scenario: Target is capped by available credits

- **WHEN** `credits_available * 100` is smaller than the Shodan result total
- **THEN** the target is clamped to `credits_available * 100`

### Requirement: Pagination, retry, and termination loop

The test suite SHALL verify the main scan loop handles Shodan rate-limit retries, "no more pages" termination, and empty-matches termination.

#### Scenario: Rate-limit error triggers retry without advancing the page

- **WHEN** `api.search` raises `shodan.APIError("Rate limit reached")` on page N once, then succeeds
- **THEN** the loop sleeps, retries page N, and eventually persists the matches from that page

#### Scenario: "No information available" stops the loop cleanly

- **WHEN** `api.search` raises `shodan.APIError("No information available for that page")`
- **THEN** the loop exits without raising and the scan is marked complete

#### Scenario: Empty matches list stops the loop

- **WHEN** `api.search` returns a result with `matches: []`
- **THEN** the loop exits and the scan is marked complete with the nodes seen so far

#### Scenario: Unknown Shodan error propagates to finalization

- **WHEN** `api.search` raises a non-rate-limit, non-pagination `shodan.APIError`
- **THEN** the error is caught by the outer handler and the scan is still completed in the `finally` block

### Requirement: Scan lifecycle persistence

The test suite SHALL verify the scan record is created in the `running` state at the start and transitioned to completed with the final node count and duration.

#### Scenario: Scan record is created before fetching

- **WHEN** `main()` proceeds past the dry-run check
- **THEN** a `Scan` row is created with `status="running"` and `queries_executed=["product:Satoshi"]`

#### Scenario: Scan is completed in the finally block

- **WHEN** the main loop exits (normally or via a handled error)
- **THEN** `ScanRepository.complete` is called with `total_nodes` equal to the number of saved nodes and a non-negative `duration_seconds`

### Requirement: Coverage gate

The test suite SHALL achieve at least 80% line coverage for `scripts/full_db_scan.py` when run under `pytest-cov`.

#### Scenario: Coverage threshold met

- **WHEN** `pytest tests/test_full_db_scan.py --cov=scripts.full_db_scan --cov-report=term-missing` is executed
- **THEN** reported line coverage for `scripts/full_db_scan.py` is ≥ 80%
