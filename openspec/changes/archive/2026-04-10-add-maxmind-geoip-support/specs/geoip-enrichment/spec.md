## ADDED Requirements

### Requirement: CLI command retroactively enriches all nodes
The system SHALL provide a `bitcoin-scanner db enrich-geo` CLI subcommand that reads all nodes from the database and fills missing geo fields using `GeoIPService`.

#### Scenario: Command enriches nodes with missing coordinates
- **WHEN** `bitcoin-scanner db enrich-geo` is run and the database contains nodes with null `latitude`/`longitude`
- **THEN** the command SHALL call `GeoIPService.lookup(ip)` for each such node and write coordinates when the lookup returns a valid `GeoRecord`

#### Scenario: Command skips nodes with complete geo data
- **WHEN** a node already has non-null values for all geo fields (`country_code`, `country_name`, `city`, `latitude`, `longitude`, `asn`, `asn_name`, `subdivision`)
- **THEN** the command SHALL skip that node (no unnecessary DB write)

#### Scenario: Command reports enrichment summary on completion
- **WHEN** `bitcoin-scanner db enrich-geo` finishes
- **THEN** it SHALL print a summary including: total nodes processed, nodes updated, nodes skipped (already complete), nodes with no MaxMind match

#### Scenario: Command processes nodes in batches of 500
- **WHEN** the database contains more than 500 nodes
- **THEN** the command SHALL commit in batches of 500 to avoid holding a long-running transaction

#### Scenario: Command fails gracefully when .mmdb files are absent
- **WHEN** `bitcoin-scanner db enrich-geo` is run but `GEOIP_DB_DIR` contains no `.mmdb` files
- **THEN** the command SHALL print an actionable error message (including the path it looked in and a pointer to the download script) and exit with non-zero status

### Requirement: Web API exposes full geo detail per node
The system SHALL expose `GET /api/v1/nodes/{id}/geo` returning the full geo record for a single node.

#### Scenario: Endpoint returns geo fields for known node
- **WHEN** `GET /api/v1/nodes/{id}/geo` is called with a valid node ID and valid API key
- **THEN** the response SHALL return JSON with: `ip`, `country_code`, `country_name`, `city`, `subdivision`, `latitude`, `longitude`, `asn`, `asn_name`

#### Scenario: Endpoint returns 404 for unknown node
- **WHEN** `GET /api/v1/nodes/{id}/geo` is called with an ID that does not exist
- **THEN** the server SHALL return HTTP 404 Not Found

#### Scenario: Endpoint requires API key
- **WHEN** `GET /api/v1/nodes/{id}/geo` is called without `X-API-Key`
- **THEN** the server SHALL return HTTP 401 Unauthorized

### Requirement: subdivision column added to nodes table
The system SHALL add a nullable `subdivision` column (String 100) to the `nodes` table via an Alembic migration.

#### Scenario: Migration applies cleanly to existing database
- **WHEN** `alembic upgrade head` is run against a database with existing node rows
- **THEN** the migration SHALL succeed and all existing rows SHALL have `subdivision = NULL`

#### Scenario: Migration is reversible
- **WHEN** `alembic downgrade -1` is run after applying migration `003`
- **THEN** the `subdivision` column SHALL be removed with no data loss to other columns
