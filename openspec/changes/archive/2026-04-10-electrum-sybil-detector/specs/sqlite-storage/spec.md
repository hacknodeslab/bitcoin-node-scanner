## ADDED Requirements

### Requirement: SQLite schema with WAL mode
The system SHALL create a SQLite database (`electrum_monitor.db`) with WAL journal mode enabled and the following tables on first run.

Tables:
- `servers(id INTEGER PK, host TEXT, port INTEGER, ssl INTEGER, first_seen INTEGER, last_state TEXT)`
- `block_notifications(id INTEGER PK, server_id INTEGER, height INTEGER, block_hash TEXT, timestamp_ms INTEGER)`
- `server_metadata(id INTEGER PK, server_id INTEGER, timestamp INTEGER, protocol_version TEXT, server_software TEXT, banner TEXT, donation_address TEXT, features_json TEXT)`
- `fee_estimates(id INTEGER PK, server_id INTEGER, timestamp INTEGER, block_target INTEGER, fee_rate REAL)`
- `relay_fees(id INTEGER PK, server_id INTEGER, timestamp INTEGER, relay_fee REAL)`
- `fee_histograms(id INTEGER PK, server_id INTEGER, timestamp INTEGER, histogram_json TEXT)`
- `availability(id INTEGER PK, server_id INTEGER, timestamp INTEGER, event_type TEXT, latency_ms REAL, error TEXT)`

#### Scenario: Tables created on first run
- **WHEN** the daemon starts with no existing database file
- **THEN** all tables are created with the correct schema and WAL mode is enabled

#### Scenario: Existing database reused
- **WHEN** the daemon starts and `electrum_monitor.db` already exists
- **THEN** existing data is preserved and new records are appended

### Requirement: Non-blocking DB writes
All database writes SHALL be executed in a thread pool executor to avoid blocking the asyncio event loop.

#### Scenario: DB write does not block event loop
- **WHEN** a block notification is received and written to SQLite
- **THEN** the asyncio event loop continues processing other server messages without waiting for the write to complete
