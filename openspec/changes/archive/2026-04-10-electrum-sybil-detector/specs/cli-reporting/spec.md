## ADDED Requirements

### Requirement: Default run mode
The system SHALL start the collection daemon when invoked with no flags and run indefinitely until interrupted.

#### Scenario: Daemon starts with no flags
- **WHEN** `python electrum_monitor.py` is executed
- **THEN** the daemon connects to all seed servers and begins collecting data

### Requirement: Summary report flag
The system SHALL support a `--report` flag that prints a human-readable summary of collected data to stdout without starting the daemon.

The report SHALL include:
- Total servers tracked, connected vs. disconnected
- Total block notifications per server with first/last timestamp
- Average ping RTT per server
- Latest fee estimates per server

#### Scenario: Report printed and process exits
- **WHEN** `python electrum_monitor.py --report` is executed
- **THEN** the summary is printed to stdout and the process exits with code 0

### Requirement: Block data CSV export flag
The system SHALL support a `--dump-blocks` flag that writes all block notification records to stdout as CSV (columns: server_id, host, port, height, block_hash, timestamp_ms).

#### Scenario: CSV written to stdout
- **WHEN** `python electrum_monitor.py --dump-blocks` is executed
- **THEN** all rows from `block_notifications` joined with `servers` are written as CSV to stdout and the process exits

#### Scenario: Empty database handled
- **WHEN** `--dump-blocks` is run against a database with no block notifications
- **THEN** only the CSV header row is printed and the process exits with code 0
