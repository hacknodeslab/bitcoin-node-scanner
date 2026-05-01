## ADDED Requirements

### Requirement: Canonical example IP list
The system SHALL maintain a single canonical list of example/demo IP addresses in `src/example_ips.py`. The list SHALL contain at minimum: `1.2.3.4`, `5.6.7.8`, `9.10.11.12`, `1.3.3.7`. The module SHALL expose a function `is_example_ip(ip: str) -> bool` that returns `True` if and only if the input is in the canonical list.

#### Scenario: Recognized example IPs return True
- **WHEN** `is_example_ip("1.2.3.4")`, `is_example_ip("5.6.7.8")`, `is_example_ip("9.10.11.12")`, or `is_example_ip("1.3.3.7")` is called
- **THEN** the function SHALL return `True`

#### Scenario: Unknown IPs return False
- **WHEN** `is_example_ip("8.8.8.8")` or `is_example_ip("203.0.113.5")` is called
- **THEN** the function SHALL return `False`

#### Scenario: Invalid input is rejected safely
- **WHEN** `is_example_ip("")`, `is_example_ip("not-an-ip")`, or `is_example_ip(None)` is called
- **THEN** the function SHALL return `False` without raising

### Requirement: Example flag is set on every node write
The system SHALL set `Node.is_example = True` when persisting or upserting a node whose IP is in the canonical example list, and `False` otherwise. This SHALL apply uniformly to every code path that writes `Node` rows from the scanner, including `BitcoinNodeScanner` and `OptimizedBitcoinScanner` paths.

#### Scenario: New example node is flagged
- **WHEN** the scanner integration persists a node with IP `1.2.3.4` for the first time
- **THEN** the resulting `Node` row SHALL have `is_example = True`

#### Scenario: New non-example node is not flagged
- **WHEN** the scanner integration persists a node with IP `198.51.100.7`
- **THEN** the resulting `Node` row SHALL have `is_example = False`

#### Scenario: Existing node is corrected on update
- **WHEN** an existing node with IP `1.2.3.4` and `is_example = False` is upserted by the scanner integration
- **THEN** the resulting row SHALL have `is_example = True` after the upsert

### Requirement: Backfill helper for existing rows
The system SHALL provide a repository method `backfill_example_flag()` and a CLI subcommand `python -m src.db.cli db-mark-examples` that idempotently set `is_example = True` for every persisted node whose IP is in the canonical list and `is_example = False` for any node previously flagged whose IP is no longer in the list.

#### Scenario: CLI backfills existing rows
- **WHEN** the database contains a node `5.6.7.8` with `is_example = False` and `db-mark-examples` is invoked
- **THEN** that node SHALL have `is_example = True` after the command completes

#### Scenario: CLI is idempotent
- **WHEN** `db-mark-examples` is invoked twice in a row
- **THEN** the second invocation SHALL not raise and SHALL leave the same set of nodes flagged

#### Scenario: Stale flag is cleared
- **WHEN** a node with IP `192.0.2.1` has `is_example = True` (set in error) and `192.0.2.1` is not in the canonical list, and `db-mark-examples` is invoked
- **THEN** that node SHALL have `is_example = False` after the command completes

### Requirement: Seed canonical example nodes
The system SHALL maintain a registry `EXAMPLE_NODES` in `src/example_ips.py` containing one synthetic node record per IP in the canonical list, where each record covers a different operator-relevant state (one normal LOW, one CRITICAL with `has_exposed_rpc=True`, one TOR with `.onion` hostname and `tor` tag, one HIGH with `is_vulnerable=True`). The system SHALL provide a CLI subcommand `python -m src.db.cli db-seed-examples` that upserts every record from `EXAMPLE_NODES` with `is_example = True`. The command SHALL be idempotent.

#### Scenario: Seeding empty database creates four flagged nodes
- **WHEN** the database has no example nodes and `db-seed-examples` is invoked
- **THEN** four `Node` rows SHALL exist after the command, one per canonical IP, all with `is_example = True`

#### Scenario: Each seeded node carries its declared state
- **WHEN** `db-seed-examples` is invoked against an empty database
- **THEN** the row for `5.6.7.8` SHALL have `port = 8332` and `has_exposed_rpc = True`; the row for `9.10.11.12` SHALL have an `.onion` hostname and `tags_json` containing `"tor"`; the row for `1.3.3.7` SHALL have `is_vulnerable = True`; and the row for `1.2.3.4` SHALL have `risk_level = "LOW"` and `has_exposed_rpc = False`

#### Scenario: Seeding is idempotent
- **WHEN** `db-seed-examples` is invoked twice in a row
- **THEN** the database SHALL still contain exactly four example node rows after the second invocation

#### Scenario: --purge-extras drops legacy example-flagged rows
- **WHEN** the database contains rows flagged `is_example=True` whose `(ip, port)` is NOT one of the canonical seed pairs (e.g., a legacy `5.6.7.8:8333` row), and `db-seed-examples --purge-extras` is invoked
- **THEN** those non-canonical example-flagged rows SHALL be deleted, the four canonical seed rows SHALL exist with `is_example=True`, and rows whose `is_example=False` SHALL be untouched

#### Scenario: --purge-extras is opt-in
- **WHEN** `db-seed-examples` is invoked without `--purge-extras` and the database contains a legacy example-flagged row at a non-canonical port
- **THEN** that legacy row SHALL remain in the database
