## ADDED Requirements

### Requirement: Canonical example IP list
The system SHALL maintain a single canonical list of example/demo IP addresses in `src/example_ips.py`. Every IP in the list MUST belong to one of the IANA documentation ranges reserved by RFC 5737 — `192.0.2.0/24` (TEST-NET-1), `198.51.100.0/24` (TEST-NET-2), or `203.0.113.0/24` (TEST-NET-3) — so the flag cannot collide with any publicly routable host. The list SHALL contain at minimum: `192.0.2.7`, `198.51.100.13`, `203.0.113.42`, `203.0.113.99`. The module SHALL expose a function `is_example_ip(ip: str) -> bool` that returns `True` if and only if the input is in the canonical list.

#### Scenario: Recognized example IPs return True
- **WHEN** `is_example_ip("192.0.2.7")`, `is_example_ip("198.51.100.13")`, `is_example_ip("203.0.113.42")`, or `is_example_ip("203.0.113.99")` is called
- **THEN** the function SHALL return `True`

#### Scenario: Publicly routable IPs return False
- **WHEN** `is_example_ip("1.2.3.4")`, `is_example_ip("5.6.7.8")`, `is_example_ip("8.8.8.8")`, or `is_example_ip("9.10.11.12")` is called
- **THEN** the function SHALL return `False` (these addresses are routable and MUST NOT be canonical)

#### Scenario: Invalid input is rejected safely
- **WHEN** `is_example_ip("")`, `is_example_ip("not-an-ip")`, or `is_example_ip(None)` is called
- **THEN** the function SHALL return `False` without raising

#### Scenario: Canonical list contains only RFC 5737 addresses
- **WHEN** the test suite iterates `EXAMPLE_IPS`
- **THEN** every entry SHALL parse as an IPv4 address that falls inside `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`

### Requirement: Example flag is set on every node write
The system SHALL set `Node.is_example = True` when persisting or upserting a node whose IP is in the canonical example list, and `False` otherwise. This SHALL apply uniformly to every code path that writes `Node` rows from the scanner, including `BitcoinNodeScanner` and `OptimizedBitcoinScanner` paths.

#### Scenario: New example node is flagged
- **WHEN** the scanner integration persists a node with IP `192.0.2.7` for the first time
- **THEN** the resulting `Node` row SHALL have `is_example = True`

#### Scenario: New non-example node is not flagged
- **WHEN** the scanner integration persists a node with IP `8.8.8.8`
- **THEN** the resulting `Node` row SHALL have `is_example = False`

#### Scenario: Existing node is corrected on update
- **WHEN** an existing node with IP `192.0.2.7` and `is_example = False` is upserted by the scanner integration
- **THEN** the resulting row SHALL have `is_example = True` after the upsert

### Requirement: Backfill helper for existing rows
The system SHALL provide a repository method `backfill_example_flag()` and a CLI subcommand `python -m src.db.cli db-mark-examples` that idempotently set `is_example = True` for every persisted node whose IP is in the canonical list and `is_example = False` for any node previously flagged whose IP is no longer in the list.

#### Scenario: CLI backfills existing rows
- **WHEN** the database contains a node `198.51.100.13` with `is_example = False` and `db-mark-examples` is invoked
- **THEN** that node SHALL have `is_example = True` after the command completes

#### Scenario: CLI is idempotent
- **WHEN** `db-mark-examples` is invoked twice in a row
- **THEN** the second invocation SHALL not raise and SHALL leave the same set of nodes flagged

#### Scenario: Stale flag is cleared
- **WHEN** a node with IP `172.16.0.1` has `is_example = True` (set in error) and `172.16.0.1` is not in the canonical list, and `db-mark-examples` is invoked
- **THEN** that node SHALL have `is_example = False` after the command completes

### Requirement: Seed canonical example nodes
The system SHALL maintain a registry `EXAMPLE_NODES` in `src/example_ips.py` containing one synthetic node record per IP in the canonical list, where each record covers a different operator-relevant state (one normal LOW, one CRITICAL with `has_exposed_rpc=True`, one TOR with `.onion` hostname and `tor` tag, one HIGH with `is_vulnerable=True`). The system SHALL provide a CLI subcommand `python -m src.db.cli db-seed-examples` that upserts every record from `EXAMPLE_NODES` with `is_example = True`. The command SHALL be idempotent.

#### Scenario: Seeding empty database creates four flagged nodes
- **WHEN** the database has no example nodes and `db-seed-examples` is invoked
- **THEN** four `Node` rows SHALL exist after the command, one per canonical IP, all with `is_example = True`

#### Scenario: Each seeded node carries its declared state
- **WHEN** `db-seed-examples` is invoked against an empty database
- **THEN** the row for `198.51.100.13` SHALL have `port = 8332` and `has_exposed_rpc = True`; the row for `203.0.113.42` SHALL have an `.onion` hostname and `tags_json` containing `"tor"`; the row for `203.0.113.99` SHALL have `is_vulnerable = True`; and the row for `192.0.2.7` SHALL have `risk_level = "LOW"` and `has_exposed_rpc = False`

#### Scenario: Seeding is idempotent
- **WHEN** `db-seed-examples` is invoked twice in a row
- **THEN** the database SHALL still contain exactly four example node rows after the second invocation

#### Scenario: --purge-extras drops legacy example-flagged rows
- **WHEN** the database contains rows flagged `is_example=True` whose `(ip, port)` is NOT one of the canonical seed pairs (e.g., a legacy `198.51.100.13:8333` row), and `db-seed-examples --purge-extras` is invoked
- **THEN** those non-canonical example-flagged rows SHALL be deleted, the four canonical seed rows SHALL exist with `is_example=True`, and rows whose `is_example=False` SHALL be untouched

#### Scenario: --purge-extras is opt-in
- **WHEN** `db-seed-examples` is invoked without `--purge-extras` and the database contains a legacy example-flagged row at a non-canonical port
- **THEN** that legacy row SHALL remain in the database
