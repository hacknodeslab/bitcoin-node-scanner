## ADDED Requirements

### Requirement: ProgressBar renders correctly
The test suite SHALL verify that `ProgressBar` updates and finishes without errors, correctly computing fill percentage.

#### Scenario: Normal update increments counter
- **WHEN** `ProgressBar(total=10).update()` is called once
- **THEN** `current` equals 1 and no exception is raised

#### Scenario: Explicit current value is set
- **WHEN** `ProgressBar(total=10).update(current=5)` is called
- **THEN** `current` equals 5

#### Scenario: Zero-total guard
- **WHEN** `ProgressBar(total=0).update()` is called
- **THEN** no division-by-zero error occurs and the method returns immediately

#### Scenario: Finish writes newline
- **WHEN** `ProgressBar.finish()` is called
- **THEN** a newline is printed to stdout

---

### Requirement: JSONImporter imports a valid list-format JSON file
The test suite SHALL verify that a JSON file containing a list of node dicts is imported into the database.

#### Scenario: All nodes imported on fresh DB
- **WHEN** `import_file` is called with a JSON file containing 3 valid node dicts
- **THEN** `file_stats["imported"]` equals 3 and `file_stats["errors"]` equals 0

#### Scenario: Node with existing IP is updated not re-inserted
- **WHEN** the same file is imported a second time
- **THEN** `file_stats["updated"]` equals 3 and `file_stats["imported"]` equals 0

---

### Requirement: JSONImporter handles dict-format JSON
The test suite SHALL verify all three dict-envelope variants.

#### Scenario: Dict with "nodes" key
- **WHEN** the JSON root is `{"nodes": [...]}` with 2 nodes
- **THEN** both nodes are imported successfully

#### Scenario: Dict representing a single node (has "ip" key)
- **WHEN** the JSON root is a single node dict containing `"ip"`
- **THEN** one node is imported

#### Scenario: Dict of arbitrary keys mapping to node dicts
- **WHEN** the JSON root is `{"a": {node1}, "b": {node2}}`
- **THEN** both nodes are imported

---

### Requirement: JSONImporter handles file errors gracefully
The test suite SHALL verify error-path behaviour without crashing.

#### Scenario: Missing file returns empty stats
- **WHEN** `import_file` is called with a non-existent path
- **THEN** all stat counts are 0 and no exception propagates

#### Scenario: Malformed JSON returns error count 1
- **WHEN** `import_file` is called with a file containing invalid JSON
- **THEN** `file_stats["errors"]` equals 1

#### Scenario: Empty node list returns without error
- **WHEN** the JSON file contains an empty list `[]`
- **THEN** all stat counts are 0

#### Scenario: Session None path is handled
- **WHEN** `get_db_session` yields `None`
- **THEN** `import_file` returns with all stats at 0 and logs "Database not configured"

---

### Requirement: _import_node skips nodes without IP
The test suite SHALL verify deduplication and skip logic.

#### Scenario: Node dict missing "ip" key is skipped
- **WHEN** `_import_node` is called with a dict that has no `"ip"` key
- **THEN** the return value is `"skipped"`

#### Scenario: RPC port triggers CRITICAL risk level
- **WHEN** a node dict has `"port": 8332`
- **THEN** `_analyze_risk_level` returns `"CRITICAL"` and `has_exposed_rpc` is `True`

---

### Requirement: _analyze_risk_level maps factors correctly
The test suite SHALL verify risk classification logic.

#### Scenario: Vulnerable version alone yields MEDIUM
- **WHEN** node has a known-vulnerable version and no other risk factors
- **THEN** `_analyze_risk_level` returns `"MEDIUM"`

#### Scenario: Vulnerable version plus dev flag yields HIGH
- **WHEN** node has a known-vulnerable version and `.99.` in version string
- **THEN** `_analyze_risk_level` returns `"HIGH"`

#### Scenario: No risk factors yields LOW
- **WHEN** node has a clean version string and port 8333
- **THEN** `_analyze_risk_level` returns `"LOW"`

---

### Requirement: _is_vulnerable_version detects old Satoshi versions
The test suite SHALL verify version string parsing.

#### Scenario: Old version below 0.21 is vulnerable
- **WHEN** version is `/Satoshi:0.18.1/`
- **THEN** `_is_vulnerable_version` returns `True`

#### Scenario: Modern version is not vulnerable
- **WHEN** version is `/Satoshi:25.0.0/`
- **THEN** `_is_vulnerable_version` returns `False`

#### Scenario: Malformed version string is not vulnerable
- **WHEN** version is `garbage`
- **THEN** `_is_vulnerable_version` returns `False` without raising

---

### Requirement: _extract_timestamp parses filename dates
The test suite SHALL verify timestamp extraction from filenames.

#### Scenario: Filename with YYYYMMDD_HHMMSS returns correct datetime
- **WHEN** filename is `nodes_20240115_120000.json`
- **THEN** returned datetime equals `2024-01-15 12:00:00`

#### Scenario: Filename with YYYYMMDD only returns correct date
- **WHEN** filename is `nodes_20240115.json`
- **THEN** returned datetime has year=2024, month=1, day=15

#### Scenario: Filename with no date returns current time (approx)
- **WHEN** filename is `nodes.json`
- **THEN** returned datetime is close to `datetime.utcnow()`

---

### Requirement: import_directory processes all JSON files in a folder
The test suite SHALL verify batch import.

#### Scenario: Directory with 2 JSON files imports all nodes
- **WHEN** `import_directory` is called on a temp dir with 2 valid JSON files (3 nodes each)
- **THEN** `stats["files_processed"]` equals 2 and `stats["nodes_imported"]` equals 6

#### Scenario: Non-existent directory returns empty stats
- **WHEN** `import_directory` is called with a path that does not exist
- **THEN** `stats["files_processed"]` equals 0

---

### Requirement: main() CLI entry point works correctly
The test suite SHALL verify argument parsing and exit codes.

#### Scenario: No arguments prints help and exits 1
- **WHEN** `main()` is called with empty argv
- **THEN** `SystemExit` with code 1 is raised

#### Scenario: DATABASE_URL not set exits 1
- **WHEN** `DATABASE_URL` env var is absent and `main()` is called with a file argument
- **THEN** `SystemExit` with code 1 is raised

#### Scenario: init_db failure exits 1
- **WHEN** `is_database_configured` returns True but `init_db` returns False
- **THEN** `SystemExit` with code 1 is raised

#### Scenario: --all flag calls import_directory on raw_data path
- **WHEN** `main()` is called with `--all`
- **THEN** `JSONImporter.import_directory` is called with `"output/raw_data"`

#### Scenario: --dir flag calls import_directory with given path
- **WHEN** `main()` is called with `--dir /some/path`
- **THEN** `JSONImporter.import_directory` is called with `"/some/path"`

#### Scenario: file positional argument calls import_file
- **WHEN** `main()` is called with a file path
- **THEN** `JSONImporter.import_file` is called with that path
