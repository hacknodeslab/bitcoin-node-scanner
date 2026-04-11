## ADDED Requirements

### Requirement: Persist Shodan base fields on every scan
The system SHALL store `os`, `hostname` (first entry), `hostnames_json`, `isp`, `org`, `vulns_json`, `cpe_json` from every Shodan search result record — no extra API calls required.

#### Scenario: Base fields saved with node
- **WHEN** a node is saved or updated from a Shodan search result
- **THEN** `os`, `hostname`, `isp`, `org`, `vulns_json`, `cpe_json` are written to the Node record

#### Scenario: Null fields tolerated
- **WHEN** Shodan does not provide a field (e.g. os is null)
- **THEN** the column is stored as NULL without error

### Requirement: Persist enrichment fields when host scan runs
The system SHALL store `open_ports_json` (list of `{port, transport, product, version}` objects) and `tags_json` from the Shodan host scan enrichment, when enrichment data is present.

#### Scenario: Enrichment fields saved after host scan
- **WHEN** enrichment runs for a node and returns `all_services` and `tags`
- **THEN** `open_ports_json` and `tags_json` are written to the Node record

#### Scenario: Enrichment absent — fields left as-is
- **WHEN** a node update does not include enrichment data
- **THEN** `open_ports_json` and `tags_json` are not modified
