## ADDED Requirements

### Requirement: Node detail endpoint exposes active CVEs

The system SHALL expose `GET /api/v1/nodes/{id}` returning the full node record plus the list of active CVEs linked to that node. Each CVE entry in the response SHALL include `cve_id`, `severity`, `cvss_score`, `detected_at`, and `detected_version`. By default only active links (`resolved_at IS NULL`) are returned; passing `?include_resolved=true` SHALL include resolved links with their `resolved_at` timestamp.

#### Scenario: Node detail returns linked CVEs
- **WHEN** `GET /api/v1/nodes/42` is called for a node that has 3 active CVE links
- **THEN** the response SHALL include a `cves` array of length 3 sorted by `cvss_score DESC` (NULLs last), each with `cve_id`, `severity`, `cvss_score`, `detected_at`, `detected_version`

#### Scenario: Node detail with no CVEs
- **WHEN** `GET /api/v1/nodes/{id}` is called for a node with no linked CVEs
- **THEN** the response SHALL include `cves: []`

#### Scenario: Include resolved CVEs on demand
- **WHEN** `GET /api/v1/nodes/{id}?include_resolved=true` is called for a node with 1 active and 2 resolved links
- **THEN** the response SHALL include all 3 entries, with `resolved_at` populated for the resolved ones and `null` for the active one

### Requirement: Node list includes CVE summary

`GET /api/v1/nodes` SHALL include `cve_count` (integer count of active CVE links) and `top_cve` (the active CVE with the highest `cvss_score`, or `null` if none) for each node in the paginated response. The full per-node CVE list is NOT returned by the list endpoint to keep responses bounded.

#### Scenario: List response includes CVE summary fields
- **WHEN** `GET /api/v1/nodes` returns a node with 2 active CVE links
- **THEN** that node entry SHALL include `cve_count: 2` and `top_cve: {cve_id, severity, cvss_score}` for the highest-scored active link

#### Scenario: List response for clean node
- **WHEN** `GET /api/v1/nodes` returns a node with no active CVE links
- **THEN** that node entry SHALL include `cve_count: 0` and `top_cve: null`

### Requirement: Vulnerabilities endpoint exposes affected nodes

The system SHALL expose `GET /api/v1/vulnerabilities/{cve_id}/nodes` returning the list of nodes currently linked to that CVE (i.e., active links in `node_vulnerabilities`). Response items SHALL include `ip`, `port`, `version`, `risk_level`, `country_name`, `last_seen`.

#### Scenario: List nodes affected by a CVE
- **WHEN** `GET /api/v1/vulnerabilities/CVE-2018-17144/nodes` is called and 7 nodes have an active link to that CVE
- **THEN** the response SHALL return those 7 nodes with the listed fields

#### Scenario: CVE not in catalog
- **WHEN** `GET /api/v1/vulnerabilities/CVE-9999-99999/nodes` is called for a CVE not present in `cve_entries`
- **THEN** the server SHALL return HTTP 404 Not Found
