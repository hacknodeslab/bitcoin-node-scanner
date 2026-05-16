## ADDED Requirements

### Requirement: Vulnerabilities catalog exposes affected node count

The `GET /api/v1/vulnerabilities` catalog response SHALL include, for each CVE entry, an `affected_node_count` field giving the number of nodes currently linked to that CVE (active links in `node_vulnerabilities`). The count SHALL be computed without issuing one query per CVE.

#### Scenario: Catalog item includes affected node count

- **WHEN** `GET /api/v1/vulnerabilities` is called and CVE-2018-17144 has 7 active node links
- **THEN** that CVE's catalog item SHALL include `affected_node_count: 7`

#### Scenario: CVE with no affected nodes

- **WHEN** a CVE in the catalog has no active node links
- **THEN** its catalog item SHALL include `affected_node_count: 0`
