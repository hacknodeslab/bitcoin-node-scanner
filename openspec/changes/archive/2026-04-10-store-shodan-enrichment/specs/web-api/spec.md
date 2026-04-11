## MODIFIED Requirements

### Requirement: Read endpoints are publicly accessible
`GET /api/v1/nodes` SHALL include the following additional fields in each node object: `hostname`, `os_info`, `isp`, `org`, `open_ports` (parsed list of port objects), `vulns` (parsed list of CVE IDs), `tags` (parsed list), `cpe` (parsed list). Fields SHALL be `null` when not available.

#### Scenario: Nodes endpoint returns enrichment fields
- **WHEN** `GET /api/v1/nodes` is called
- **THEN** each node object includes `hostname`, `os_info`, `isp`, `org`, `open_ports`, `vulns`, `tags`, `cpe` (null if not yet collected)
