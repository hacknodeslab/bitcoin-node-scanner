## MODIFIED Requirements

### Requirement: Dashboard loads without authentication
The Shodan section of the node detail modal SHALL display the following additional fields when available: Hostname, OS, ISP, Org, CVEs (as a list of badge-style tags), Shodan Tags, CPE, and an Open Ports table (columns: Port, Transport, Service/Product, Version).

#### Scenario: Modal shows enrichment fields
- **WHEN** the node detail modal opens for a node with enrichment data
- **THEN** the Shodan section shows Hostname, OS, ISP, Org, CVEs, Tags, CPE, and a ports table

#### Scenario: Modal shows dashes for missing enrichment
- **WHEN** the node detail modal opens for a node without enrichment data
- **THEN** enrichment fields show "—" and the ports table is absent or shows "No data"
