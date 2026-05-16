## ADDED Requirements

### Requirement: Vulnerabilities page lists the CVE catalog

The dashboard SHALL expose a `/vulnerabilities` route rendering the CVE catalog from `GET /api/v1/vulnerabilities` as a table. Each row SHALL show: severity, CVE id, CVSS score, published date, affected versions, and affected node count. The CVE id SHALL link to the corresponding NVD page. The page SHALL use the existing design-system tokens, the dark/light theme, and the `Pill` `kind="CVE"` component for severity.

#### Scenario: Catalog renders as a table

- **WHEN** a user navigates to `/vulnerabilities` and the catalog has CVE entries
- **THEN** each entry SHALL render as a row showing severity, CVE id (linked to NVD), CVSS score, published date, affected versions, and affected node count

#### Scenario: Empty catalog

- **WHEN** the catalog has no CVE entries
- **THEN** the page SHALL render an empty state rather than an empty or broken table

### Requirement: Catalog table is sortable and paginated

The vulnerabilities table SHALL be sortable by severity, CVSS score, published date, and affected node count, and SHALL be paginated using the same pagination pattern as the explorer's node table.

#### Scenario: Sort by affected node count

- **WHEN** the user sorts by affected node count descending
- **THEN** the CVE affecting the most nodes SHALL appear first

#### Scenario: Pagination advances pages

- **WHEN** the catalog has more entries than one page and the user advances to the next page
- **THEN** the table SHALL show the next set of entries without a full reload of unrelated dashboard state

### Requirement: Pivot from a CVE to its affected nodes

Selecting a CVE row SHALL reveal the nodes affected by that CVE, sourced from `GET /api/v1/vulnerabilities/{cve_id}/nodes`. Each affected node SHALL be selectable to deep-link into the explorer / node detail view for that node.

#### Scenario: Reveal affected nodes

- **WHEN** the user selects a CVE row
- **THEN** the nodes linked to that CVE SHALL be shown with their ip, port, version, risk level, country, and last-seen

#### Scenario: Navigate to an affected node

- **WHEN** the user selects an affected node from the revealed list
- **THEN** the dashboard SHALL navigate to that node's detail view in the explorer

### Requirement: Vulnerabilities page is reachable from the dashboard

The `/vulnerabilities` page SHALL be reachable from the command palette and from a persistent dashboard navigation affordance. The `vuln.list` palette command SHALL navigate to `/vulnerabilities` (rather than only refreshing cached data) while keeping its `GET /api/v1/vulnerabilities` REST mapping so the palette-REST parity check still passes.

#### Scenario: Open the page from the palette

- **WHEN** the user runs the `vuln: list` command from the command palette
- **THEN** the dashboard SHALL navigate to `/vulnerabilities`

#### Scenario: Palette-REST parity holds

- **WHEN** the palette-REST parity test runs over the command set
- **THEN** the `vuln.list` command SHALL still resolve to the registered `GET /api/v1/vulnerabilities` endpoint and the test SHALL pass
