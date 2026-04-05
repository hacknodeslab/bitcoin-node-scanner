## ADDED Requirements

### Requirement: Dashboard displays vulnerabilities table
The dashboard SHALL include a "Vulnerabilities" tab or section that fetches CVE data from `GET /api/v1/vulnerabilities` and renders it as a sortable table.

#### Scenario: Vulnerabilities table renders on tab activation
- **WHEN** the user clicks the "Vulnerabilities" tab
- **THEN** the dashboard SHALL fetch `/api/v1/vulnerabilities` and display a table with columns: CVE ID, Severity, CVSS Score, Published Date, Description (truncated to 120 chars)

#### Scenario: Severity color coding
- **WHEN** the vulnerabilities table is rendered
- **THEN** the Severity column SHALL use color badges: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=green, UNKNOWN=gray

#### Scenario: Loading state shown during fetch
- **WHEN** the vulnerabilities tab is activated and the fetch is in progress
- **THEN** the table area SHALL display a loading indicator until the response is received

#### Scenario: Error state shown on NVD unavailability
- **WHEN** the fetch to `/api/v1/vulnerabilities` returns a non-200 response
- **THEN** the dashboard SHALL display an error message: "Could not load vulnerability data. Try again later."

#### Scenario: Cache age indicator
- **WHEN** the vulnerabilities table is rendered and `fetched_at` is available
- **THEN** the dashboard SHALL display a subtitle showing "Last updated: <relative time>" (e.g., "Last updated: 3 hours ago")
