## ADDED Requirements

### Requirement: Dashboard served at root URL
The system SHALL serve a single-page HTML dashboard at `GET /` that loads without a build step.

#### Scenario: Dashboard loads in browser
- **WHEN** a browser navigates to `http://<host>:<port>/`
- **THEN** the server SHALL return a valid HTML page with status 200

### Requirement: Dashboard displays scan statistics
The dashboard SHALL fetch and display aggregate statistics from `GET /api/v1/stats` on page load and refresh every 30 seconds.

#### Scenario: Stats displayed on load
- **WHEN** the dashboard page is loaded
- **THEN** it SHALL show total node count, breakdown by risk level (CRITICAL/HIGH/MEDIUM/LOW), and timestamp of last scan

#### Scenario: Stats auto-refresh
- **WHEN** 30 seconds have elapsed since the last stats fetch
- **THEN** the dashboard SHALL automatically re-fetch `/api/v1/stats` and update the display without a full page reload

### Requirement: Dashboard displays node table
The dashboard SHALL fetch and display a paginated table of nodes from `GET /api/v1/nodes`.

#### Scenario: Node table renders on load
- **WHEN** the dashboard page is loaded
- **THEN** it SHALL display a table with columns: IP, Port, Version, Risk Level, Country, Last Seen

#### Scenario: Risk level filter applied
- **WHEN** the user selects a risk level from a filter dropdown
- **THEN** the dashboard SHALL re-fetch `/api/v1/nodes?risk_level=<selected>` and update the table

### Requirement: Trigger scan from dashboard
The dashboard SHALL provide a button to trigger a new scan via `POST /api/v1/scans`.

#### Scenario: Scan triggered from UI
- **WHEN** user clicks "Start Scan" and no scan is running
- **THEN** the dashboard SHALL POST to `/api/v1/scans`, show a "Scan running..." status indicator, and poll the job status every 10 seconds

#### Scenario: Scan button disabled while scan is running
- **WHEN** a scan job is in `pending` or `running` state
- **THEN** the "Start Scan" button SHALL be disabled and show current scan status

### Requirement: Sortable table headers
Each column header in the node table SHALL be clickable. Clicking a header sorts by that column ascending; clicking again toggles to descending. The active sort column SHALL display ▲ (asc) or ▼ (desc). Inactive columns SHALL display a dim ⇅ hint.

#### Scenario: Click header sorts by that column
- **WHEN** user clicks the "Last Seen" column header
- **THEN** the table reloads sorted by `last_seen` and the header shows ▼

#### Scenario: Second click on same header reverses order
- **WHEN** user clicks an already-active sort header
- **THEN** sort direction toggles and the table reloads

### Requirement: Country filter dropdown
A dropdown filter for "Server Location" (country) SHALL be present in the toolbar. It SHALL be populated from `GET /api/v1/nodes/countries`. Selecting a country filters the table; selecting the blank option clears the filter.

#### Scenario: Dropdown shows available countries
- **WHEN** the page loads
- **THEN** the country dropdown contains all distinct countries from the database

#### Scenario: Selecting a country filters the table
- **WHEN** user selects "Germany" from the country dropdown
- **THEN** the table reloads showing only nodes with Server Location = Germany

#### Scenario: Country filter combines with risk level filter
- **WHEN** both a risk level and a country are selected
- **THEN** the table shows only nodes matching both filters
